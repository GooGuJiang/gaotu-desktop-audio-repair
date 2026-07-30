from __future__ import annotations

import ctypes
import datetime as dt
import hashlib
import json
import os
import queue
import sys
import threading
import time
import traceback
from pathlib import Path
from tkinter import BooleanVar, StringVar, Tk, messagebox
from tkinter import ttk

import frida


APP_NAME = "高途课堂兼容修复"
APP_VERSION = "1.0.0"
MUTEX_NAME = r"Local\Gaotu384kCompatGUI"
EXPECTED_ROOM_DLL_SHA256 = (
    "7A61D786F17E0E893E0045B6F88D80287EE0D34BA9A2A64A911521ABA5FC3934"
)

LOCAL_APPDATA = Path(os.environ.get("LOCALAPPDATA", Path.home()))
DATA_DIR = LOCAL_APPDATA / "GaotuCompat"
SETTINGS_FILE = DATA_DIR / "settings.json"
LOG_FILE = DATA_DIR / "gaotu_compat.log"
LOG_BACKUP_FILE = DATA_DIR / "gaotu_compat.previous.log"
MAX_LOG_BYTES = 512 * 1024
LOG_LOCK = threading.Lock()


def find_gaotu_exe() -> Path:
    candidates = [
        Path(os.environ.get("APPDATA", "")) / "gaotu" / "bin" / "gaotu.exe",
        Path(__file__).resolve().parents[2] / "gaotu.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


GAOTU_EXE = find_gaotu_exe()
ROOM_DLL = GAOTU_EXE.with_name("libShijieRoom.dll")


def bundled_asset(relative_path: str) -> Path:
    bundle_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return bundle_root / relative_path


def write_log(message: str) -> None:
    with LOG_LOCK:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        try:
            if LOG_FILE.is_file() and LOG_FILE.stat().st_size >= MAX_LOG_BYTES:
                LOG_BACKUP_FILE.unlink(missing_ok=True)
                LOG_FILE.replace(LOG_BACKUP_FILE)
        except OSError:
            pass

        timestamp = dt.datetime.now().isoformat(timespec="seconds")
        with LOG_FILE.open("a", encoding="utf-8") as stream:
            stream.write(f"[{timestamp}] {message}\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest().upper()


def load_settings() -> dict[str, bool]:
    defaults = {"block_audio_ducking": True}
    try:
        loaded = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        defaults["block_audio_ducking"] = bool(
            loaded.get("block_audio_ducking", True)
        )
    except (OSError, ValueError, TypeError):
        pass
    return defaults


def save_settings(block_audio_ducking: bool) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temporary = SETTINGS_FILE.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(
            {"block_audio_ducking": block_audio_ducking},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    temporary.replace(SETTINGS_FILE)


def build_hook_script(block_audio_ducking: bool) -> str:
    block_literal = "true" if block_audio_ducking else "false"
    return rf"""
const TARGET_RATE = 384000;
const SAFE_RATE = 192000;
const AUDIO_CALLBACK_RVA = 0xCAC9C0;
const BLOCK_AUDIO_DUCKING = {block_literal};
const COMMUNICATION_AUDIO_SWITCH =
    "--enable-gaotu-audio-set-render-communication";

let installed = false;
let adaptedCallbacks = 0;
let strippedLaunches = 0;
let nativeScaler = null;
let duplicateStereoFrames = null;

try {{
    nativeScaler = new CModule(`
        typedef unsigned int uint32_t;
        void duplicate_stereo_frames(uint32_t *output, uint32_t frames) {{
            uint32_t index;
            for (index = frames; index > 0; index--) {{
                uint32_t packed = output[index - 1];
                output[(index - 1) * 2] = packed;
                output[(index - 1) * 2 + 1] = packed;
            }}
        }}
    `);
    duplicateStereoFrames = new NativeFunction(
        nativeScaler.duplicate_stereo_frames,
        "void",
        ["pointer", "uint32"]
    );
}} catch (_) {{
    duplicateStereoFrames = null;
}}

function removeCommunicationAudioSwitch(commandLinePointer) {{
    if (!BLOCK_AUDIO_DUCKING || commandLinePointer.isNull()) {{
        return;
    }}
    try {{
        const commandLine = commandLinePointer.readUtf16String();
        if (commandLine.indexOf(COMMUNICATION_AUDIO_SWITCH) === -1) {{
            return;
        }}

        const replacement = " ".repeat(COMMUNICATION_AUDIO_SWITCH.length);
        commandLinePointer.writeUtf16String(
            commandLine.split(COMMUNICATION_AUDIO_SWITCH).join(replacement)
        );
        strippedLaunches++;
        send({{
            kind: "ducking_disabled",
            pid: Process.id,
            launches: strippedLaunches
        }});
    }} catch (_) {{
    }}
}}

function hookProcessCreation(exportName, commandLineArgument) {{
    try {{
        const address = Module.getGlobalExportByName(exportName);
        Interceptor.attach(address, {{
            onEnter(args) {{
                removeCommunicationAudioSwitch(args[commandLineArgument]);
            }}
        }});
    }} catch (_) {{
    }}
}}

if (BLOCK_AUDIO_DUCKING) {{
    hookProcessCreation("CreateProcessW", 1);
    hookProcessCreation("CreateProcessAsUserW", 2);
}}

function duplicateFramesFallback(output, frames) {{
    for (let index = frames - 1; index >= 0; index--) {{
        const packedFrame = output.add(index * 4).readU32();
        output.add(index * 8).writeU32(packedFrame);
        output.add(index * 8 + 4).writeU32(packedFrame);
    }}
}}

function installAudioHook(module) {{
    if (installed) {{
        return;
    }}
    installed = true;
    const target = module.base.add(AUDIO_CALLBACK_RVA);

    Interceptor.attach(target, {{
        onEnter(args) {{
            this.adapt = false;

            const sampleRate = args[4].toUInt32();
            const channels = args[3].toUInt32() & 0xff;
            if (sampleRate !== TARGET_RATE || channels !== 2) {{
                return;
            }}

            this.adapt = true;
            this.output = args[5];
            this.sampleCount = args[6];

            // The vendor function has a fixed 7,680-byte stack buffer.
            // Let it render one safe 192-kHz block, then expand to 384 kHz.
            args[4] = ptr(SAFE_RATE);
        }},

        onLeave() {{
            if (!this.adapt || this.output.isNull() || this.sampleCount.isNull()) {{
                return;
            }}

            const frames = this.sampleCount.readU32();
            if (frames === 0 || frames > 1920) {{
                return;
            }}

            if (duplicateStereoFrames !== null) {{
                duplicateStereoFrames(this.output, frames);
            }} else {{
                duplicateFramesFallback(this.output, frames);
            }}
            this.sampleCount.writeU32(frames * 2);

            adaptedCallbacks++;
            if (adaptedCallbacks === 1 || adaptedCallbacks % 6000 === 0) {{
                send({{
                    kind: "adapted",
                    pid: Process.id,
                    callbacks: adaptedCallbacks,
                    inputFrames: frames,
                    outputFrames: frames * 2,
                    nativeScaler: duplicateStereoFrames !== null
                }});
            }}
        }}
    }});

    send({{
        kind: "hook_ready",
        pid: Process.id,
        callback: target.toString()
    }});
}}

Process.attachModuleObserver({{
    onAdded(module) {{
        if (module.name.toLowerCase() === "libshijieroom.dll") {{
            installAudioHook(module);
        }}
    }}
}});

setInterval(function () {{
    if (installed) {{
        return;
    }}
    try {{
        installAudioHook(Process.getModuleByName("libShijieRoom.dll"));
    }} catch (_) {{
    }}
}}, 100);
"""


class CompatEngine:
    def __init__(self, events: queue.Queue[tuple[str, object]]) -> None:
        self.events = events
        self.device = frida.get_local_device()
        self.sessions: dict[int, frida.core.Session] = {}
        self.scripts: dict[int, frida.core.Script] = {}
        self.lock = threading.RLock()
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.root_pid: int | None = None
        self.block_audio_ducking = True

    @property
    def running(self) -> bool:
        return bool(self.thread and self.thread.is_alive())

    def emit(self, kind: str, payload: object = None) -> None:
        self.events.put((kind, payload))

    def gaotu_pids(self) -> set[int]:
        try:
            return {
                process.pid
                for process in self.device.enumerate_processes()
                if process.name.lower() == "gaotu.exe"
            }
        except Exception as exc:
            write_log(f"process scan failed: {exc}")
            return set()

    def start(self, block_audio_ducking: bool) -> None:
        if self.running:
            return
        self.block_audio_ducking = block_audio_ducking
        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._run,
            name="GaotuCompatEngine",
            daemon=True,
        )
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()

    def wait(self, timeout: float) -> bool:
        thread = self.thread
        if not thread:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def _validate_installation(self) -> None:
        if not GAOTU_EXE.is_file():
            raise FileNotFoundError(f"未找到高途程序：{GAOTU_EXE}")
        if not ROOM_DLL.is_file():
            raise FileNotFoundError(f"未找到课堂组件：{ROOM_DLL}")
        actual_hash = sha256_file(ROOM_DLL)
        if actual_hash != EXPECTED_ROOM_DLL_SHA256:
            raise RuntimeError(
                "检测到高途课堂组件版本已变化，为避免错误适配，本修复未启动。\n"
                f"当前 DLL SHA-256：{actual_hash}"
            )

    def _handle_message(self, message: dict, _data: object) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            kind = payload.get("kind")
            if kind == "hook_ready":
                write_log(
                    f"audio hook ready pid={payload.get('pid')} "
                    f"callback={payload.get('callback')}"
                )
                self.emit("audio_ready", payload)
            elif kind == "adapted":
                write_log(
                    f"adapted pid={payload.get('pid')} "
                    f"callbacks={payload.get('callbacks')} "
                    f"frames={payload.get('inputFrames')}->{payload.get('outputFrames')} "
                    f"native={payload.get('nativeScaler')}"
                )
                self.emit("audio_adapted", payload)
            elif kind == "ducking_disabled":
                write_log(
                    f"communication audio switch removed pid={payload.get('pid')} "
                    f"launches={payload.get('launches')}"
                )
                self.emit("ducking_blocked", payload)
        elif message.get("type") == "error":
            details = message.get("description") or message.get("stack")
            write_log(f"hook script error: {details}")
            self.emit("warning", f"兼容脚本报告错误：{details}")

    def _instrument(self, pid: int, hook_script: str) -> None:
        with self.lock:
            if pid in self.sessions:
                return

        session = self.device.attach(pid)
        script = session.create_script(hook_script)
        script.on("message", self._handle_message)
        script.load()

        def on_detached(_reason: str, _crash: object) -> None:
            with self.lock:
                self.sessions.pop(pid, None)
                self.scripts.pop(pid, None)

        session.on("detached", on_detached)
        with self.lock:
            self.sessions[pid] = session
            self.scripts[pid] = script

    def _close_existing_gaotu(self) -> None:
        pids = self.gaotu_pids()
        if not pids:
            return

        user32 = ctypes.windll.user32
        enum_callback_type = ctypes.WINFUNCTYPE(
            ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p
        )

        def close_window(hwnd: int, _lparam: int) -> bool:
            process_id = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
            if process_id.value in pids and user32.IsWindowVisible(hwnd):
                user32.PostMessageW(hwnd, 0x0010, 0, 0)
            return True

        callback = enum_callback_type(close_window)
        user32.EnumWindows(callback, 0)

        deadline = time.monotonic() + 5
        while self.gaotu_pids() and time.monotonic() < deadline:
            time.sleep(0.2)

        for pid in self.gaotu_pids():
            try:
                process_handle = ctypes.windll.kernel32.OpenProcess(
                    0x0001, False, pid
                )
                if process_handle:
                    ctypes.windll.kernel32.TerminateProcess(process_handle, 0)
                    ctypes.windll.kernel32.CloseHandle(process_handle)
            except Exception:
                pass

    def _detach_all(self) -> None:
        with self.lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
            self.scripts.clear()
        for session in sessions:
            try:
                session.detach()
            except Exception:
                pass

    def _run(self) -> None:
        try:
            self._validate_installation()
            self.emit("starting", self.block_audio_ducking)
            write_log(
                "launcher starting "
                f"block_audio_ducking={self.block_audio_ducking}"
            )

            self._close_existing_gaotu()
            hook_script = build_hook_script(self.block_audio_ducking)
            self.root_pid = self.device.spawn([str(GAOTU_EXE)])
            self._instrument(self.root_pid, hook_script)
            self.device.resume(self.root_pid)
            write_log(f"main process started pid={self.root_pid}")
            self.emit("started", self.root_pid)

            empty_scans = 0
            attach_retry_after: dict[int, float] = {}
            while not self.stop_event.is_set():
                gaotu_pids = self.gaotu_pids()
                current_time = time.monotonic()
                attach_retry_after = {
                    pid: retry_time
                    for pid, retry_time in attach_retry_after.items()
                    if pid in gaotu_pids
                }
                for pid in gaotu_pids:
                    with self.lock:
                        known = pid in self.sessions
                    if known or current_time < attach_retry_after.get(pid, 0):
                        continue
                    try:
                        self._instrument(pid, hook_script)
                        attach_retry_after.pop(pid, None)
                    except (
                        frida.ProcessNotFoundError,
                        frida.InvalidOperationError,
                    ):
                        attach_retry_after[pid] = current_time + 30
                    except Exception as exc:
                        write_log(f"attach failed pid={pid}: {exc}")
                        attach_retry_after[pid] = current_time + 30

                if not gaotu_pids:
                    empty_scans += 1
                    if empty_scans >= 5:
                        break
                else:
                    empty_scans = 0
                time.sleep(0.2)

            if self.stop_event.is_set():
                self._close_existing_gaotu()
            self.emit("stopped")
            write_log("launcher stopped")
        except Exception as exc:
            details = traceback.format_exc()
            write_log(details)
            self.emit("error", str(exc))
        finally:
            self._detach_all()
            self.root_pid = None


class CompatApp(Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME}  {APP_VERSION}")
        self.geometry("620x430")
        self.minsize(620, 430)
        self.configure(bg="#f3f6fb")
        try:
            self.iconbitmap(default=str(bundled_asset("assets/gaotu.ico")))
        except Exception:
            pass

        settings = load_settings()
        self.block_ducking = BooleanVar(
            value=settings["block_audio_ducking"]
        )
        self.status_text = StringVar(value="正在准备应用兼容层…")
        self.audio_status = StringVar(value="384 kHz 兼容：等待课堂播放器")
        self.ducking_status = StringVar()
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.engine = CompatEngine(self.events)
        self.closing = False

        self._configure_style()
        self._build_ui()
        self._update_ducking_label()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._drain_events)
        self.after(650, self._auto_start)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except Exception:
            pass
        style.configure(
            "Title.TLabel",
            background="#f3f6fb",
            foreground="#12233f",
            font=("Microsoft YaHei UI", 18, "bold"),
        )
        style.configure(
            "Subtitle.TLabel",
            background="#f3f6fb",
            foreground="#61718c",
            font=("Microsoft YaHei UI", 9),
        )
        style.configure(
            "Card.TFrame",
            background="#ffffff",
            relief="flat",
        )
        style.configure(
            "CardTitle.TLabel",
            background="#ffffff",
            foreground="#182a47",
            font=("Microsoft YaHei UI", 11, "bold"),
        )
        style.configure(
            "CardText.TLabel",
            background="#ffffff",
            foreground="#52627b",
            font=("Microsoft YaHei UI", 9),
        )
        style.configure(
            "Status.TLabel",
            background="#ffffff",
            foreground="#147a50",
            font=("Microsoft YaHei UI", 10, "bold"),
        )
        style.configure(
            "Primary.TButton",
            font=("Microsoft YaHei UI", 10, "bold"),
            padding=(18, 9),
        )
        style.configure(
            "Secondary.TButton",
            font=("Microsoft YaHei UI", 9),
            padding=(14, 8),
        )
        style.configure(
            "Duck.TCheckbutton",
            background="#ffffff",
            foreground="#1c2e4b",
            font=("Microsoft YaHei UI", 10, "bold"),
        )

    def _build_ui(self) -> None:
        header = ttk.Frame(self, padding=(28, 22, 28, 12))
        header.pack(fill="x")
        ttk.Label(header, text="高途课堂兼容修复", style="Title.TLabel").pack(
            anchor="w"
        )
        ttk.Label(
            header,
            text="应用内解决 384 kHz 课堂崩溃，并可控制高途是否触发音频闪避",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(4, 0))

        card = ttk.Frame(self, style="Card.TFrame", padding=(24, 20))
        card.pack(fill="both", expand=True, padx=28, pady=(0, 16))

        ttk.Label(card, text="运行状态", style="CardTitle.TLabel").pack(
            anchor="w"
        )
        ttk.Label(
            card,
            textvariable=self.status_text,
            style="Status.TLabel",
            wraplength=520,
        ).pack(anchor="w", pady=(8, 3))
        ttk.Label(
            card,
            textvariable=self.audio_status,
            style="CardText.TLabel",
        ).pack(anchor="w", pady=2)
        ttk.Label(
            card,
            textvariable=self.ducking_status,
            style="CardText.TLabel",
        ).pack(anchor="w", pady=(2, 16))

        ttk.Separator(card).pack(fill="x", pady=(0, 15))
        ttk.Checkbutton(
            card,
            text="阻止高途触发音频闪避（推荐）",
            variable=self.block_ducking,
            command=self._on_ducking_changed,
            style="Duck.TCheckbutton",
        ).pack(anchor="w")
        ttk.Label(
            card,
            text=(
                "开启后仅移除高途的“通信音频”标记，避免其他程序音量被自动压低；"
                "不会修改 Windows 音频或通信活动设置。"
            ),
            style="CardText.TLabel",
            wraplength=520,
        ).pack(anchor="w", pady=(6, 18))

        actions = ttk.Frame(card, style="Card.TFrame")
        actions.pack(fill="x")
        self.apply_button = ttk.Button(
            actions,
            text="应用设置并启动高途",
            command=self._restart,
            style="Primary.TButton",
        )
        self.apply_button.pack(side="left")
        ttk.Button(
            actions,
            text="退出高途",
            command=self._stop,
            style="Secondary.TButton",
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            actions,
            text="查看日志",
            command=self._open_log,
            style="Secondary.TButton",
        ).pack(side="right")

        ttk.Label(
            self,
            text=(
                "高途原始程序与签名 DLL 保持不变｜当前适配版本：11.12.3.0722"
            ),
            style="Subtitle.TLabel",
        ).pack(anchor="center", pady=(0, 15))

    def _auto_start(self) -> None:
        if not self.closing and not self.engine.running:
            self._start()

    def _update_ducking_label(self) -> None:
        if self.block_ducking.get():
            self.ducking_status.set("音频闪避：已阻止（仅对高途进程）")
        else:
            self.ducking_status.set("音频闪避：允许高途按原方式触发")

    def _on_ducking_changed(self) -> None:
        save_settings(self.block_ducking.get())
        self._update_ducking_label()
        if self.engine.running:
            self.status_text.set(
                "设置已保存；点击“应用设置并启动高途”重启后生效。"
            )

    def _start(self) -> None:
        save_settings(self.block_ducking.get())
        self.apply_button.state(["disabled"])
        self.audio_status.set("384 kHz 兼容：正在等待课堂播放器")
        self.engine.start(self.block_ducking.get())

    def _restart(self) -> None:
        save_settings(self.block_ducking.get())
        self.apply_button.state(["disabled"])
        if not self.engine.running:
            self._start()
            return

        self.status_text.set("正在安全重启高途并应用设置…")

        def restart_worker() -> None:
            self.engine.stop()
            self.engine.wait(10)
            if not self.closing:
                self.after(0, self._start)

        threading.Thread(target=restart_worker, daemon=True).start()

    def _stop(self) -> None:
        if self.engine.running:
            self.status_text.set("正在退出高途…")
            self.engine.stop()
        else:
            self.status_text.set("高途当前未运行。")

    def _open_log(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(DATA_DIR)
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"无法打开日志目录：\n{exc}")

    def _drain_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "starting":
                    self.status_text.set("正在启动高途并加载应用兼容层…")
                elif kind == "started":
                    self.status_text.set("高途已启动，兼容层正在运行。")
                    self.apply_button.state(["!disabled"])
                elif kind == "audio_ready":
                    self.audio_status.set("384 kHz 兼容：课堂模块已接管")
                elif kind == "audio_adapted":
                    details = payload if isinstance(payload, dict) else {}
                    native = "原生快速处理" if details.get("nativeScaler") else "兼容处理"
                    self.audio_status.set(
                        f"384 kHz 兼容：已生效（{native}，"
                        f"{details.get('inputFrames', 1920)}→"
                        f"{details.get('outputFrames', 3840)} 帧）"
                    )
                    self.status_text.set("课堂音频防崩溃修复已生效。")
                elif kind == "ducking_blocked":
                    self.ducking_status.set(
                        "音频闪避：已阻止（高途通信音频标记已移除）"
                    )
                elif kind == "warning":
                    self.status_text.set(str(payload))
                elif kind == "error":
                    self.apply_button.state(["!disabled"])
                    self.status_text.set("启动失败。")
                    messagebox.showerror(APP_NAME, str(payload))
                elif kind == "stopped":
                    self.apply_button.state(["!disabled"])
                    if not self.closing:
                        self.status_text.set("高途已退出，兼容层已停止。")
        except queue.Empty:
            pass
        if not self.closing:
            self.after(100, self._drain_events)

    def _on_close(self) -> None:
        if self.closing:
            return
        if self.engine.running:
            confirmed = messagebox.askyesno(
                APP_NAME,
                "兼容程序需要在高途运行期间保持开启。\n"
                "关闭本程序将同时退出高途，是否继续？",
            )
            if not confirmed:
                return
        self.closing = True
        self.engine.stop()

        def close_worker() -> None:
            self.engine.wait(8)
            self.after(0, self.destroy)

        threading.Thread(target=close_worker, daemon=True).start()


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    kernel32 = ctypes.windll.kernel32
    mutex = kernel32.CreateMutexW(None, False, MUTEX_NAME)
    if not mutex:
        raise ctypes.WinError()
    if kernel32.GetLastError() == 183:
        ctypes.windll.user32.MessageBoxW(
            None,
            "兼容修复程序已经在运行。",
            APP_NAME,
            0x40,
        )
        return

    write_log(f"{APP_NAME} {APP_VERSION} GUI started")
    app = CompatApp()
    app.mainloop()
    write_log("GUI stopped")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        details = traceback.format_exc()
        write_log(details)
        ctypes.windll.user32.MessageBoxW(
            None,
            f"程序发生错误，详细信息已写入：\n{LOG_FILE}",
            APP_NAME,
            0x10,
        )
