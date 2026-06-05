"""
IoT Vulnerability Scanner — Tkinter splash/launcher GUI.

Splash page that checks system dependencies, then runs the three-stage
discovery pipeline (ARP + ICMP + cache → Nmap → CVE) and displays results
in a dark UI that matches the main PyQt6 dashboard style.
"""

import ctypes
import math
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from tkinter import messagebox, scrolledtext, ttk
from typing import Callable, Optional

# Ensure scanner/analysis/llm packages are importable regardless of launch dir.
# gui/ → iden_coop/ → code/  (parent needed so "iden_coop.x" imports resolve)
_gui_dir  = os.path.abspath(os.path.dirname(__file__))
_pkg_dir  = os.path.dirname(_gui_dir)   # iden_coop/
_root_dir = os.path.dirname(_pkg_dir)   # code/
for _d in (_pkg_dir, _root_dir):
    if _d not in sys.path:
        sys.path.insert(0, _d)
del _gui_dir, _pkg_dir, _root_dir, _d

import customtkinter as ctk
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

# ── Apple-style palette ───────────────────────────────────────────────────
SUCCESS      = "#34C759"   # Apple systemGreen
ERROR        = "#FF3B30"   # Apple systemRed
PRIMARY      = "#007AFF"   # Apple systemBlue
PRIMARY_DARK = "#0051D5"   # Apple blue pressed
BG           = "#FFFFFF"
BG_LIGHT     = "#F2F2F7"   # Apple systemGroupedBackground
BG_BORDER    = "#C6C6C8"   # Apple separator
TEXT         = "#1C1C1E"   # Apple label
MUTED        = "#6C6C70"   # Apple secondaryLabel
BLUE_BOX     = "#E5F1FF"
BLUE_TEXT    = "#0051D5"
AMBER        = "#FF9500"   # Apple systemOrange

# ── Results window palette (Apple system colours) ─────────────────────────
D_BG        = "#F2F2F7"   # systemGroupedBackground
D_CARD      = "#FFFFFF"   # systemBackground
D_SIDE      = "#F2F2F7"
D_ACCENT    = "#007AFF"   # systemBlue
D_TEXT      = "#1C1C1E"   # label
D_SUB       = "#6C6C70"   # secondaryLabel
D_BORDER    = "#C6C6C8"   # separator
SCAN_BG     = "#1C1C1E"   # near-black for scanning modal

# ── Risk colours (Apple system colours) ───────────────────────────────────
RISK_COLOURS = {
    "Critical": "#FF3B30",   # Apple red
    "High":     "#FF9500",   # Apple orange
    "Medium":   "#FFCC00",   # Apple yellow
    "Low":      "#34C759",   # Apple green
    "Info":     "#007AFF",   # Apple blue
}
RISK_TEXT = {
    "Medium": "#1C1C1E",   # yellow badge needs dark text
}


# ── Dependency checks ─────────────────────────────────────────────────────

def _check_python() -> tuple[bool, str]:
    v = sys.version_info
    ok = (v.major, v.minor) >= (3, 11)
    detail = f"Python {v.major}.{v.minor}.{v.micro} detected"
    if not ok:
        detail = f"Python {v.major}.{v.minor} detected — 3.11+ required"
    return ok, detail


def _check_ollama() -> tuple[bool, str]:
    try:
        s = socket.create_connection(("localhost", 11434), timeout=2)
        s.close()
        return True, "Running on localhost:11434"
    except Exception:
        return False, "Not running — start with: ollama serve"


def _check_nmap() -> tuple[bool, str]:
    path = shutil.which("nmap")
    if not path:
        return False, "Not found in PATH"
    try:
        r = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
        line = r.stdout.splitlines()[0] if r.stdout else "nmap found"
        return True, line.strip()
    except Exception:
        return True, "Found (version unknown)"


def _check_admin() -> tuple[bool, str]:
    try:
        if platform.system() == "Windows":
            ok = bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            ok = subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() == "0"
    except Exception:
        ok = False
    return ok, "Administrator access confirmed" if ok else "Required for raw socket access"


DEPS = [
    ("python", "Python 3.11+",            _check_python),
    ("ollama", "Ollama (Local LLM)",       _check_ollama),
    ("nmap",   "Nmap Network Scanner",     _check_nmap),
    ("admin",  "Administrator Privileges", _check_admin),
]


# ── Splash / main window ──────────────────────────────────────────────────

class IoTScannerGUI:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("IoT Vulnerability Scanner")
        self.root.geometry("620x700")
        self.root.resizable(True, True)
        self.root.configure(bg="#F2F2F7")
        self.root.bind("<F11>", self._toggle_fullscreen)
        self.root.bind("<Escape>", self._exit_fullscreen)
        self._fullscreen = False

        self._dep_status: dict[str, bool] = {}
        self._dep_widgets: dict[str, dict] = {}

        self.setup_ui()
        self._start_dependency_checks()

    # ── Rounded box helper ────────────────────────────────────────────────

    def _rounded_box(self, parent: tk.Frame, fill: str,
                     outline: str = "#d1d5db", r: int = 12) -> tk.Frame:
        """Return a tk.Frame inside a Canvas-drawn rounded rectangle."""
        bg = parent["bg"]
        canvas = tk.Canvas(parent, bg=bg, highlightthickness=0)
        canvas.pack(fill="x", pady=(0, 12))
        inner = tk.Frame(canvas, bg=fill)
        win = canvas.create_window(r, r, anchor="nw", window=inner)

        def _redraw(e=None):
            cw = canvas.winfo_width()
            ih = inner.winfo_reqheight()
            if cw < 20 or ih < 4:
                return
            h = ih + r * 2
            canvas.config(height=h)
            canvas.delete("rr")
            pts = [
                r, 0,   cw - r, 0,
                cw, 0,  cw, r,
                cw, h - r,  cw, h,
                cw - r, h,  r, h,
                0, h,   0, h - r,
                0, r,   0, 0,
            ]
            canvas.create_polygon(pts, smooth=True,
                                  fill=fill, outline=outline, width=1, tags="rr")
            canvas.itemconfig(win, width=cw - r * 2)

        canvas.bind("<Configure>", lambda e: canvas.after(5, _redraw))
        inner.bind("<Configure>", lambda e: canvas.after(5, _redraw))
        return inner

    def _toggle_fullscreen(self, event=None) -> None:
        self._fullscreen = not self._fullscreen
        self.root.attributes("-fullscreen", self._fullscreen)

    def _exit_fullscreen(self, event=None) -> None:
        if self._fullscreen:
            self._fullscreen = False
            self.root.attributes("-fullscreen", False)

    def setup_ui(self) -> None:
        # Scrollable canvas — content never gets clipped regardless of window size
        self._main_canvas = tk.Canvas(
            self.root, bg="#F2F2F7", highlightthickness=0
        )
        self._main_canvas.pack(fill="both", expand=True)

        # Mouse-wheel scrolling
        self._main_canvas.bind(
            "<MouseWheel>",
            lambda e: self._main_canvas.yview_scroll(-(e.delta // 120), "units"),
        )

        # Content frame inside the canvas
        self._scroll_frame = tk.Frame(self._main_canvas, bg="#F2F2F7")
        self._scroll_id = self._main_canvas.create_window(
            0, 0, anchor="nw", window=self._scroll_frame
        )

        self._scroll_frame.bind("<Configure>", self._on_frame_configure)
        self._main_canvas.bind("<Configure>", self._on_canvas_configure)

        # The actual padded content, centred inside scroll_frame
        content = tk.Frame(self._scroll_frame, bg="#F2F2F7")
        content.pack(padx=20, pady=14)

        self._build_header(content)
        self._build_dep_box(content)
        self._build_privacy_box(content)
        self._build_scan_button(content)

    def _on_frame_configure(self, event=None) -> None:
        self._main_canvas.configure(
            scrollregion=self._main_canvas.bbox("all")
        )

    def _on_canvas_configure(self, event=None) -> None:
        # Keep scroll_frame the full canvas width so content centres properly
        self._main_canvas.itemconfig(
            self._scroll_id, width=event.width if event else self._main_canvas.winfo_width()
        )

    # ── Header ────────────────────────────────────────────────────────────

    def _build_header(self, parent: tk.Frame) -> None:
        bg = "#F2F2F7"
        hdr = tk.Frame(parent, bg=bg)
        hdr.pack(pady=(0, 10))

        c = tk.Canvas(hdr, width=72, height=72, bg=bg, highlightthickness=0)
        c.pack()
        c.create_oval(4, 4, 68, 68, fill="#dbeafe", outline="#93c5fd", width=2)
        c.create_text(36, 38, text="🪬", font=("Segoe UI Emoji", 32))

        tk.Label(hdr, text="IoT Vulnerability Scanner",
                 font=("Segoe UI", 17, "bold"), fg="#0f172a", bg=bg).pack(pady=(5, 0))
        tk.Label(hdr,
                 text="Scan your home network for vulnerable devices in one click",
                 font=("Segoe UI", 9), fg="#64748b", bg=bg).pack(pady=(2, 0))

    # ── Dependency box ────────────────────────────────────────────────────

    def _build_dep_box(self, parent: tk.Frame) -> None:
        box = self._rounded_box(parent, fill="#FFFFFF", outline="#C6C6C8", r=14)

        # Section header
        hdr_row = tk.Frame(box, bg="#FFFFFF")
        hdr_row.pack(fill="x", padx=16, pady=(10, 6))

        gc = tk.Label(hdr_row, text="⚙️", font=("Segoe UI Emoji", 13),
                      bg="#FFFFFF")
        gc.pack(side="left")

        tk.Label(hdr_row, text="  System Requirements",
                 font=("Segoe UI", 12, "bold"),
                 fg="#0f172a", bg="#FFFFFF").pack(side="left")

        # Separator
        tk.Frame(box, bg="#e2e8f0", height=1).pack(fill="x", padx=14)

        for i, (key, label, _) in enumerate(DEPS):
            row = tk.Frame(box, bg="#FFFFFF")
            row.pack(fill="x", padx=16, pady=6)

            badge = tk.Label(row, text="⏳", font=("Segoe UI Emoji", 14),
                             bg="#FFFFFF")
            badge.pack(side="left", padx=(0, 10))

            info = tk.Frame(row, bg="#FFFFFF")
            info.pack(side="left", fill="x", expand=True)

            tk.Label(info, text=label,
                     font=("Segoe UI", 10, "bold"),
                     fg="#0f172a", bg="#FFFFFF", anchor="w").pack(anchor="w")

            detail_lbl = tk.Label(info, text="Checking...",
                                  font=("Segoe UI", 8),
                                  fg="#94a3b8", bg="#FFFFFF", anchor="w")
            detail_lbl.pack(anchor="w")

            self._dep_widgets[key] = {"badge": badge, "detail": detail_lbl}

            if i < len(DEPS) - 1:
                tk.Frame(box, bg="#e2e8f0", height=1).pack(fill="x", padx=14)

        # bottom padding
        tk.Frame(box, bg="#FFFFFF", height=6).pack()

    # ── Privacy box ───────────────────────────────────────────────────────

    def _build_privacy_box(self, parent: tk.Frame) -> None:
        box = self._rounded_box(parent, fill="#EBF4FF", outline="#A8C8E8", r=14)

        inner = tk.Frame(box, bg="#EBF4FF")
        inner.pack(fill="x", padx=14, pady=9)

        bc = tk.Label(inner, text="🔒", font=("Segoe UI Emoji", 20),
                      bg="#EBF4FF")
        bc.pack(side="left", padx=(0, 10))

        tf = tk.Frame(inner, bg="#EBF4FF")
        tf.pack(side="left", fill="x", expand=True)

        tk.Label(tf, text="Privacy-First Design",
                 font=("Segoe UI", 9, "bold"),
                 fg="#1e40af", bg="#EBF4FF", anchor="w").pack(anchor="w")
        tk.Label(tf,
                 text="All analysis runs locally. No data is sent to external servers.\n"
                      "Your network information stays private.",
                 font=("Segoe UI", 8), fg="#1e40af", bg="#EBF4FF",
                 anchor="w", justify="left").pack(anchor="w")

    # ── Scan button (Apple pill) ──────────────────────────────────────────

    def _build_scan_button(self, parent: tk.Frame) -> None:
        self._btn_enabled  = False
        self._btn_scanning = False

        self._btn_cv = tk.Canvas(parent, height=48, bg="#F2F2F7",
                                 highlightthickness=0)
        self._btn_cv.pack(fill="x", pady=(6, 4))
        self._btn_cv.bind("<Configure>",    lambda e: self._redraw_btn())
        self._btn_cv.bind("<ButtonPress-1>",   self._on_btn_press)
        self._btn_cv.bind("<ButtonRelease-1>", self._on_btn_release)

        self._scan_msg = tk.Label(
            parent, text="Checking system requirements...",
            font=("Segoe UI", 9), fg="#8E8E93", bg="#F2F2F7",
        )
        self._scan_msg.pack()

    def _redraw_btn(self, pressed: bool = False) -> None:
        cv = self._btn_cv
        cv.delete("all")
        w, h = cv.winfo_width(), cv.winfo_height()
        if w < 10 or h < 10:
            return
        r = h // 2  # full pill radius

        if self._btn_scanning:
            fill, label = "#636366", "Scanning…"
        elif not self._btn_enabled:
            fill, label = "#C7C7CC", "🌊  Scan My Network"
        elif pressed:
            fill, label = "#0051D5", "🌊  Scan My Network"
        else:
            fill, label = "#007AFF", "🌊  Scan My Network"

        pts = [r,0, w-r,0, w,0, w,r, w,h-r, w,h, w-r,h, r,h, 0,h, 0,h-r, 0,r, 0,0]
        cv.create_polygon(pts, smooth=True, fill=fill, outline="")
        cv.create_text(w // 2, h // 2 + 1, text=label,
                       fill="white", font=("Segoe UI", 12, "bold"))

    def _on_btn_press(self, event) -> None:
        if self._btn_enabled and not self._btn_scanning:
            self._redraw_btn(pressed=True)

    def _on_btn_release(self, event) -> None:
        if self._btn_enabled and not self._btn_scanning:
            self._redraw_btn()
            self._on_scan_clicked()

    # ── Dependency checking ───────────────────────────────────────────────

    def _start_dependency_checks(self) -> None:
        threading.Thread(target=self._run_checks, daemon=True).start()

    def _run_checks(self) -> None:
        for key, _, fn in DEPS:
            ok, detail = fn()
            self.root.after(0, self.update_dependency, key, ok, detail)

    def update_dependency(self, key: str, ok: bool, detail: str) -> None:
        w = self._dep_widgets[key]
        badge = w["badge"]
        badge.config(text="✅" if ok else "❌")
        w["detail"].config(text=detail,
                           fg="#34C759" if ok else "#FF3B30")
        self._dep_status[key] = ok
        if len(self._dep_status) == len(DEPS):
            self._refresh_scan_button()

    def _refresh_scan_button(self) -> None:
        # Ollama is optional — scan can run without it; only block on hard deps.
        hard_deps = {k: v for k, v in self._dep_status.items() if k != "ollama"}
        all_hard_ok = all(hard_deps.values())
        ollama_ok = self._dep_status.get("ollama", True)

        if all_hard_ok:
            self._btn_enabled = True
            self._btn_cv.config(cursor="hand2")
            if ollama_ok:
                self._scan_msg.config(text="All requirements met — ready to scan",
                                      fg="#34C759")
            else:
                self._scan_msg.config(
                    text="Ready to scan  —  AI features limited (Ollama not running)",
                    fg="#FF9500",
                )
        else:
            self._btn_enabled = False
            self._btn_cv.config(cursor="arrow")
            self._scan_msg.config(text="Please resolve the issues above to continue",
                                  fg="#FF3B30")
        self._redraw_btn()

    # ── Scan launch ───────────────────────────────────────────────────────

    def _on_scan_clicked(self) -> None:
        ollama_ok = self._dep_status.get("ollama", True)
        if not ollama_ok:
            messagebox.showwarning(
                "Ollama Not Running",
                "Ollama is not running — AI features will be limited:\n\n"
                "  • 'Get Security Plan' buttons will be disabled\n"
                "  • Network Findings AI Rating will be unavailable\n\n"
                "All other scan features (discovery, port scan, CVE lookup)\n"
                "work normally without Ollama.\n\n"
                "To enable AI: run  ollama serve  then rescan.",
            )

        if messagebox.askokcancel(
            "Start Network Scan",
            "IdenCoop will now scan your home network.\n\n"
            "What will happen:\n"
            "  • Non-intrusive device discovery (ARP + ICMP + Cache)\n"
            "  • CVE vulnerability checking via NVD database\n"
            "  • Local AI analysis using Ollama\n\n"
            "Estimated time: 2–5 minutes\n\n"
            "No data leaves your machine.",
            icon="info",
        ):
            self.start_scan()

    def start_scan(self, subnet: Optional[str] = None) -> None:
        print("[TRACE] start_scan() called")
        self._btn_scanning = True
        self._btn_enabled  = False
        self._redraw_btn()
        print("[TRACE] Creating ScanningModal...")
        ScanningModal(self.root, subnet=subnet, on_complete=self._on_scan_complete)
        print("[TRACE] ScanningModal created")

    def _on_scan_complete(self, results: list, logs: list[str]) -> None:
        self._btn_scanning = False
        self._btn_enabled  = True
        self._redraw_btn()
        if results:
            ResultsWindow(self.root, results, logs, rescan_cb=self.start_scan)
        else:
            messagebox.showwarning(
                "No Devices Found",
                "No devices were discovered.\n\n"
                "Ensure you are connected to your home network "
                "and running as Administrator.",
            )


# ── Helpers ───────────────────────────────────────────────────────────────

def _severity_to_level(severity: str) -> str:
    return {
        "CRITICAL": "Critical", "HIGH": "High",
        "MEDIUM": "Medium", "LOW": "Low",
    }.get(severity.upper(), "Info")


# ── Scanning modal ────────────────────────────────────────────────────────

class ScanningModal:

    _STEPS = [
        ("🔍", "Discovering devices",              "ARP + ICMP + OS Cache"),
        ("🔍", "Analysing open ports",             "Non-intrusive Nmap scan"),
        ("🧠", "Running AI vulnerability assessment", "Powered by Ollama (local)"),
    ]

    def __init__(self, parent: tk.Tk, on_complete: Callable,
                 subnet: Optional[str] = None):
        print("[TRACE] ScanningModal.__init__() called")
        self._parent      = parent
        self._on_complete = on_complete
        self._subnet      = subnet
        self._results: list = []
        self._log_lines: list[str] = []
        self._log_visible = False

        self._win = tk.Toplevel(parent)
        self._win.title("Scanning Network…")
        self._win.resizable(False, False)
        self._win.configure(bg=SCAN_BG)
        self._win.grab_set()
        self._win.protocol("WM_DELETE_WINDOW", lambda: None)

        self._build_ui()
        self._centre(700, 500)

        print("[TRACE] Starting _run_pipeline thread...")
        threading.Thread(target=self._run_pipeline, daemon=True).start()
        print("[TRACE] Thread started")

    def _centre(self, w: int, h: int) -> None:
        self._win.geometry(f"{w}x{h}")
        self._win.update_idletasks()
        px = self._parent.winfo_x() + (self._parent.winfo_width()  - w) // 2
        py = self._parent.winfo_y() + (self._parent.winfo_height() - h) // 2
        self._win.geometry(f"{w}x{h}+{px}+{py}")

    def _build_ui(self) -> None:
        # ── Header ─────────────────────────────────────────────────────────
        hdr = tk.Frame(self._win, bg=SCAN_BG)
        hdr.pack(fill="x", pady=(28, 4))
        tk.Label(hdr, text="📡", font=("Segoe UI Emoji", 38), bg=SCAN_BG).pack()
        tk.Label(hdr, text="Scanning Your Network…",
                 font=("Segoe UI", 17, "bold"), fg="#F2F2F7", bg=SCAN_BG).pack(pady=(4, 0))
        tk.Label(hdr, text="Please keep the application open",
                 font=("Segoe UI", 10), fg="#8E8E93", bg=SCAN_BG).pack(pady=(2, 16))

        # ── Step indicators ────────────────────────────────────────────────
        steps_frame = tk.Frame(self._win, bg=SCAN_BG)
        steps_frame.pack(fill="x", padx=60, pady=(0, 16))
        self._step_labels: list[tk.Label] = []

        for icon, title, sub in self._STEPS:
            row = tk.Frame(steps_frame, bg=SCAN_BG)
            row.pack(fill="x", pady=5)

            tk.Label(row, text=icon, font=("Segoe UI Emoji", 13),
                     fg="#F2F2F7", bg=SCAN_BG, width=2).pack(side="left")
            inner = tk.Frame(row, bg=SCAN_BG)
            inner.pack(side="left", padx=10, fill="x", expand=True)

            lbl = tk.Label(inner, text=title, font=("Segoe UI", 11, "bold"),
                           fg="#8E8E93", bg=SCAN_BG, anchor="w")
            lbl.pack(fill="x")
            tk.Label(inner, text=sub, font=("Segoe UI", 9),
                     fg="#48484A", bg=SCAN_BG, anchor="w").pack(fill="x")
            self._step_labels.append(lbl)

        # ── Progress bar ───────────────────────────────────────────────────
        pb_outer = tk.Frame(self._win, bg=SCAN_BG)
        pb_outer.pack(fill="x", padx=60, pady=(4, 12))

        self._progress = _RoundPBar(pb_outer)
        self._progress.pack(fill="x", pady=(2, 0))
        self._progress.start(14)

        self._progress_label = tk.Label(
            pb_outer, text="Discovering devices…",
            font=("Segoe UI", 9), fg="#8E8E93", bg=SCAN_BG, anchor="w",
        )
        self._progress_label.pack(fill="x", pady=(4, 0))

        # ── Detail toggle button ───────────────────────────────────────────
        self._toggle_btn = tk.Button(
            self._win, text="▼  Show Details",
            font=("Segoe UI", 10), fg="#8E8E93", bg="#2C2C2E",
            activebackground="#3A3A3C", activeforeground="#F2F2F7",
            relief="flat", bd=0, cursor="hand2", pady=6,
            command=self._toggle_log,
        )
        self._toggle_btn.pack(fill="x", padx=60, pady=(0, 4))

        # ── Log panel (hidden until toggled) ──────────────────────────────
        self._log_frame = tk.Frame(self._win, bg=SCAN_BG)

        self._log_box = scrolledtext.ScrolledText(
            self._log_frame,
            height=12, font=("Consolas", 9),
            bg="#0d1117", fg="#7ee787",
            insertbackground=D_TEXT,
            relief="flat", bd=0, padx=10, pady=8,
            state="disabled", wrap="word",
        )
        self._log_box.pack(fill="both", expand=True, padx=60, pady=(0, 16))

    def _toggle_log(self) -> None:
        if self._log_visible:
            self._log_frame.pack_forget()
            self._toggle_btn.config(text="▼  Show Details")
            self._win.geometry("700x500")
        else:
            self._log_frame.pack(fill="both", expand=True)
            self._toggle_btn.config(text="▲  Hide Details")
            self._win.geometry("700x740")
        self._log_visible = not self._log_visible

    def _log(self, msg: str) -> None:
        """Append a line to the log box and collected log list."""
        self._log_lines.append(msg)
        def _append():
            self._log_box.config(state="normal")
            self._log_box.insert("end", msg + "\n")
            self._log_box.see("end")
            self._log_box.config(state="disabled")
        self._win.after(0, _append)

    def _set_step(self, idx: int) -> None:
        def _update():
            for i, lbl in enumerate(self._step_labels):
                if i < idx:
                    lbl.config(fg="#34C759")
                elif i == idx:
                    lbl.config(fg="#F2F2F7")
                else:
                    lbl.config(fg="#8E8E93")
        self._win.after(0, _update)

    def _init_progress(self, total: int) -> None:
        def _update():
            self._progress.stop()
            self._progress.config(mode="determinate", maximum=total, value=0)
            self._progress_done = 0
            self._progress_label.config(text=f"Scanning 0 of {total} device(s)…")
        self._win.after(0, _update)

    def _tick_progress(self, ip: str, done: int, total: int) -> None:
        def _update():
            self._progress["value"] = done
            self._progress_label.config(text=f"Scanning {ip}… ({done}/{total})")
        self._win.after(0, _update)

    def _finish_progress(self, total: int) -> None:
        def _update():
            self._progress["value"] = total
            self._progress_label.config(text=f"Scan complete — {total} device(s) analysed")
        self._win.after(0, _update)

    # ── Pipeline ──────────────────────────────────────────────────────────

    def _run_pipeline(self) -> None:
        print("[TRACE] _run_pipeline() started")
        # Log to file for debugging
        import tempfile
        logfile = os.path.join(tempfile.gettempdir(), "iot_shield_scan.log")

        def file_log(msg: str) -> None:
            print(f"[LOG] {msg}")
            self._log(msg)
            try:
                with open(logfile, "a") as f:
                    f.write(msg + "\n")
            except:
                pass

        try:
            # Stage 1 — Discovery
            print("[TRACE] Setting step 0...")
            self._set_step(0)
            print("[TRACE] Logging scan start...")
            file_log(f"=== SCAN START ===")
            file_log(f"Subnet parameter: {self._subnet or 'auto-detect'}")

            try:
                from iden_coop.scanner.discovery import discover, get_local_subnets
                file_log("✓ Discovery module imported")

                # Show what subnets we'll scan
                if not self._subnet:
                    try:
                        local = get_local_subnets()
                        file_log(f"  Local subnets detected: {local}")
                    except Exception as e:
                        file_log(f"  Warning: Could not get local subnets: {e}")
            except ImportError as ie:
                file_log(f"[ERROR] Failed to import discovery: {ie}")
                raise

            try:
                file_log("Starting discover()...")
                hosts = discover(subnet=self._subnet, log=file_log)
                file_log(f"→ {len(hosts)} host(s) found")
            except Exception as de:
                file_log(f"[ERROR] Discovery failed: {de}")
                import traceback
                file_log(traceback.format_exc())
                raise

            self._init_progress(len(hosts))

            # Stage 2 — Nmap + CVE
            self._set_step(1)
            from iden_coop.scanner import nmap_scan, cve_lookup
            from iden_coop.scanner.discovery import get_local_subnets
            from iden_coop.analysis.risk_engine import score_device

            nmap_bin = nmap_scan._find_nmap()
            self._log(f"Nmap binary: {nmap_bin or 'NOT FOUND'}")

            # Determine which subnets are directly connected so we can flag
            # routed (gateway-discovered) hosts and use TCP-connect scans.
            try:
                local_prefixes = {
                    sn.rsplit(".0/24", 1)[0]
                    for sn in get_local_subnets()
                }
            except Exception:
                local_prefixes = set()

            def _is_routed(ip: str) -> bool:
                prefix = ip.rsplit(".", 1)[0]
                return prefix not in local_prefixes

            _VIRTUAL_VENDORS = ("vmware", "virtualbox", "oracle vm virtualbox")

            def _is_virtual_adapter(vendor: str) -> bool:
                v = (vendor or "").lower()
                return any(kw in v for kw in _VIRTUAL_VENDORS)

            results = []
            for i, host in enumerate(hosts, 1):
                self._tick_progress(host.ip, i - 1, len(hosts))
                routed = _is_routed(host.ip)

                # Skip nmap for VMware/VirtualBox virtual adapter IPs — these are
                # the host machine's own virtual network services (DHCP, NAT),
                # not IoT devices. A full 65535-port scan would time out or return
                # nothing useful.
                if _is_virtual_adapter(host.vendor or ""):
                    self._log(
                        f"Skipping {host.ip}  ({host.vendor})  — local virtual adapter"
                    )
                    results.append({
                        "ip": host.ip, "mac": host.mac,
                        "vendor": host.vendor, "hostname": host.hostname,
                        "os_guess": "Virtual Adapter", "risk_level": "Info",
                        "risk_score": 0.0, "services": [], "cves": [],
                        "risk_reasons": ["Local VMware/VirtualBox virtual adapter — not scanned"],
                    })
                    continue

                self._log(f"Scanning {host.ip}  ({host.vendor or 'Unknown'}){'  [routed]' if routed else ''}…")
                device: dict = {
                    "ip": host.ip, "mac": host.mac,
                    "vendor": host.vendor, "hostname": host.hostname,
                    "os_guess": "", "risk_level": "Info", "risk_score": 0.0,
                    "services": [], "cves": [], "risk_reasons": [],
                }
                try:
                    nm = nmap_scan.scan_host(host.ip, privileged=True, routed=routed)
                    device["os_guess"] = nm.os_guess
                    svcs = [
                        {"port": s.port, "protocol": s.protocol, "state": s.state,
                         "name": s.name, "product": s.product, "version": s.version,
                         "extra_info": s.extra_info, "script_output": s.script_output}
                        for s in nm.services
                    ]
                    open_ports = [str(s["port"]) for s in svcs if s["state"] == "open"]
                    if open_ports:
                        self._log(f"  Open ports: {', '.join(open_ports)}")
                    device["services"] = svcs

                    cve_map = cve_lookup.lookup_cves_for_services(svcs)
                    cves = []
                    for cve_list in cve_map.values():
                        for c in cve_list:
                            cves.append({"cve_id": c.cve_id, "cvss_score": c.cvss_score,
                                         "severity": c.severity, "description": c.description})
                    if cves:
                        self._log(f"  {len(cves)} CVE(s) found — top CVSS {cves[0]['cvss_score']}")
                    device["cves"] = cves

                    nse = nmap_scan.flag_dangerous_services(nm)
                    risk = score_device(svcs, cves, nse)
                    device["risk_level"]   = risk.level.value
                    device["risk_score"]   = risk.score
                    device["risk_reasons"] = risk.reasons
                    self._log(f"  Risk: {risk.level.value}  (score {risk.score})")
                except Exception as exc:
                    import traceback
                    self._log(f"  Scan error: {exc}")
                    self._log(traceback.format_exc())

                results.append(device)

            # Stage 3 — Persist results to SQLite
            self._set_step(2)
            try:
                from iden_coop.database.db import insert_scan
                scan_id = insert_scan(results, subnet=self._subnet or "auto")
                self._log(f"Results saved to database (scan #{scan_id}).")
            except Exception as db_exc:
                self._log(f"  Database write skipped: {db_exc}")

            self._finish_progress(len(results))
            self._log("AI assessment ready — click 'Get AI Advice' on any device.")
            self._results = results

        except Exception as exc:
            _msg = str(exc)
            self._log(f"[ERROR] {_msg}")
            self._results = []
            self._win.after(0, lambda m=_msg: messagebox.showerror(
                "Scan Error", m, parent=self._win
            ))
        finally:
            self._win.after(0, self._finish)

    def _finish(self) -> None:
        self._win.grab_release()
        self._win.destroy()
        self._on_complete(self._results, self._log_lines)


class _RoundPBar(tk.Canvas):
    """
    Pill-shaped progress bar — replaces ttk.Progressbar for full visual control.
    Supports indeterminate (bouncing slug) and determinate (fill) modes.
    Exposes the same minimal API the ScanningModal uses.
    """
    _BG = "#3A3A3C"   # trough (dark gray)
    _FG = "#34C759"   # fill  (Apple green)
    _H  = 12          # bar height in pixels

    def __init__(self, parent, **kwargs):
        kwargs.setdefault("height", self._H)
        kwargs.setdefault("bg", SCAN_BG)
        kwargs.setdefault("highlightthickness", 0)
        super().__init__(parent, **kwargs)
        self._mode    = "indeterminate"
        self._value   = 0.0
        self._maximum = 100.0
        self._slug_x  = 0
        self._slug_dir = 1
        self._after_id = None
        self.bind("<Configure>", lambda e: self._draw())

    # ── ttk-compatible API ────────────────────────────────────────────────

    def start(self, interval: int = 14) -> None:
        self._mode = "indeterminate"
        self._tick(interval)

    def stop(self) -> None:
        if self._after_id:
            self.after_cancel(self._after_id)
            self._after_id = None

    def configure(self, **kw):          # type: ignore[override]
        if "mode" in kw:    self._mode    = kw.pop("mode")
        if "maximum" in kw: self._maximum = float(kw.pop("maximum"))
        if "value" in kw:
            self._value = float(kw.pop("value"))
            self._draw()
        super().configure(**kw)

    def config(self, **kw):             # alias used in ScanningModal
        self.configure(**kw)

    def __setitem__(self, key, val):    # progress["value"] = n
        if key == "value":
            self._value = float(val)
            self._draw()
        elif key == "maximum":
            self._maximum = float(val)

    def __getitem__(self, key):
        return self._value if key == "value" else self._maximum

    # ── Internal animation ────────────────────────────────────────────────

    def _tick(self, ms: int) -> None:
        W = self.winfo_width() or 1
        slug = max(int(W * 0.28), 60)
        self._slug_x += self._slug_dir * 7
        if self._slug_x + slug >= W:
            self._slug_dir = -1
        if self._slug_x <= 0:
            self._slug_dir = 1
            self._slug_x = 0
        self._draw()
        self._after_id = self.after(ms, self._tick, ms)

    def _draw(self) -> None:
        W = self.winfo_width()
        H = self._H
        if W < 4:
            return
        self.delete("all")
        r = H // 2
        # Background pill
        self._pill(0, 0, W, H, r, self._BG)
        # Fill
        if self._mode == "indeterminate":
            slug = max(int(W * 0.28), 60)
            x0 = max(0, min(self._slug_x, W - slug))
            self._pill(x0, 0, x0 + slug, H, r, self._FG)
        else:
            if self._maximum > 0:
                fw = int(W * min(self._value / self._maximum, 1.0))
                if fw > 0:
                    self._pill(0, 0, fw, H, r, self._FG)

    def _pill(self, x0, y0, x1, y1, r, color) -> None:
        r = min(r, max((x1 - x0) // 2, 0))
        if r < 1 or x1 <= x0:
            return
        self.create_oval(x0, y0, x0 + 2*r, y1, fill=color, outline="")
        self.create_oval(x1 - 2*r, y0, x1, y1, fill=color, outline="")
        if x1 - x0 > 2 * r:
            self.create_rectangle(x0 + r, y0, x1 - r, y1, fill=color, outline="")


def _smooth_circle(c: tk.Canvas, cx: float, cy: float, r: float, **kw) -> int:
    """Polygon-approximated circle with smooth=True — no jagged oval edges."""
    pts: list[float] = []
    for i in range(48):
        a = 2 * math.pi * i / 48
        pts.extend([cx + r * math.cos(a), cy + r * math.sin(a)])
    return c.create_polygon(pts, smooth=True, **kw)


def _device_emoji(dev: dict) -> str:
    """Pick a contextual emoji based on vendor, hostname, OS and open ports."""
    vendor   = (dev.get("vendor")   or "").lower()
    hostname = (dev.get("hostname") or "").lower()
    os_guess = (dev.get("os_guess") or "").lower()
    ports    = {s.get("port") for s in dev.get("services", [])
                if s.get("state") == "open"}
    ip       = dev.get("ip", "")

    # Gateway / router — .1 or .254 addresses, or hostname hints
    last_octet = ip.rsplit(".", 1)[-1] if "." in ip else ""
    if last_octet in ("1", "254") or any(k in hostname for k in ("gateway", "router", "gw")):
        return "🌐"

    # Smart TV / streaming stick
    if any(k in vendor for k in ("hisense", "samsung", "lg electron", "sony",
                                  "tcl", "vizio", "roku", "philips", "panasonic")):
        return "📺"
    # Apple device
    if "apple" in vendor or any(k in hostname for k in ("iphone", "ipad", "macbook", "imac")):
        return "🍎"
    # macOS by OS
    if "mac os" in os_guess or "darwin" in os_guess:
        return "🍎"
    # Printer
    if 9100 in ports or 631 in ports or "print" in hostname:
        return "🖨️"
    if any(k in vendor for k in ("epson", "canon", "brother", "lexmark", "xerox", "ricoh", "kyocera")):
        return "🖨️"
    # IP Camera / NVR / CCTV
    if 554 in ports or any(k in hostname for k in ("cam", "nvr", "dvr", "cctv", "ipcam")):
        return "📷"
    # Mobile / tablet
    if any(k in hostname for k in ("phone", "mobile", "android", "iphone", "galaxy", "pixel")):
        return "📱"
    if "android" in os_guess or "ios" in os_guess:
        return "📱"
    # Smart speaker / audio
    if any(k in vendor for k in ("amazon", "sonos", "bose", "harman", "jbl")):
        return "🔊"
    if "echo" in hostname or "alexa" in hostname or "google-home" in hostname:
        return "🔊"
    # Network infra (not gateway)
    if any(k in vendor for k in ("cisco", "netgear", "tp-link", "ubiquiti",
                                  "linksys", "d-link", "zyxel", "aruba",
                                  "ruckus", "mikrotik", "fortinet", "palo alto")):
        return "📡"
    # NAS / storage
    if any(k in vendor for k in ("synology", "qnap", "western digital", "seagate")):
        return "🗄️"
    if any(k in hostname for k in ("nas", "storage", "synology", "qnap")):
        return "🗄️"
    # VMware / virtual machine — distinctive VM icon
    if "vmware" in vendor or "virtual" in hostname or "vm" in hostname:
        return "🖳"
    # Generic PC / laptop vendors
    if any(k in vendor for k in ("dell", "lenovo", "acer", "gigabyte", "msi",
                                  "hewlett", "hp ", "intel", "asus")):
        return "🖥️"
    if "windows" in os_guess:
        return "🖥️"
    if "linux" in os_guess:
        return "🐧"
    # Unknown / generic IoT
    return "📡"


_EMOJI_TYPE = {
    "🌐": "Gateway / Router",
    "📺": "Smart TV / Monitor",
    "🍎": "Mac / iOS PC",
    "🖨️": "Printer",
    "📷": "Security Camera",
    "📱": "Smartphone",
    "🔊": "Smart Speaker / Audio Device",
    "📡": "Generic Network Endpoint",
    "🗄️": "Server",
    "🖥️": "Desktop Computer",
    "💻": "Laptop Computer",
    "🐧": "Server",
}

def _device_type(dev: dict) -> str:
    return _EMOJI_TYPE.get(_device_emoji(dev), "Network Device")


# ── CTK risk palette (card colours from the spec) ─────────────────────────

_CTK_RISK = {
    "Critical": {"bg": "#FCEBEB", "fg": "#A32D2D", "dot": "#E24B4A"},
    "High":     {"bg": "#FAEEDA", "fg": "#854F0B", "dot": "#EF9F27"},
    "Medium":   {"bg": "#FAF3E0", "fg": "#856A0B", "dot": "#EF9F27"},
    "Low":      {"bg": "#EAF3DE", "fg": "#3B6D11", "dot": "#639922"},
    "Info":     {"bg": "#F1EFE8", "fg": "#5F5E5A", "dot": "#888780"},
}

_DANGEROUS_PORTS: set[int] = {
    21, 23, 25, 79, 81, 110, 143, 445, 554,
    1883, 2323, 4840, 5683, 5900, 5901, 7547,
    8080, 8081, 8082, 8443, 8883,
}

_PORT_INFO: dict[int, tuple[str, str]] = {
    21:   ("FTP — File Transfer Protocol",
           "Unencrypted file transfer. Use SFTP or SCP instead of FTP."),
    22:   ("SSH — Secure Shell",
           "Encrypted remote access. Generally safe — ensure strong passwords and disable root login."),
    23:   ("Telnet",
           "⚠️ DANGEROUS: Sends all data, including passwords, in plain text. Disable immediately."),
    80:   ("HTTP — Web Server",
           "Unencrypted web traffic. Consider redirecting to HTTPS (port 443)."),
    443:  ("HTTPS — Encrypted Web Server",
           "Encrypted web traffic. Verify TLS certificate is up to date."),
    554:  ("RTSP — Real Time Streaming",
           "Used by IP cameras for live video. Restrict access and require authentication."),
    1883: ("MQTT — IoT Messaging",
           "IoT device communication protocol. Do not expose publicly without authentication."),
    3389: ("RDP — Remote Desktop",
           "⚠️ Frequently attacked. Restrict access, use a VPN, and enable Network Level Authentication."),
    5900: ("VNC — Virtual Network Computing",
           "⚠️ Remote desktop, often unencrypted. Restrict to localhost or tunnel through a VPN."),
    8080: ("HTTP Alternate Port",
           "Web server on a non-standard port. Verify if this service should be externally accessible."),
}


# ── Results window — full tabbed dashboard ────────────────────────────────

class ResultsWindow:

    def __init__(self, parent: tk.Tk, results: list, logs: list[str],
                 rescan_cb: Callable):
        self._results   = sorted(results, key=lambda d: d.get("risk_score", 0), reverse=True)
        self._logs      = logs
        self._rescan_cb = rescan_cb
        self._selected: Optional[dict]   = None
        self._subnet_var: Optional[tk.StringVar] = None
        self._mode_var:   Optional[tk.StringVar] = None
        self._cidr_entry  = None
        self._advice_box  = None
        self._ai_btn      = None
        self._sidebar_rows: list = []   # (frame, dot_lbl, name_lbl, device)

        self._win = ctk.CTkToplevel(parent)
        self._win.title(f"Iden Ltd — {len(results)} device(s) found")
        self._win.geometry("1240x760")
        self._win.minsize(1100, 700)

        self._build_ui()

    # ── Layout ────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_topbar()
        self._build_body()

    def _build_topbar(self) -> None:
        # Outer bar — light warm-white, with a hairline bottom border
        bar = ctk.CTkFrame(self._win, height=52, corner_radius=0,
                           fg_color="#F7F7FA",
                           border_width=0)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        # Bottom separator line
        ctk.CTkFrame(self._win, height=1, corner_radius=0,
                     fg_color="#D1D1D6").pack(fill="x")

        # Brand
        ctk.CTkLabel(bar, text="🛡  Iden Ltd",
                     font=ctk.CTkFont(size=15, weight="bold"),
                     text_color="#1C1C1E").pack(side="left", padx=18)

        ctk.CTkFrame(bar, width=1, fg_color="#D1D1D6").pack(
            side="left", fill="y", pady=10)

        # ── Pill-shaped tab switcher — individual buttons, no dividers ───────
        pill = ctk.CTkFrame(bar, corner_radius=20,
                            fg_color="#EBEBF0", border_width=0)
        pill.pack(side="left", padx=18, pady=10)

        self._tab_btns: dict[str, ctk.CTkButton] = {}
        for tab_name in ("Network Findings", "Device Detail", "Network Map", "Logs", "Advanced"):
            btn = ctk.CTkButton(
                pill,
                text=tab_name,
                command=lambda n=tab_name: self._switch_tab(n),
                width=118, height=30,
                corner_radius=16,
                fg_color="transparent",
                hover_color="#D8D8DE",
                text_color="#1C1C1E",
                font=ctk.CTkFont(size=12, weight="bold"),
                border_width=0,
            )
            btn.pack(side="left", padx=3, pady=3)
            self._tab_btns[tab_name] = btn

        # Highlight the default active tab
        self._tab_btns["Network Findings"].configure(
            fg_color="#185FA5", text_color="white", hover_color="#1565C0"
        )

        # ── Right-side action buttons ──────────────────────────────────────
        # Settings gear — placeholder, opens Advanced tab
        ctk.CTkButton(
            bar, text="⚙", width=34, height=34,
            fg_color="#EBEBF0", hover_color="#D4D4DA",
            text_color="#1C1C1E",
            font=ctk.CTkFont(size=18),
            corner_radius=10,
            border_width=0,
            command=lambda: self._switch_tab("Advanced"),
        ).pack(side="right", padx=(0, 12))

        ctk.CTkButton(
            bar, text="⟳  Rescan", command=self._do_rescan,
            width=110, height=34,
            fg_color="#185FA5", hover_color="#1565C0",
            font=ctk.CTkFont(size=12, weight="bold"),
            corner_radius=10,
        ).pack(side="right", padx=(0, 8))

        # Dark-mode toggle
        self._dark_mode = False
        self._dark_btn = ctk.CTkButton(
            bar, text="🌙", width=34, height=34,
            fg_color="#EBEBF0", hover_color="#D4D4DA",
            text_color="#1C1C1E",
            font=ctk.CTkFont(size=16),
            corner_radius=10,
            command=self._toggle_dark,
        )
        self._dark_btn.pack(side="right", padx=(0, 4))

        # Color-coded risk summary
        self._build_summary_labels(bar)

    def _build_body(self) -> None:
        body = ctk.CTkFrame(self._win, corner_radius=0, fg_color="transparent")
        body.pack(fill="both", expand=True)

        # ── Sidebar ────────────────────────────────────────────────────────
        side = ctk.CTkFrame(body, width=260, corner_radius=0,
                            fg_color="#EBEBF0")
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        self._sidebar = side

        # Thin right border to separate sidebar from content
        ctk.CTkFrame(side, width=1, fg_color="#C6C6C8").pack(side="right", fill="y")

        ctk.CTkLabel(side, text=f"DEVICES ({len(self._results)})",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="#6C6C70", anchor="w").pack(
            fill="x", padx=16, pady=(14, 4))

        self._list_scroll = ctk.CTkScrollableFrame(side, fg_color="transparent")
        self._list_scroll.pack(fill="both", expand=True, padx=0)
        for d in self._results:
            self._add_list_item(d)

        # ── Content area ───────────────────────────────────────────────────
        area = ctk.CTkFrame(body, corner_radius=0, fg_color="transparent")
        area.pack(side="left", fill="both", expand=True)

        # _v_detail uses a tk.Canvas for reliable, CTK-free scrolling
        self._v_findings = ctk.CTkFrame(area, corner_radius=0, fg_color="#F7F7FA")
        self._v_detail   = ctk.CTkFrame(area, corner_radius=0, fg_color="white")
        self._detail_canvas: tk.Canvas | None = None
        self._detail_inner: ctk.CTkFrame | None = None
        self._v_map      = ctk.CTkFrame(area, corner_radius=0, fg_color="transparent")
        self._v_logs     = ctk.CTkFrame(area, corner_radius=0, fg_color="transparent")
        # Plain CTkFrame so tkraise() works; scrollable content built inside
        self._v_advanced = ctk.CTkFrame(area, corner_radius=0, fg_color="transparent")

        self._views = {
            "Network Findings": self._v_findings,
            "Device Detail":    self._v_detail,
            "Network Map":      self._v_map,
            "Logs":             self._v_logs,
            "Advanced":         self._v_advanced,
        }
        for v in self._views.values():
            v.place(relx=0, rely=0, relwidth=1, relheight=1)

        self._build_logs_content()
        self._build_map_content()
        self._build_advanced_content()
        self._build_detail_placeholder()
        self._build_findings_content()
        self._switch_tab("Network Findings")

    def _switch_tab(self, name: str) -> None:
        view = self._views.get(name)
        if view:
            view.tkraise()
        for tab, btn in self._tab_btns.items():
            if tab == name:
                btn.configure(fg_color="#185FA5", text_color="white",
                              hover_color="#1565C0")
            else:
                btn.configure(fg_color="transparent", text_color="#1C1C1E",
                              hover_color="#EDEDF2")

    # ── Device list ───────────────────────────────────────────────────────

    def _add_list_item(self, device: dict) -> None:
        level  = device.get("risk_level", "Info")
        colors = _CTK_RISK.get(level, _CTK_RISK["Info"])

        row = ctk.CTkFrame(self._list_scroll, corner_radius=6,
                           fg_color="transparent", cursor="hand2")
        row.pack(fill="x", pady=2, padx=4)

        # Risk dot — fixed 24px column
        dot = ctk.CTkLabel(row, text="⬤", width=24,
                           text_color=colors["dot"],
                           font=ctk.CTkFont(size=15),
                           anchor="center")
        dot.pack(side="left", padx=(14, 0), pady=10)

        # Device emoji — fixed 30px column so all rows align
        icon = ctk.CTkLabel(row, text=_device_emoji(device), width=30,
                            font=ctk.CTkFont(size=18),
                            anchor="center")
        icon.pack(side="left", padx=(4, 6))

        # Name — allow up to 22 chars before truncating
        raw = (device.get("hostname") or device.get("vendor") or device.get("ip", "?"))
        name_str = raw if len(raw) <= 22 else raw[:20] + "…"
        name_lbl = ctk.CTkLabel(row, text=name_str, anchor="w",
                                font=ctk.CTkFont(size=12),
                                text_color="#1C1C1E")
        name_lbl.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self._sidebar_rows.append((row, dot, name_lbl, device))
        for w in (row, dot, icon, name_lbl):
            w.bind("<Button-1>", lambda e, d=device: self._on_device_click(d))

    def _highlight_row(self, selected_device: Optional[dict]) -> None:
        for row, dot, name_lbl, dev in self._sidebar_rows:
            sel = (selected_device is not None and
                   dev.get("ip") == selected_device.get("ip"))
            row.configure(fg_color=("white", "#3A3A3C") if sel else "transparent")
            name_lbl.configure(
                font=ctk.CTkFont(size=12, weight="bold" if sel else "normal")
            )

    def _on_device_click(self, device: dict) -> None:
        self._selected = device
        self._highlight_row(device)
        self._rebuild_detail(device)
        self._switch_tab("Device Detail")
        # Steal focus from the sidebar widget so no focus-ring flash appears
        self._win.focus_set()

    # ── Device Detail ─────────────────────────────────────────────────────

    def _ensure_detail_canvas(self) -> None:
        """Create the scrollable canvas once inside _v_detail."""
        if self._detail_canvas is not None:
            return
        sc = tk.Canvas(self._v_detail, bg="white", highlightthickness=0)
        sb = tk.Scrollbar(self._v_detail, orient="vertical", command=sc.yview)
        sc.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        sc.pack(fill="both", expand=True)
        sc.bind("<MouseWheel>",
                lambda e: sc.yview_scroll(-(e.delta // 120), "units"))
        self._detail_canvas = sc

    def _build_detail_placeholder(self) -> None:
        self._ensure_detail_canvas()
        self._refresh_detail_inner()
        ctk.CTkLabel(self._detail_inner,
                     text="Select a device from the sidebar to view details.",
                     text_color="gray", font=ctk.CTkFont(size=14)).pack(pady=80, padx=20)

    def _refresh_detail_inner(self) -> None:
        """Destroy old inner frame and create a fresh one in the canvas."""
        sc = self._detail_canvas
        sc.delete("all")
        if self._detail_inner is not None:
            self._detail_inner.destroy()
        inner = ctk.CTkFrame(sc, fg_color="white", corner_radius=0)
        self._detail_inner = inner
        win = sc.create_window(0, 0, anchor="nw", window=inner)
        inner.bind("<Configure>",
                   lambda e: (sc.configure(scrollregion=sc.bbox("all")),
                              sc.itemconfig(win, width=sc.winfo_width())))
        sc.bind("<Configure>",
                lambda e: sc.itemconfig(win, width=e.width))
        # Propagate mousewheel through inner widgets
        inner.bind("<MouseWheel>",
                   lambda e: sc.yview_scroll(-(e.delta // 120), "units"))

    def _rebuild_detail(self, device: dict) -> None:
        self._ensure_detail_canvas()
        self._refresh_detail_inner()
        self._advice_box = None
        self._ai_btn     = None
        self._detail_build(device)
        # Force layout so scroll region is correct immediately
        self._win.update_idletasks()
        self._detail_canvas.configure(
            scrollregion=self._detail_canvas.bbox("all")
        )

    def _detail_card(self, title: str = "", subtitle: str = "") -> ctk.CTkFrame:
        card = ctk.CTkFrame(self._detail_inner, corner_radius=8,
                            border_width=1, border_color="#E5E5EA",
                            fg_color="white")
        card.pack(fill="x", padx=20, pady=5)
        if title:
            hdr = ctk.CTkFrame(card, fg_color="transparent")
            hdr.pack(fill="x", padx=13, pady=(13, 6))
            ctk.CTkLabel(hdr, text=title,
                         font=ctk.CTkFont(size=14, weight="bold"),
                         text_color="#1C1C1E").pack(side="left")
            if subtitle:
                ctk.CTkLabel(hdr, text=subtitle, text_color="#6C6C70",
                             font=ctk.CTkFont(size=12)).pack(side="left", padx=8)
        return card

    def _detail_build(self, device: dict) -> None:
        level  = device.get("risk_level", "Info")
        score  = device.get("risk_score", 0.0)
        colors = _CTK_RISK.get(level, _CTK_RISK["Info"])

        # ── Header row ────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self._detail_inner, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(16, 6))

        icon_bg = ctk.CTkFrame(hdr, width=54, height=54, corner_radius=12,
                               fg_color=colors["bg"])
        icon_bg.pack(side="left", padx=(0, 14))
        icon_bg.pack_propagate(False)
        ctk.CTkLabel(
            icon_bg,
            text=_device_emoji(device),
            font=ctk.CTkFont(size=26),
            width=54, height=54,
            anchor="center",
        ).pack(fill="both", expand=True)

        center = ctk.CTkFrame(hdr, fg_color="transparent")
        center.pack(side="left", fill="both", expand=True)
        name_str = (device.get("hostname") or device.get("vendor") or device.get("ip", "?"))
        ctk.CTkLabel(center, text=name_str, anchor="w",
                     font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w")
        meta = (f"{device.get('ip','?')}  ·  {device.get('mac','')}  ·  "
                f"{device.get('vendor','Unknown')}")
        ctk.CTkLabel(center, text=meta, text_color="gray", anchor="w",
                     font=ctk.CTkFont(size=12)).pack(anchor="w")

        score_frame = ctk.CTkFrame(hdr, fg_color="transparent")
        score_frame.pack(side="right", padx=(14, 0))
        ctk.CTkLabel(score_frame, text=f"{score:.1f}",
                     font=ctk.CTkFont(size=32, weight="bold"),
                     text_color=colors["dot"]).pack()
        badge = ctk.CTkFrame(score_frame, corner_radius=10, fg_color=colors["bg"])
        badge.pack()
        ctk.CTkLabel(badge, text=f"  {level} risk  ",
                     text_color=colors["fg"],
                     font=ctk.CTkFont(size=12, weight="bold")).pack(padx=4, pady=3)

        # ── Card: Risk legend ─────────────────────────────────────────────
        legend_card = self._detail_card("Risk level legend  ℹ️")
        row = ctk.CTkFrame(legend_card, fg_color="transparent")
        row.pack(fill="x", padx=13, pady=(0, 13))
        for lvl_name, lvl_bg, lvl_fg, rng in [
            ("Critical", "#FCEBEB", "#A32D2D", "9.0–10.0"),
            ("High",     "#FAEEDA", "#854F0B", "7.0–8.9"),
            ("Medium",   "#FAF3E0", "#856A0B", "4.0–6.9"),
            ("Low",      "#EAF3DE", "#3B6D11", "0.1–3.9"),
            ("Info",     "#F1EFE8", "#5F5E5A", "No CVEs"),
        ]:
            col = ctk.CTkFrame(row, fg_color="transparent")
            col.pack(side="left", padx=5)
            pill = ctk.CTkFrame(col, corner_radius=10, fg_color=lvl_bg)
            pill.pack()
            ctk.CTkLabel(pill, text=f"  {lvl_name}  ", text_color=lvl_fg,
                         font=ctk.CTkFont(size=12, weight="bold")).pack(padx=2, pady=3)
            ctk.CTkLabel(col, text=rng, text_color="gray",
                         font=ctk.CTkFont(size=11)).pack(pady=(2, 0))

        # ── Card: Open ports ──────────────────────────────────────────────
        open_svcs = [s for s in device.get("services", []) if s.get("state") == "open"]
        ports_card = self._detail_card("Open ports", "Click a web port to open in browser")
        if open_svcs:
            chip_area = ctk.CTkFrame(ports_card, fg_color="transparent")
            chip_area.pack(fill="x", padx=13, pady=(0, 13))
            chip_row = None
            for i, svc in enumerate(open_svcs):
                if i % 8 == 0:
                    chip_row = ctk.CTkFrame(chip_area, fg_color="transparent")
                    chip_row.pack(fill="x", pady=2)
                port   = svc.get("port", 0)
                sname  = svc.get("name", "")
                danger = port in _DANGEROUS_PORTS or sname in ("telnet", "vnc", "rdp")
                bg   = "#FCEBEB" if danger else "#F1EFE8"
                fg   = "#A32D2D" if danger else "#5F5E5A"
                brd  = "#F7C1C1" if danger else "#DDDDDD"
                chip = tk.Button(
                    chip_row,
                    text=f"  {port} {sname}  ",
                    bg=bg, fg=fg,
                    relief="solid", bd=1,
                    highlightbackground=brd, highlightthickness=1,
                    font=("Helvetica", 11), cursor="hand2",
                    activebackground=bg, activeforeground=fg,
                )
                chip.configure(command=lambda s=svc, d=device: self._port_click(s, d))
                chip.pack(side="left", padx=3, pady=2)
        else:
            ctk.CTkLabel(ports_card, text="No open ports detected.",
                         text_color="gray").pack(padx=13, pady=(0, 13))

        # ── Card: Risk factors / CVEs ─────────────────────────────────────
        cves = device.get("cves", [])
        cves_card = self._detail_card()
        title_row = ctk.CTkFrame(cves_card, fg_color="transparent")
        title_row.pack(fill="x", padx=13, pady=(13, 8))
        ctk.CTkLabel(title_row, text="Risk factors",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
        if cves:
            pill_bg, pill_fg, pill_txt = "#FCEBEB", "#A32D2D", f"  {len(cves)} CVE{'s' if len(cves)>1 else ''} found  "
        else:
            pill_bg, pill_fg, pill_txt = "#EAF3DE", "#3B6D11", "  Clean  "
        cpill = ctk.CTkFrame(title_row, corner_radius=8, fg_color=pill_bg)
        cpill.pack(side="left", padx=8)
        ctk.CTkLabel(cpill, text=pill_txt.strip(), text_color=pill_fg,
                     font=ctk.CTkFont(size=11, weight="bold")).pack(padx=4, pady=3)

        if cves:
            for i, cve in enumerate(cves[:10]):
                clvl = _severity_to_level(cve.get("severity", ""))
                cc   = _CTK_RISK.get(clvl, _CTK_RISK["Info"])
                cve_row = ctk.CTkFrame(cves_card, fg_color="transparent")
                cve_row.pack(fill="x", padx=13, pady=3)
                badge2 = ctk.CTkFrame(cve_row, corner_radius=6, fg_color=cc["bg"],
                                      width=82, height=42)
                badge2.pack(side="left", padx=(0, 12))
                badge2.pack_propagate(False)
                ctk.CTkLabel(badge2,
                             text=f"{clvl}\n{cve.get('cvss_score', 0):.1f}",
                             text_color=cc["fg"],
                             font=ctk.CTkFont(size=11, weight="bold"),
                             justify="center").place(relx=0.5, rely=0.5, anchor="center")
                info = ctk.CTkFrame(cve_row, fg_color="transparent")
                info.pack(side="left", fill="both", expand=True)
                ctk.CTkLabel(info, text=cve.get("cve_id", ""), anchor="w",
                             font=ctk.CTkFont(family="Courier New", size=12,
                                             weight="bold")).pack(anchor="w")
                desc = (cve.get("description", "") or "")[:200]
                if len(cve.get("description", "")) > 200: desc += "…"
                ctk.CTkLabel(info, text=desc, anchor="w", wraplength=520,
                             font=ctk.CTkFont(size=12), text_color="gray",
                             justify="left").pack(anchor="w")
                if i < len(cves) - 1:
                    ctk.CTkFrame(cves_card, height=1,
                                 fg_color=("#E5E5EA", "#3A3A3C")).pack(
                        fill="x", padx=13, pady=3)
        else:
            ctk.CTkLabel(cves_card, text="No known CVEs found for detected services.",
                         text_color="gray").pack(padx=13, pady=(0, 13))
        ctk.CTkFrame(cves_card, height=6, fg_color="transparent").pack()

        # ── Card: Scan Summary ────────────────────────────────────────────
        sum_card = self._detail_card("🔍  Scan Summary")
        risk_descs = {
            "Critical": "Critical vulnerabilities detected on this device. Immediate action is required — one or more services expose severe, easily exploitable flaws.",
            "High":     "High-risk issues found. These should be addressed as soon as possible to prevent unauthorised access.",
            "Medium":   "Medium-risk issues detected. Review and apply patches or configuration changes when possible.",
            "Low":      "This device has a low risk profile. A few minor improvements are recommended.",
            "Info":     "No significant vulnerabilities detected. This device currently has a very low risk profile.",
        }
        reasons = device.get("risk_reasons", [])
        summary_text = risk_descs.get(level, "")
        if reasons:
            summary_text += "\n\nKey findings:\n" + "\n".join(f"• {r}" for r in reasons[:5])
        sum_box = ctk.CTkTextbox(
            sum_card, height=120,
            fg_color=("#F2F2F7", "#1C1C1E"),
            border_width=0, font=ctk.CTkFont(size=13),
            wrap="word", state="normal",
        )
        sum_box.pack(fill="x", padx=13, pady=(4, 13))
        sum_box.insert("1.0", summary_text or "No summary available.")
        sum_box.configure(state="disabled")

        # ── Card: AI Remediation ──────────────────────────────────────────
        ai_card = self._detail_card("🤖  AI-Powered Remediation",
                                    "Get a personalised security plan")

        # Auto-sizing text widget with markdown support
        self._advice_box = tk.Text(
            ai_card,
            font=("Segoe UI", 11),
            bg=("#F2F2F7" if not self._dark_mode else "#1C1C1E"),
            fg=("#1C1C1E" if not self._dark_mode else "#AEAEB2"),
            relief="flat",
            bd=0,
            padx=0,
            pady=0,
            wrap="word",
            height=1,
            state="disabled",
        )
        self._advice_box.pack(fill="x", padx=0, pady=(4, 8))

        # Configure markdown-like tags
        self._advice_box.tag_config("bold", font=("Segoe UI", 11, "bold"),
                                    foreground=("#1C1C1E" if not self._dark_mode else "#FFFFFF"))
        self._advice_box.tag_config("header", font=("Segoe UI", 13, "bold"),
                                    foreground=("#185FA5" if not self._dark_mode else "#007AFF"),
                                    spacing1=8, spacing3=4)
        self._advice_box.tag_config("code", font=("Courier New", 10),
                                    background=("#EBEBF0" if not self._dark_mode else "#2C2C2E"))

        self._advice_box.configure(state="normal")
        self._advice_box.insert("1.0",
            "Click 'Get Security Plan' to generate an easy-to-follow remediation guide for this device.")
        self._advice_box.configure(state="disabled")

        self._ai_btn = ctk.CTkButton(
            ai_card, text="Get Security Plan",
            fg_color="#185FA5", hover_color="#1565C0",
            height=36, font=ctk.CTkFont(size=13, weight="bold"),
        )
        self._ai_btn.configure(
            command=lambda: self._fetch_advice(device, self._ai_btn)
        )
        self._ai_btn.pack(fill="x", padx=13, pady=(8, 13))

    # ── Port click ────────────────────────────────────────────────────────

    def _port_click(self, svc: dict, device: dict) -> None:
        port = svc.get("port", 0)
        if port == 80:
            webbrowser.open(f"http://{device.get('ip')}")
            return
        if port == 443:
            webbrowser.open(f"https://{device.get('ip')}")
            return
        name, desc = _PORT_INFO.get(port, (
            f"Port {port} ({svc.get('name','')})",
            "No specific risk information available for this port.",
        ))
        dlg = ctk.CTkToplevel(self._win)
        dlg.title("Port Information")
        dlg.geometry("440x210")
        dlg.resizable(False, False)
        dlg.grab_set()
        ctk.CTkLabel(dlg, text=name, font=ctk.CTkFont(size=14, weight="bold"),
                     wraplength=400).pack(padx=20, pady=(22, 8))
        ctk.CTkLabel(dlg, text=desc, wraplength=400, text_color="gray",
                     font=ctk.CTkFont(size=13)).pack(padx=20)
        ctk.CTkButton(dlg, text="Close", command=dlg.destroy,
                      width=100, fg_color="#185FA5",
                      hover_color="#1565C0").pack(pady=18)

    # ── Network Findings ──────────────────────────────────────────────────

    def _build_findings_content(self) -> None:
        parent = self._v_findings

        # ── Top header row ────────────────────────────────────────────────
        hdr = ctk.CTkFrame(parent, corner_radius=0, fg_color="#FFFFFF",
                           border_width=0)
        hdr.pack(fill="x", padx=0, pady=0)
        ctk.CTkFrame(parent, height=1, corner_radius=0,
                     fg_color="#D1D1D6").pack(fill="x")

        ctk.CTkLabel(hdr, text="Network Findings",
                     font=ctk.CTkFont(size=18, weight="bold"),
                     text_color="#1C1C1E").pack(side="left", padx=20, pady=14)

        # Risk legend chips
        legend_frame = ctk.CTkFrame(hdr, fg_color="transparent")
        legend_frame.pack(side="right", padx=20)
        for level, color in (
            ("Critical", "#FF3B30"), ("High", "#FF9500"),
            ("Medium",   "#FFCC00"), ("Low",  "#34C759"), ("Info", "#8E8E93"),
        ):
            chip = ctk.CTkFrame(legend_frame, corner_radius=10,
                                fg_color=color, width=10, height=10)
            chip.pack(side="left", padx=(6, 2), pady=6)
            chip.pack_propagate(False)
            ctk.CTkLabel(legend_frame, text=level,
                         font=ctk.CTkFont(size=11),
                         text_color="#3C3C43").pack(side="left", padx=(0, 6))

        # ── 3-column body ─────────────────────────────────────────────────
        cols = ctk.CTkFrame(parent, fg_color="transparent")
        cols.pack(fill="both", expand=True, padx=16, pady=14)
        cols.columnconfigure(0, weight=1)
        cols.columnconfigure(1, weight=1)
        cols.columnconfigure(2, weight=2)
        cols.rowconfigure(0, weight=1)

        def _card(master, title: str) -> ctk.CTkFrame:
            outer = ctk.CTkFrame(master, corner_radius=12, fg_color="#FFFFFF",
                                 border_width=1, border_color="#E0E0E5")
            ctk.CTkLabel(outer, text=title,
                         font=ctk.CTkFont(size=13, weight="bold"),
                         text_color="#1C1C1E", anchor="w").pack(
                fill="x", padx=14, pady=(12, 6))
            ctk.CTkFrame(outer, height=1, fg_color="#EBEBF0",
                         corner_radius=0).pack(fill="x", padx=14)
            return outer

        # ── Column 1: Subnets scanned ─────────────────────────────────────
        sub_card = _card(cols, "Subnets Scanned")
        sub_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        sub_body = ctk.CTkScrollableFrame(sub_card, fg_color="transparent")
        sub_body.pack(fill="both", expand=True, padx=8, pady=8)

        seen_subnets: set[str] = set()
        for d in self._results:
            ip = d.get("ip", "")
            parts = ip.split(".")
            if len(parts) == 4:
                seen_subnets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")

        for sn in sorted(seen_subnets):
            prefix = sn.rsplit(".0/24", 1)[0]   # e.g. "192.168.10"
            count = sum(
                1 for d in self._results
                if d.get("ip", "").rsplit(".", 1)[0] == prefix
            )
            row = ctk.CTkFrame(sub_body, fg_color="#F5F5F7", corner_radius=8)
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text="🌐", font=ctk.CTkFont(size=13),
                         width=28).pack(side="left", padx=(10, 4), pady=8)
            ctk.CTkLabel(row, text=sn,
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color="#1C1C1E", anchor="w").pack(
                side="left", fill="x", expand=True)
            ctk.CTkLabel(row, text=f"{count} device{'s' if count != 1 else ''}",
                         font=ctk.CTkFont(size=11),
                         text_color="#6C6C70").pack(side="right", padx=10)

        # ── Column 2: Most vulnerable devices ────────────────────────────
        vuln_card = _card(cols, "Most Vulnerable Devices")
        vuln_card.grid(row=0, column=1, sticky="nsew", padx=(0, 8))
        vuln_body = ctk.CTkScrollableFrame(vuln_card, fg_color="transparent")
        vuln_body.pack(fill="both", expand=True, padx=8, pady=8)

        risk_colors = {
            "Critical": "#FF3B30", "High": "#FF9500",
            "Medium": "#FFCC00",   "Low":  "#34C759", "Info": "#8E8E93",
        }
        top_devices = [
            d for d in self._results
            if d.get("risk_level") in ("Critical", "High", "Medium")
        ][:12]
        if not top_devices:
            top_devices = self._results[:8]

        for d in top_devices:
            level  = d.get("risk_level", "Info")
            color  = risk_colors.get(level, "#8E8E93")
            name   = (d.get("hostname") or d.get("vendor") or d.get("ip", "Unknown"))
            ip     = d.get("ip", "")
            row = ctk.CTkFrame(vuln_body, fg_color="#F5F5F7", corner_radius=8)
            row.pack(fill="x", pady=3)
            dot = ctk.CTkLabel(row, text="⬤", font=ctk.CTkFont(size=12),
                               text_color=color, width=20)
            dot.pack(side="left", padx=(10, 6), pady=8)
            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, pady=6)
            ctk.CTkLabel(info, text=name,
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color="#1C1C1E", anchor="w").pack(fill="x")
            ctk.CTkLabel(info, text=ip,
                         font=ctk.CTkFont(size=10),
                         text_color="#6C6C70", anchor="w").pack(fill="x")
            ctk.CTkLabel(row, text=level,
                         font=ctk.CTkFont(size=10, weight="bold"),
                         text_color=color).pack(side="right", padx=10)

        # ── Column 3: AI Network Rating ───────────────────────────────────
        ai_card = _card(cols, "AI Network Rating")
        ai_card.grid(row=0, column=2, sticky="nsew")

        self._findings_ai_box = tk.Text(
            ai_card,
            font=("Segoe UI", 11), wrap="word",
            bg="#FAFAFA", fg="#1C1C1E",
            relief="flat", bd=0,
            padx=14, pady=10,
            state="disabled",
        )
        self._findings_ai_box.pack(fill="both", expand=True, padx=8, pady=(8, 4))

        self._findings_ai_status = ctk.CTkLabel(
            ai_card, text="⏳ Generating network assessment…",
            font=ctk.CTkFont(size=11), text_color="#6C6C70",
        )
        self._findings_ai_status.pack(pady=(0, 10))

        # Kick off Ollama summary in a background thread
        threading.Thread(target=self._generate_network_summary, daemon=True).start()

    def _append_findings_chunk(self, chunk: str) -> None:
        box = self._findings_ai_box
        box.configure(state="normal")
        box.insert("end", chunk)
        box.see("end")
        box.configure(state="disabled")

    def _generate_network_summary(self) -> None:
        try:
            from iden_coop.llm.advisor import get_network_summary
            get_network_summary(
                results=self._results,
                on_chunk=lambda c: self._win.after(0, self._append_findings_chunk, c),
            )
            self._win.after(0, lambda: self._findings_ai_status.configure(
                text="✓ Assessment complete  |  Powered by Ollama — all data stays on-device"
            ))
        except Exception as exc:
            msg = str(exc)
            self._win.after(0, lambda m=msg: self._findings_ai_status.configure(
                text=f"⚠ {m}"
            ))

    # ── Network Map ───────────────────────────────────────────────────────

    def _build_map_content(self) -> None:
        c = tk.Canvas(self._v_map, bg=D_BG, highlightthickness=0)
        c.pack(fill="both", expand=True)
        c.bind("<Configure>", lambda e: self._draw_topology(c))

    def _draw_topology(self, c: tk.Canvas) -> None:
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if w < 50 or h < 50:
            return

        cx, cy = w // 2, h // 2
        NR = 28   # node radius
        PAD = 80  # edge padding

        # ── Detect actual gateway ────────────────────────────────────────
        gateway = None
        others  = []
        for d in self._results:
            parts = d.get("ip", "").split(".")
            if len(parts) == 4 and parts[3] in ("1", "254"):
                if gateway is None:
                    gateway = d
                    continue
            others.append(d)

        # Fallback: use first device as gateway if none found
        if gateway is None and self._results:
            gateway  = self._results[0]
            others   = self._results[1:]

        # ── Ring layout: inner + outer for large device counts ───────────
        n = len(others)
        if n == 0:
            rings: list[tuple[list, float]] = []
        elif n <= 10:
            rings = [(others, min(w, h) / 2 - PAD)]
        else:
            # Split into two concentric rings
            split    = max(6, n // 2)
            r_inner  = min(w, h) * 0.28
            r_outer  = min(w, h) / 2 - PAD
            rings    = [(others[:split], r_inner), (others[split:], r_outer)]

        # ── Draw spokes first (behind nodes) ────────────────────────────
        for ring_devs, ring_r in rings:
            rn = len(ring_devs)
            for i in range(rn):
                angle = (2 * math.pi * i / rn) - math.pi / 2
                dx = cx + int(ring_r * math.cos(angle))
                dy = cy + int(ring_r * math.sin(angle))
                c.create_line(cx, cy, dx, dy,
                              fill="#cbd5e1", width=1, dash=(5, 4))

        # ── Draw device nodes ────────────────────────────────────────────
        for ring_devs, ring_r in rings:
            rn = len(ring_devs)
            for i, dev in enumerate(ring_devs):
                angle = (2 * math.pi * i / rn) - math.pi / 2
                dx = cx + int(ring_r * math.cos(angle))
                dy = cy + int(ring_r * math.sin(angle))
                self._draw_node(c, dx, dy, dev, NR, gateway_node=False)

        # ── Draw gateway node on top (centre) — smooth circles ───────────
        if gateway:
            GR = 36
            _smooth_circle(c, cx + 2, cy + 3, GR, fill="#C7C7CC", outline="")  # shadow
            _smooth_circle(c, cx, cy, GR, fill="#5E0ACC", outline="")            # outer ring
            _smooth_circle(c, cx, cy, GR - 4, fill="#7C3AED", outline="")       # inner fill
            c.create_text(cx, cy + 1, text="🌐", font=("Segoe UI Emoji", 20))
            gw_host = (gateway.get("hostname") or "Gateway")[:20]
            c.create_text(cx, cy - GR - 14, text=gw_host,
                          font=("Segoe UI", 9, "bold"), fill=D_TEXT)
            c.create_text(cx, cy + GR + 13, text=gateway.get("ip", ""),
                          font=("Consolas", 8), fill="#007AFF")

    def _draw_node(self, c: tk.Canvas, dx: int, dy: int,
                   dev: dict, nr: int, gateway_node: bool) -> None:
        level  = dev.get("risk_level", "Info")
        colour = RISK_COLOURS.get(level, "#007AFF")
        emoji  = _device_emoji(dev)

        # Soft shadow (smooth polygon, offset)
        _smooth_circle(c, dx + 2, dy + 3, nr, fill="#C7C7CC", outline="")
        # Coloured outer ring (risk level)
        _smooth_circle(c, dx, dy, nr, fill=colour, outline="")
        # White inner fill
        _smooth_circle(c, dx, dy, nr - 3, fill="#FFFFFF", outline="")
        # Device emoji centred
        c.create_text(dx, dy + 1, text=emoji,
                      font=("Segoe UI Emoji", max(nr - 6, 16)))

        ip    = dev.get("ip", "?")
        parts = ip.split(".")
        # Show last two octets for readability: e.g.  230.14
        short_ip = ".".join(parts[-2:]) if len(parts) >= 2 else ip

        # Hostname ABOVE node
        host = (dev.get("hostname") or dev.get("vendor") or "Unknown")
        host = host[:16]
        c.create_text(dx, dy - nr - 13, text=host,
                      font=("Segoe UI", 8, "bold"), fill=D_TEXT,
                      anchor="center")
        # IP BELOW node
        c.create_text(dx, dy + nr + 11, text=short_ip,
                      font=("Consolas", 8), fill=D_SUB,
                      anchor="center")

    # ── Logs ──────────────────────────────────────────────────────────────

    def _build_logs_content(self) -> None:
        container = tk.Frame(self._v_logs, bg="white")
        container.pack(fill="both", expand=True)
        log_box = tk.Text(
            container, font=("Consolas", 10),
            bg="white", fg="#1C1C1E",
            relief="flat", bd=0, highlightthickness=0,
            padx=16, pady=12, state="disabled", wrap="word",
        )
        sb = tk.Scrollbar(container, command=log_box.yview, relief="flat")
        sb.pack(side="right", fill="y")
        log_box.configure(yscrollcommand=sb.set)
        log_box.pack(fill="both", expand=True)
        log_box.configure(state="normal")
        for line in self._logs:
            log_box.insert("end", line + "\n")
        log_box.see("end")
        log_box.configure(state="disabled")

    # ── Advanced / Subnet Discovery ───────────────────────────────────────

    # Subnets from the user's common-gateway specification — always shown
    _WELL_KNOWN_SUBNETS: dict[str, str] = {
        "192.168.1.0/24":   "Linksys, ASUS, Netgear, TP-Link",
        "192.168.0.0/24":   "D-Link, Netgear, TP-Link",
        "192.168.1.0/24":   "BT, AT&T (192.168.1.254)",   # same /24 as above — merged
        "10.0.0.0/24":      "Comcast / Xfinity, Cisco",
        "192.168.100.0/24": "Motorola / Arris cable modems",
        "192.168.8.0/24":   "Huawei, GL.iNet",
        "192.168.50.0/24":  "ASUS (newer models)",
        "192.168.254.0/24": "Actiontec (192.168.254.254)",
    }

    def _build_advanced_content(self) -> None:
        # Inner scrollable frame — _v_advanced is a plain CTkFrame so tkraise() works
        scroll = ctk.CTkScrollableFrame(
            self._v_advanced, corner_radius=0, fg_color="transparent"
        )
        scroll.pack(fill="both", expand=True)
        f = scroll  # all content packs into f

        self._subnet_vars: dict[str, tk.BooleanVar] = {}
        self._probe_result_widgets: list = []

        # Title
        ctk.CTkLabel(f, text="Scan Scope",
                     font=ctk.CTkFont(size=18, weight="bold"),
                     text_color="#1C1C1E").pack(anchor="w", padx=24, pady=(20, 2))
        ctk.CTkLabel(
            f,
            text="Subnets are probed in parallel before sweeping — only those whose "
                 "gateway responds will be fully scanned, so ticking extras costs "
                 "at most ~5 s of probing with no wasted ICMP traffic.",
            text_color="#6C6C70", font=ctk.CTkFont(size=13),
            wraplength=640, justify="left",
        ).pack(anchor="w", padx=24, pady=(0, 16))

        # ── Local interface subnets ───────────────────────────────────────
        ctk.CTkLabel(f, text="This device's networks",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#1C1C1E").pack(anchor="w", padx=24, pady=(0, 4))

        local_card = ctk.CTkFrame(f, corner_radius=8, border_width=1,
                                  border_color="#E5E5EA", fg_color="white")
        local_card.pack(fill="x", padx=24, pady=(0, 12))

        local_subnets = self._get_local_subnets_safe()
        if local_subnets:
            for sn in local_subnets:
                var = tk.BooleanVar(value=True)
                self._subnet_vars[sn] = var
                self._add_subnet_row(local_card, sn, var, "this device's network")
        else:
            ctk.CTkLabel(local_card,
                         text="Could not enumerate interfaces — auto-detect will be used.",
                         text_color="#8E8E93", font=ctk.CTkFont(size=12)
                         ).pack(padx=12, pady=8)

        # ── Well-known router subnets (always visible, pre-ticked) ────────
        ctk.CTkLabel(f, text="Common home router subnets",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#1C1C1E").pack(anchor="w", padx=24, pady=(4, 4))

        well_card = ctk.CTkFrame(f, corner_radius=8, border_width=1,
                                 border_color="#E5E5EA", fg_color="white")
        well_card.pack(fill="x", padx=24, pady=(0, 12))

        for sn, label in self._WELL_KNOWN_SUBNETS.items():
            if sn in self._subnet_vars:
                continue  # already shown as local
            var = tk.BooleanVar(value=True)
            self._subnet_vars[sn] = var
            self._add_subnet_row(well_card, sn, var, label)

        # ── Live probe for additional VLANs ───────────────────────────────
        ctk.CTkLabel(f, text="Additional networks (detected by gateway probe)",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#1C1C1E").pack(anchor="w", padx=24, pady=(4, 4))

        probe_row = ctk.CTkFrame(f, fg_color="transparent")
        probe_row.pack(fill="x", padx=24, pady=(0, 4))

        self._probe_btn = ctk.CTkButton(
            probe_row,
            text="🔍  Re-probe Adjacent Networks",
            command=self._start_gateway_probe,
            fg_color="#34C759", hover_color="#2EAD4F",
            text_color="white",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=36, width=270,
        )
        self._probe_btn.pack(side="left")

        self._probe_status = ctk.CTkLabel(
            probe_row, text="",
            text_color="#8E8E93", font=ctk.CTkFont(size=12),
        )
        self._probe_status.pack(side="left", padx=12)

        # Frame populated by probe results
        self._probe_card = ctk.CTkFrame(f, corner_radius=8, border_width=1,
                                        border_color="#E5E5EA", fg_color="white")
        self._probe_card.pack(fill="x", padx=24, pady=(0, 12))
        ctk.CTkLabel(self._probe_card,
                     text="Probing gateways…",
                     text_color="#8E8E93", font=ctk.CTkFont(size=12)
                     ).pack(padx=12, pady=10)

        # Auto-run the probe immediately so results are ready
        self._win.after(200, self._start_gateway_probe)

        # ── Custom subnet ─────────────────────────────────────────────────
        ctk.CTkLabel(f, text="Custom subnet (CIDR notation)",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#1C1C1E").pack(anchor="w", padx=24, pady=(4, 4))

        custom_row = ctk.CTkFrame(f, fg_color="transparent")
        custom_row.pack(fill="x", padx=24, pady=(0, 20))

        self._custom_entry = ctk.CTkEntry(
            custom_row, width=300,
            placeholder_text="e.g.  192.168.10.0/24",
            font=ctk.CTkFont(family="Courier New", size=13),
        )
        self._custom_entry.pack(side="left")
        ctk.CTkLabel(custom_row, text="  leave blank to skip",
                     text_color="#8E8E93",
                     font=ctk.CTkFont(size=12)).pack(side="left")

        # ── Scan button ───────────────────────────────────────────────────
        ctk.CTkFrame(f, height=1, fg_color="#E5E5EA").pack(fill="x", padx=24, pady=(0, 16))

        ctk.CTkButton(
            f, text="⟳  Scan Selected Subnets",
            command=self._do_rescan,
            fg_color="#185FA5", hover_color="#1565C0",
            height=42, font=ctk.CTkFont(size=14, weight="bold"), width=340,
        ).pack(anchor="w", padx=24)

        ctk.CTkLabel(
            f,
            text="If no subnets are ticked above, the scanner falls back to auto-detect.",
            text_color="#8E8E93", font=ctk.CTkFont(size=11),
        ).pack(anchor="w", padx=24, pady=(6, 20))

    def _add_subnet_row(self, parent, subnet: str, var: tk.BooleanVar,
                        label: str) -> None:
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=3)
        ctk.CTkCheckBox(
            row, text=subnet,
            variable=var,
            font=ctk.CTkFont(family="Courier New", size=13),
            text_color="#1C1C1E",
            checkmark_color="white",
            fg_color="#185FA5",
            hover_color="#1565C0",
        ).pack(side="left")
        ctk.CTkLabel(row, text=f"  {label}",
                     text_color="#8E8E93",
                     font=ctk.CTkFont(size=11)).pack(side="left", padx=4)

    @staticmethod
    def _get_local_subnets_safe() -> list[str]:
        try:
            from iden_coop.scanner.discovery import get_local_subnets
            return get_local_subnets()
        except Exception:
            return []

    def _start_gateway_probe(self) -> None:
        self._probe_btn.configure(state="disabled", text="🔍  Probing…")
        self._probe_status.configure(text="Scanning common gateway addresses (this takes ~5 seconds)…")
        local = set(self._subnet_vars.keys())

        def _run():
            try:
                from iden_coop.scanner.discovery import probe_reachable_gateways
                results = probe_reachable_gateways(exclude_subnets=local)
                self._win.after(0, self._show_probe_results, results)
            except Exception as exc:
                self._win.after(0, self._show_probe_results, [], str(exc))

        threading.Thread(target=_run, daemon=True).start()

    def _show_probe_results(self, results: list, error: str = "") -> None:
        self._probe_btn.configure(state="normal", text="🔍  Discover Adjacent Networks")
        for w in self._probe_card.winfo_children():
            w.destroy()

        if error:
            ctk.CTkLabel(self._probe_card,
                         text=f"Probe error: {error}",
                         text_color="#FF3B30",
                         font=ctk.CTkFont(size=12)).pack(padx=12, pady=8)
            self._probe_status.configure(text="Probe failed — see error above.")
            return

        if not results:
            ctk.CTkLabel(self._probe_card,
                         text="No additional networks found. "
                              "All common gateway addresses either didn't respond "
                              "or are already covered above.",
                         text_color="#8E8E93",
                         font=ctk.CTkFont(size=12),
                         wraplength=580, justify="left").pack(padx=12, pady=10)
            self._probe_status.configure(
                text=f"Probe complete — no adjacent networks detected.")
            return

        for gw_ip, subnet in results:
            if subnet in self._subnet_vars:
                continue  # already listed as local
            var = tk.BooleanVar(value=True)
            self._subnet_vars[subnet] = var
            row = ctk.CTkFrame(self._probe_card, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=4)
            ctk.CTkCheckBox(
                row, text=subnet,
                variable=var,
                font=ctk.CTkFont(family="Courier New", size=13),
                text_color="#1C1C1E",
                checkmark_color="white",
                fg_color="#185FA5",
                hover_color="#1565C0",
            ).pack(side="left")
            ctk.CTkLabel(row,
                         text=f"  gateway {gw_ip} responded",
                         text_color="#8E8E93",
                         font=ctk.CTkFont(size=11)).pack(side="left", padx=8)

        self._probe_status.configure(
            text=f"Found {len(results)} adjacent network(s). "
                 "Tick the ones you want to include in the next scan.")

    # ── Rescan ────────────────────────────────────────────────────────────

    def _do_rescan(self) -> None:
        selected: list[str] = []

        # Collect ticked subnets from the Advanced panel (if it was visited)
        if hasattr(self, "_subnet_vars"):
            selected = [sn for sn, var in self._subnet_vars.items() if var.get()]

        # Append any custom entry
        if hasattr(self, "_custom_entry") and self._custom_entry:
            custom = self._custom_entry.get().strip()
            if custom and "/" in custom and custom not in selected:
                selected.append(custom)

        # Build subnet argument: comma-separated list, or None for auto-detect
        subnet_arg = ",".join(selected) if selected else None

        self._win.destroy()
        self._rescan_cb(subnet_arg)

    # ── Helpers ───────────────────────────────────────────────────────────

    _LEVEL_COLORS = {
        "Critical": "#E24B4A",
        "High":     "#FF9500",
        "Medium":   "#FFCC00",
        "Low":      "#34C759",
        "Info":     "#007AFF",
    }

    def _build_summary_labels(self, bar) -> None:
        """Build per-risk-level colored labels in the topbar, right-aligned."""
        from collections import Counter
        counts = Counter(d.get("risk_level", "Info") for d in self._results)

        frame = ctk.CTkFrame(bar, fg_color="transparent")
        frame.pack(side="right", padx=10)

        first = True
        for level in ("Critical", "High", "Medium", "Low", "Info"):
            n = counts.get(level, 0)
            if not n:
                continue
            if not first:
                ctk.CTkLabel(frame, text=" | ", text_color="#C6C6C8",
                             font=ctk.CTkFont(size=12)).pack(side="left")
            ctk.CTkLabel(
                frame,
                text=f"{n} {level}",
                text_color=self._LEVEL_COLORS[level],
                font=ctk.CTkFont(size=12, weight="bold"),
            ).pack(side="left")
            first = False

    def _summary_text(self) -> str:
        from collections import Counter
        counts = Counter(d.get("risk_level", "Info") for d in self._results)
        parts = [f"{counts[l]} {l}" for l in ("Critical", "High", "Medium", "Low", "Info")
                 if counts[l]]
        return "  |  ".join(parts) or f"{len(self._results)} device(s)"

    def _toggle_dark(self) -> None:
        self._dark_mode = not self._dark_mode
        mode = "dark" if self._dark_mode else "light"
        ctk.set_appearance_mode(mode)
        self._dark_btn.configure(text="☀️" if self._dark_mode else "🌙")
        # Update tk-native canvas backgrounds
        canvas_bg = "#1C1C1E" if self._dark_mode else "white"
        log_bg    = "#1C1C1E" if self._dark_mode else "white"
        log_fg    = "#AEAEB2" if self._dark_mode else "#1C1C1E"
        if self._detail_canvas:
            self._detail_canvas.configure(bg=canvas_bg)
            if self._detail_inner:
                self._detail_inner.configure(fg_color="#1C1C1E" if self._dark_mode else "white")
        # Update topo map canvas
        topo_c = getattr(self, "_topo_canvas", None)
        if topo_c:
            topo_c.configure(bg="#1C1C1E" if self._dark_mode else D_BG)
        # Update logs
        for v in self._v_logs.winfo_children():
            for child in v.winfo_children():
                if isinstance(child, tk.Text):
                    child.configure(bg=log_bg, fg=log_fg)

    def _fetch_advice(self, device: dict, btn) -> None:
        btn.configure(state="disabled", text="Generating…")
        if self._advice_box:
            self._advice_box.configure(state="normal")
            self._advice_box.delete("1.0", "end")
            self._advice_box.configure(state="disabled")

        def _run():
            try:
                from iden_coop.llm.advisor import get_advice
                get_advice(
                    device_type=device.get("vendor") or device.get("os_guess") or "IoT Device",
                    services=device.get("services", []),
                    cves=device.get("cves", []),
                    on_chunk=lambda chunk: self._win.after(0, self._append_advice, chunk),
                )
            except Exception as exc:
                self._win.after(0, self._append_advice, f"Error: {exc}")
            finally:
                self._win.after(0, lambda: btn.configure(state="normal", text="Get Security Plan"))

        threading.Thread(target=_run, daemon=True).start()

    def _append_advice(self, chunk: str) -> None:
        if not self._advice_box:
            return
        self._advice_box.configure(state="normal")
        self._advice_box.insert("end", chunk)

        # Parse and apply markdown tags on-the-fly
        content = self._advice_box.get("1.0", "end-1c")
        self._advice_box.tag_remove("bold", "1.0", "end")
        self._advice_box.tag_remove("header", "1.0", "end")

        # Bold: **text** → apply bold tag
        import re
        for m in re.finditer(r"\*\*(.+?)\*\*", content):
            start = f"1.0+{m.start()}c"
            end = f"1.0+{m.end()}c"
            self._advice_box.tag_add("bold", start, end)

        # Headers: lines starting with ## or 1. or * (list items)
        for i, line in enumerate(content.split("\n"), 1):
            if line.startswith("## ") or line.startswith("# "):
                self._advice_box.tag_add("header", f"{i}.0", f"{i}.end")
            elif line.startswith(("1. ", "2. ", "3. ", "* ", "- ")):
                # Indent list items
                pass

        self._advice_box.see("end")

        # Auto-resize: measure content height and adjust widget height
        self._advice_box.update_idletasks()
        linect = int(self._advice_box.index("end-1c").split(".")[0])
        new_height = max(3, min(linect + 1, 25))  # cap at 25 lines
        self._advice_box.configure(height=new_height)

        self._advice_box.configure(state="disabled")


# ── Legal consent gate ────────────────────────────────────────────────────

class LegalWarningDialog:
    """
    Modal consent dialog shown before any scanning functionality is accessible.
    Blocks the main window until the user explicitly accepts or exits.
    """

    _TITLE = "Authorised Use Only"

    _BODY = (
        "This tool performs active network reconnaissance using Nmap and raw "
        "packet techniques. It must only be used on networks you own or have "
        "explicit written authorisation to test.\n\n"
        "Unauthorised scanning is a criminal offence in most jurisdictions:\n\n"
        "  •  United Kingdom — Computer Misuse Act 1990 (CMA)\n"
        "     Sections 1–3 criminalise unauthorised access and modification.\n\n"
        "  •  United States — Computer Fraud and Abuse Act (CFAA)\n"
        "     18 U.S.C. § 1030 — penalties up to 10 years imprisonment.\n\n"
        "  •  European Union — Directive 2013/40/EU\n"
        "     Mandates criminal sanctions for illegal system access across all\n"
        "     member states.\n\n"
        "  •  Australia — Criminal Code Act 1995, Part 10.7\n"
        "     Unauthorised access carries up to 10 years imprisonment.\n\n"
        "By clicking  \"I Understand & Accept\"  you confirm that:\n\n"
        "  1.  You own, or have written permission to scan, the target network.\n"
        "  2.  You accept full legal responsibility for how this tool is used.\n"
        "  3.  You will not use this tool on public, corporate, or government\n"
        "      networks without explicit authorisation."
    )

    def __init__(self, parent: tk.Tk,
                 on_accept: Callable, on_decline: Callable) -> None:
        self._on_accept  = on_accept
        self._on_decline = on_decline

        self._win = tk.Toplevel(parent)
        self._win.title(self._TITLE)
        self._win.resizable(False, False)
        self._win.configure(bg="#F2F2F7")
        self._win.grab_set()
        self._win.protocol("WM_DELETE_WINDOW", self._decline)

        self._build_ui()
        self._centre(parent, 620, 760)

    def _centre(self, parent: tk.Tk, w: int, h: int) -> None:
        self._win.update_idletasks()
        sw = parent.winfo_screenwidth()
        sh = parent.winfo_screenheight()
        self._win.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

    def _build_ui(self) -> None:
        # ── Icon + title ──────────────────────────────────────────────────
        top = tk.Frame(self._win, bg="#F2F2F7")
        top.pack(fill="x", padx=32, pady=(28, 0))

        tk.Label(top, text="⚠️", font=("Segoe UI Emoji", 40),
                 bg="#F2F2F7").pack()
        tk.Label(top, text=self._TITLE,
                 font=("Segoe UI", 19, "bold"), fg="#1C1C1E",
                 bg="#F2F2F7").pack(pady=(6, 2))
        tk.Label(top,
                 text="Read carefully before proceeding",
                 font=("Segoe UI", 11), fg="#6C6C70",
                 bg="#F2F2F7").pack()

        # ── White card with legal text ────────────────────────────────────
        card_cv = tk.Canvas(self._win, bg="#F2F2F7", highlightthickness=0)
        card_cv.pack(fill="x", padx=28, pady=16)

        card_inner = tk.Frame(card_cv, bg="#FFFFFF")
        card_win   = card_cv.create_window(14, 14, anchor="nw", window=card_inner)

        tk.Label(
            card_inner,
            text=self._BODY,
            font=("Segoe UI", 9),
            fg="#3C3C43",
            bg="#FFFFFF",
            justify="left",
            wraplength=478,
            padx=16, pady=14,
        ).pack()

        def _redraw_card(e=None):
            cw = card_cv.winfo_width()
            ih = card_inner.winfo_reqheight()
            if cw < 20 or ih < 4:
                return
            h  = ih + 28
            card_cv.config(height=h)
            card_cv.delete("rr")
            r  = 12
            pts = [r,0, cw-r,0, cw,0, cw,r, cw,h-r, cw,h,
                   cw-r,h, r,h, 0,h, 0,h-r, 0,r, 0,0]
            card_cv.create_polygon(pts, smooth=True,
                                   fill="#FFFFFF", outline="#C6C6C8",
                                   width=1, tags="rr")
            card_cv.itemconfig(card_win, width=cw - 28)

        card_cv.bind("<Configure>", lambda e: card_cv.after(5, _redraw_card))
        card_inner.bind("<Configure>", lambda e: card_cv.after(5, _redraw_card))

        # ── Buttons ───────────────────────────────────────────────────────
        btn_row = tk.Frame(self._win, bg="#F2F2F7")
        btn_row.pack(fill="x", padx=28, pady=(0, 28))

        # Grid layout guarantees both buttons get exactly 50% of the row width
        btn_row.columnconfigure(0, weight=1)
        btn_row.columnconfigure(1, weight=1)

        # Exit (gray pill)
        exit_cv = tk.Canvas(btn_row, height=44, bg="#F2F2F7",
                            highlightthickness=0, cursor="hand2")
        exit_cv.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        exit_cv.bind("<Configure>",       lambda e: self._draw_pill(exit_cv, "#E5E5EA", "#3C3C43", "Exit"))
        exit_cv.bind("<ButtonPress-1>",   lambda e: self._draw_pill(exit_cv, "#D1D1D6", "#3C3C43", "Exit"))
        exit_cv.bind("<ButtonRelease-1>", lambda e: (self._draw_pill(exit_cv, "#E5E5EA", "#3C3C43", "Exit"), self._decline()))

        # Accept (Apple blue pill)
        accept_cv = tk.Canvas(btn_row, height=44, bg="#F2F2F7",
                              highlightthickness=0, cursor="hand2")
        accept_cv.grid(row=0, column=1, sticky="ew", padx=(6, 0))
        accept_cv.bind("<Configure>",       lambda e: self._draw_pill(accept_cv, "#007AFF", "#FFFFFF", "I Understand & Accept"))
        accept_cv.bind("<ButtonPress-1>",   lambda e: self._draw_pill(accept_cv, "#0051D5", "#FFFFFF", "I Understand & Accept"))
        accept_cv.bind("<ButtonRelease-1>", lambda e: (self._draw_pill(accept_cv, "#007AFF", "#FFFFFF", "I Understand & Accept"), self._accept()))

    @staticmethod
    def _draw_pill(cv: tk.Canvas, fill: str, fg: str, label: str) -> None:
        cv.delete("all")
        w, h = cv.winfo_width(), cv.winfo_height()
        if w < 10 or h < 10:
            return
        r   = h // 2
        pts = [r,0, w-r,0, w,0, w,r, w,h-r, w,h, w-r,h, r,h, 0,h, 0,h-r, 0,r, 0,0]
        cv.create_polygon(pts, smooth=True, fill=fill, outline="")
        cv.create_text(w // 2, h // 2 + 1, text=label, fill=fg,
                       font=("Segoe UI", 10, "bold"))

    def _accept(self) -> None:
        self._win.grab_release()
        self._win.destroy()
        self._on_accept()

    def _decline(self) -> None:
        self._win.grab_release()
        self._win.destroy()
        self._on_decline()


# ── Entry point ───────────────────────────────────────────────────────────

def main() -> None:
    # Initialise the SQLite database on every launch — idempotent if it already exists.
    try:
        from iden_coop.database.db import init_db
        init_db()
    except Exception:
        pass  # non-fatal: app runs fine without persistence

    root = tk.Tk()
    root.withdraw()   # hide until consent is given

    def _accepted() -> None:
        root.deiconify()
        IoTScannerGUI(root)

    def _declined() -> None:
        root.destroy()

    LegalWarningDialog(root, on_accept=_accepted, on_decline=_declined)
    root.mainloop()


if __name__ == "__main__":
    main()
