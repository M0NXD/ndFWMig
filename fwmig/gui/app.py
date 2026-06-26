"""
Main GUI application — ndFWMig.

Layout:
  ┌────────────────────────────────────────────────────────┐
  │  Title bar                                             │
  ├──────────────────────┬─────────────────────────────────┤
  │  SOURCE panel        │  OUTPUT panel                   │
  │  Platform selector   │  Platform selector              │
  │  Version selector    │  Version selector               │
  │  [Browse] [Parse]    │  [Generate] [Copy] [Save]       │
  ├──────────────────────┴─────────────────────────────────┤
  │  Notebook: Source | Statistics | Warnings | Output     │
  ├────────────────────────────────────────────────────────┤
  │  Status bar                                            │
  └────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import os
import re
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from ..models.common import Platform, PLATFORM_VERSIONS, VERSION_NOTES, FirewallConfig
from ..parsers import get_parser
from ..generators import get_generator
from ..statistics import ConfigAnalyzer, ConfigStats
from ..transform import (
    collect_interface_names, suggest_target_names, apply_interface_mapping,
)

# ---------------------------------------------------------------------------
# Colour palette (dark theme)
# ---------------------------------------------------------------------------
BG       = "#1e1e2e"
BG2      = "#2a2a3e"
BG3      = "#313147"
FG       = "#cdd6f4"
FG_DIM   = "#a6adc8"
ACCENT   = "#89b4fa"
GREEN    = "#a6e3a1"
YELLOW   = "#f9e2af"
RED      = "#f38ba8"
MONO     = ("Consolas", 10) if sys.platform == "win32" else ("Menlo", 10)
BOLD     = ("Segoe UI", 10, "bold") if sys.platform == "win32" else ("Helvetica", 10, "bold")
SANS     = ("Segoe UI", 10) if sys.platform == "win32" else ("Helvetica", 10)

DISCLAIMER = """\
Disclaimer of warranties and liability

This software is provided "as is" and "as available", without warranty of any \
kind, whether express, implied or statutory, including but not limited to the \
implied warranties of satisfactory quality, fitness for a particular purpose, \
accuracy and non-infringement. The author makes no representation or warranty \
that the software is error-free or secure, that its operation will be \
uninterrupted, or that any defect will be corrected.

Authorised use only. This software is intended solely for use on networks, \
systems and devices that you own or are expressly authorised to audit. You are \
solely responsible for ensuring that your use is lawful and properly \
authorised, and for any consequence of unauthorised or improper use.

To the fullest extent permitted by law, and whether in contract, tort \
(including negligence), breach of statutory duty or otherwise, the author shall \
not be liable for any loss or damage of any kind arising out of or in \
connection with the use of, or inability to use, this software, including but \
not limited to any direct, indirect, incidental, special or consequential \
loss, loss of profits, revenue, business, goodwill, data or anticipated \
savings, or business interruption, even if advised of the possibility of such \
loss. You use this software entirely at your own risk and are solely \
responsible for maintaining adequate backups and for any outcome that results \
from such use.

Indemnity. To the fullest extent permitted by law, you agree to indemnify, \
defend and hold harmless the author against any and all claims, demands, \
proceedings, losses, liabilities, damages, costs and expenses (including \
reasonable legal fees) arising out of or in connection with your use of the \
software, your breach of this notice, or any unauthorised or unlawful use of \
the software by you.

Nothing in this notice excludes or limits the author's liability for death or \
personal injury caused by negligence, for fraud or fraudulent \
misrepresentation, or for any other liability that cannot lawfully be excluded \
or limited under applicable law.
"""


class FWMigApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("ndFWMig")
        self.geometry("1280x800")
        self.minsize(960, 640)
        self.configure(bg=BG)

        self._cfg: Optional[FirewallConfig] = None
        self._stats: Optional[ConfigStats] = None
        self._source_file: Optional[str] = None
        self._gen_warnings: list = []
        # User overrides for interface-name refactoring: {source_key: target_name}
        self._iface_map: dict = {}

        # Pre-init StringVars that may be referenced before their widgets are built
        self._ver_note_var = tk.StringVar(value="")
        self._info_var = tk.StringVar(value="No config loaded.")
        self._status_var = tk.StringVar(value="Ready — load a firewall config to begin.")

        self._setup_style()
        self._build_ui()

    # ------------------------------------------------------------------ style
    def _setup_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".",
                         background=BG, foreground=FG,
                         fieldbackground=BG2, insertcolor=FG,
                         font=SANS, relief="flat")
        style.configure("TFrame",   background=BG)
        style.configure("TLabel",   background=BG, foreground=FG)
        style.configure("TButton",  background=BG3, foreground=FG, padding=6,
                         relief="flat", borderwidth=0)
        style.map("TButton",
                   background=[("active", ACCENT), ("pressed", ACCENT)],
                   foreground=[("active", BG)])

        style.configure("Accent.TButton", background=ACCENT, foreground=BG, padding=6)
        style.map("Accent.TButton",
                   background=[("active", "#74c0fc"), ("pressed", "#74c0fc")])

        style.configure("TCombobox",
                         fieldbackground=BG2, background=BG2,
                         foreground=FG, selectbackground=ACCENT,
                         arrowcolor=FG)
        style.map("TCombobox",
                   fieldbackground=[("readonly", BG2)],
                   selectbackground=[("readonly", BG2)],
                   selectforeground=[("readonly", FG)])

        style.configure("TNotebook",       background=BG,  tabmargins=0)
        style.configure("TNotebook.Tab",   background=BG3, foreground=FG_DIM,
                         padding=(12, 4), font=SANS)
        style.map("TNotebook.Tab",
                   background=[("selected", BG2)],
                   foreground=[("selected", FG)])

        style.configure("TPanedwindow",  background=BG)
        style.configure("TSeparator",    background=BG3)

        style.configure("Header.TLabel", background=BG2, foreground=ACCENT,
                         font=BOLD, padding=(8, 6))
        style.configure("Dim.TLabel",    background=BG, foreground=FG_DIM)
        style.configure("Warn.TLabel",   background=BG, foreground=YELLOW)
        style.configure("Error.TLabel",  background=BG, foreground=RED)
        style.configure("OK.TLabel",     background=BG, foreground=GREEN)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        # Title bar
        title_bar = tk.Frame(self, bg=BG2, height=50)
        title_bar.pack(fill=tk.X, side=tk.TOP)
        title_bar.pack_propagate(False)
        tk.Label(title_bar, text="  ndFWMig",
                 bg=BG2, fg=ACCENT, font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT, padx=8)
        ttk.Button(title_bar, text="About", command=self._show_about).pack(
            side=tk.RIGHT, padx=8, pady=8)
        tk.Label(title_bar, text="v0.22  |  ASA · FWSM · FTD · PAN-OS · FortiOS",
                 bg=BG2, fg=FG_DIM, font=SANS).pack(side=tk.RIGHT, padx=12)

        # Control panel (top)
        ctrl = tk.Frame(self, bg=BG2, pady=8)
        ctrl.pack(fill=tk.X, side=tk.TOP)
        self._build_control_panel(ctrl)

        # Notebook (main body)
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 2))
        self._build_source_tab()
        self._build_stats_tab()
        self._build_warnings_tab()
        self._build_output_tab()

        # Status bar
        status_bar = tk.Frame(self, bg=BG3, height=24)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        status_bar.pack_propagate(False)
        tk.Label(status_bar, textvariable=self._status_var,
                 bg=BG3, fg=FG_DIM, font=("Segoe UI", 9),
                 anchor="w").pack(side=tk.LEFT, padx=10)

    # ------------------------------------------------------------------ control panel
    def _build_control_panel(self, parent: tk.Frame) -> None:
        # ---- SOURCE ----
        src_frame = tk.LabelFrame(parent, text=" SOURCE ",
                                   bg=BG2, fg=ACCENT, font=BOLD,
                                   bd=1, relief="solid", padx=6, pady=4)
        src_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(8, 4))

        tk.Label(src_frame, text="Platform:", bg=BG2, fg=FG_DIM, font=SANS).grid(
            row=0, column=0, sticky="e", padx=4)
        self._src_platform = tk.StringVar(value=Platform.CISCO_ASA.value)
        src_plat_cb = ttk.Combobox(src_frame, textvariable=self._src_platform,
                                    values=[p.value for p in Platform],
                                    state="readonly", width=18)
        src_plat_cb.grid(row=0, column=1, padx=4, pady=2)
        src_plat_cb.bind("<<ComboboxSelected>>", self._on_src_platform_change)

        tk.Label(src_frame, text="Version:", bg=BG2, fg=FG_DIM, font=SANS).grid(
            row=1, column=0, sticky="e", padx=4)
        self._src_version = tk.StringVar()
        self._src_ver_cb = ttk.Combobox(src_frame, textvariable=self._src_version,
                                         state="readonly", width=18)
        self._src_ver_cb.grid(row=1, column=1, padx=4, pady=2)
        self._src_ver_cb.bind("<<ComboboxSelected>>", self._on_src_version_change)
        self._update_src_versions()

        btn_frame = tk.Frame(src_frame, bg=BG2)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=4)
        ttk.Button(btn_frame, text="Browse...", command=self._browse_file).pack(
            side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Auto-detect", command=self._auto_detect).pack(
            side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Parse", style="Accent.TButton",
                   command=self._parse).pack(side=tk.LEFT, padx=2)

        # ---- separator ----
        tk.Frame(parent, bg=BG3, width=2).pack(side=tk.LEFT, fill=tk.Y, padx=8)

        # ---- TARGET ----
        tgt_frame = tk.LabelFrame(parent, text=" TARGET ",
                                   bg=BG2, fg=GREEN, font=BOLD,
                                   bd=1, relief="solid", padx=6, pady=4)
        tgt_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(4, 8))

        tk.Label(tgt_frame, text="Platform:", bg=BG2, fg=FG_DIM, font=SANS).grid(
            row=0, column=0, sticky="e", padx=4)
        self._tgt_platform = tk.StringVar(value=Platform.PALO_ALTO.value)
        tgt_plat_cb = ttk.Combobox(tgt_frame, textvariable=self._tgt_platform,
                                    values=[p.value for p in Platform],
                                    state="readonly", width=18)
        tgt_plat_cb.grid(row=0, column=1, padx=4, pady=2)
        tgt_plat_cb.bind("<<ComboboxSelected>>", self._on_tgt_platform_change)

        tk.Label(tgt_frame, text="Version:", bg=BG2, fg=FG_DIM, font=SANS).grid(
            row=1, column=0, sticky="e", padx=4)
        self._tgt_version = tk.StringVar()
        self._tgt_ver_cb = ttk.Combobox(tgt_frame, textvariable=self._tgt_version,
                                         state="readonly", width=18)
        self._tgt_ver_cb.grid(row=1, column=1, padx=4, pady=2)
        self._tgt_ver_cb.bind("<<ComboboxSelected>>", self._on_tgt_version_change)
        self._update_tgt_versions()

        btn_frame2 = tk.Frame(tgt_frame, bg=BG2)
        btn_frame2.grid(row=2, column=0, columnspan=2, pady=4)
        ttk.Button(btn_frame2, text="Generate", style="Accent.TButton",
                   command=self._generate).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame2, text="Map Interfaces...",
                   command=self._open_iface_map).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame2, text="Copy", command=self._copy_output).pack(
            side=tk.LEFT, padx=2)
        ttk.Button(btn_frame2, text="Save...", command=self._save_output).pack(
            side=tk.LEFT, padx=2)

        # ---- info panel (right side) ----
        info_frame = tk.Frame(parent, bg=BG2, padx=12)
        info_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=8)
        tk.Label(info_frame, textvariable=self._info_var,
                 bg=BG2, fg=FG_DIM, font=SANS,
                 anchor="nw", justify="left", wraplength=400).pack(anchor="w")

        # Version notes (shown when a version with known changes is selected)
        self._ver_note_lbl = tk.Label(
            info_frame, textvariable=self._ver_note_var,
            bg=BG2, fg=YELLOW, font=("Segoe UI", 8),
            anchor="nw", justify="left", wraplength=500,
        )
        self._ver_note_lbl.pack(anchor="w", pady=(4, 0))

    # ------------------------------------------------------------------ tabs
    def _build_source_tab(self) -> None:
        frame = tk.Frame(self._nb, bg=BG)
        self._nb.add(frame, text="  Source Config  ")

        self._src_text = self._make_text_widget(frame)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._src_text.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self._src_text.xview)
        self._src_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._src_text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

    def _build_stats_tab(self) -> None:
        frame = tk.Frame(self._nb, bg=BG)
        self._nb.add(frame, text="  Statistics  ")

        # Top row: summary cards
        self._cards_frame = tk.Frame(frame, bg=BG)
        self._cards_frame.pack(fill=tk.X, padx=8, pady=8)

        # Bottom: detail table
        self._stats_text = self._make_text_widget(frame)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._stats_text.yview)
        self._stats_text.configure(yscrollcommand=vsb.set)
        self._stats_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0), pady=(0, 8))
        vsb.pack(side=tk.RIGHT, fill=tk.Y, pady=(0, 8), padx=(0, 4))
        self._stats_text.configure(state="disabled")

    def _build_warnings_tab(self) -> None:
        frame = tk.Frame(self._nb, bg=BG)
        self._nb.add(frame, text="  Warnings & Risks  ")

        self._warn_text = self._make_text_widget(frame)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._warn_text.yview)
        self._warn_text.configure(yscrollcommand=vsb.set)
        self._warn_text.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        vsb.grid(row=0, column=1, sticky="ns", pady=8, padx=(0, 4))
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self._warn_text.configure(state="disabled")

        # Tags for colour
        self._warn_text.tag_configure("warn",  foreground=YELLOW)
        self._warn_text.tag_configure("error", foreground=RED)
        self._warn_text.tag_configure("risk",  foreground=YELLOW)
        self._warn_text.tag_configure("ok",    foreground=GREEN)
        self._warn_text.tag_configure("head",  foreground=ACCENT, font=BOLD)

    def _build_output_tab(self) -> None:
        frame = tk.Frame(self._nb, bg=BG)
        self._nb.add(frame, text="  Output Config  ")

        self._out_text = self._make_text_widget(frame)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._out_text.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self._out_text.xview)
        self._out_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._out_text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

    # ------------------------------------------------------------------ widget factory
    def _make_text_widget(self, parent: tk.Widget) -> tk.Text:
        t = tk.Text(parent, bg=BG, fg=FG,
                    insertbackground=FG, selectbackground=ACCENT,
                    font=MONO, wrap="none", relief="flat",
                    borderwidth=0, padx=8, pady=8,
                    undo=True)
        # Tag colours for syntax highlighting
        t.tag_configure("hl_keyword",  foreground="#89b4fa")   # blue  — keywords
        t.tag_configure("hl_action",   foreground="#a6e3a1")   # green — permit/accept/allow
        t.tag_configure("hl_deny",     foreground="#f38ba8")   # red   — deny/drop/reject
        t.tag_configure("hl_ip",       foreground="#f9e2af")   # yellow — IP addresses
        t.tag_configure("hl_comment",  foreground="#6c7086", font=(MONO[0], MONO[1], "italic"))
        t.tag_configure("hl_string",   foreground="#cba6f7")   # purple — quoted strings
        return t

    # Compiled once at class level — reused across every highlight pass.
    _HL_PATTERNS = [
        # Comment: whole line starting with # or ! (or a Cisco 'remark' line)
        ("hl_comment", re.compile(r"^[ \t]*(?:#|!|remark\b).*$")),
        ("hl_string",  re.compile(r'"[^"]*"')),
        ("hl_action",  re.compile(r"\b(?:permit|allow|accept)\b")),
        ("hl_deny",    re.compile(r"\b(?:deny|drop|reject|block)\b")),
        ("hl_keyword", re.compile(
            r"\b(?:access-list|access-group|nat|object|object-group|interface|route|static|dynamic"
            r"|config|edit|set|end|next|entry|rulebase|security|address|service"
            r"|source|destination|protocol|action|log|enabled|disabled)\b"
        )),
        ("hl_ip",      re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")),
    ]
    # Skip highlighting beyond this many lines to keep the UI responsive.
    _HL_MAX_LINES = 6000

    def _apply_highlight(self, widget: tk.Text) -> None:
        """Apply syntax highlighting line-by-line using O(1) line.col indices."""
        for tag, _ in self._HL_PATTERNS:
            widget.tag_remove(tag, "1.0", tk.END)

        content = widget.get("1.0", "end-1c")
        if not content:
            return
        lines = content.split("\n")
        if len(lines) > self._HL_MAX_LINES:
            lines = lines[: self._HL_MAX_LINES]

        for lineno, text in enumerate(lines, start=1):
            if not text:
                continue
            # If the whole line is a comment, tag it and skip the other patterns.
            cm = self._HL_PATTERNS[0][1].match(text)
            if cm:
                widget.tag_add("hl_comment", f"{lineno}.0", f"{lineno}.end")
                continue
            for tag, pat in self._HL_PATTERNS[1:]:
                for m in pat.finditer(text):
                    widget.tag_add(tag, f"{lineno}.{m.start()}", f"{lineno}.{m.end()}")

    # ------------------------------------------------------------------ event handlers
    def _on_src_platform_change(self, _event=None) -> None:
        self._update_src_versions()

    def _on_tgt_platform_change(self, _event=None) -> None:
        self._update_tgt_versions()

    def _on_src_version_change(self, _event=None) -> None:
        self._show_version_note(self._src_platform.get(), self._src_version.get())

    def _on_tgt_version_change(self, _event=None) -> None:
        self._show_version_note(self._tgt_platform.get(), self._tgt_version.get())

    def _show_version_note(self, platform_str: str, version: str) -> None:
        # Derive a short platform prefix for the VERSION_NOTES key
        plat = self._get_platform(platform_str)
        prefix_map = {
            Platform.PALO_ALTO: "PAN-OS",
            Platform.FORTIGATE: "FortiOS",
            Platform.CISCO_ASA: "ASA",
            Platform.CISCO_FWSM: "FWSM",
            Platform.CISCO_FTD: "FTD",
        }
        prefix = prefix_map.get(plat, "")
        note = VERSION_NOTES.get(f"{prefix}:{version}", "")
        self._ver_note_var.set(note)

    def _update_src_versions(self) -> None:
        plat = self._get_platform(self._src_platform.get())
        versions = PLATFORM_VERSIONS.get(plat, [])
        self._src_ver_cb["values"] = versions
        if versions:
            self._src_version.set(versions[0])
        self._ver_note_var.set("")

    def _update_tgt_versions(self) -> None:
        plat = self._get_platform(self._tgt_platform.get())
        versions = PLATFORM_VERSIONS.get(plat, [])
        self._tgt_ver_cb["values"] = versions
        if versions:
            self._tgt_version.set(versions[0])
        self._ver_note_var.set("")

    @staticmethod
    def _get_platform(value: str) -> Platform:
        for p in Platform:
            if p.value == value:
                return p
        return Platform.CISCO_ASA

    # ------------------------------------------------------------------ browse / load
    def _browse_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Open Firewall Configuration",
            filetypes=[
                ("All supported", "*.txt *.cfg *.conf *.xml *.log"),
                ("Text files", "*.txt *.cfg *.conf"),
                ("XML files", "*.xml"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            messagebox.showerror("Open Error", str(e))
            return

        self._source_file = path
        self._load_text_into_editor(text)
        self._set_status(f"Loaded: {os.path.basename(path)} ({len(text):,} bytes)")

    def _load_text_into_editor(self, text: str) -> None:
        self._src_text.delete("1.0", tk.END)
        self._src_text.insert("1.0", text)
        self.after(50, lambda: self._apply_highlight(self._src_text))
        self._nb.select(0)

    def _auto_detect(self) -> None:
        """Try to detect platform from current source text."""
        text = self._src_text.get("1.0", tk.END)
        platform, version = self._detect_platform(text)
        if platform:
            self._src_platform.set(platform.value)
            self._update_src_versions()
            if version:
                available = list(self._src_ver_cb["values"])
                if version in available:
                    self._src_version.set(version)
                else:
                    # Fall back to closest available version (first one >= detected, else first)
                    closest = self._closest_version(version, available)
                    self._src_version.set(closest)
                    self._set_status(
                        f"Auto-detected: {platform.value} {version} "
                        f"(not in version list — using {closest})"
                    )
                    return
            self._set_status(f"Auto-detected: {platform.value} {version or ''}")
        else:
            self._set_status("Auto-detect failed — please select platform manually.")

    @staticmethod
    def _closest_version(detected: str, available: list[str]) -> str:
        """Return the available version string closest to detected (by numeric distance)."""
        if not available:
            return detected

        def _ver_int(v: str) -> int:
            """Encode version as a comparable integer (up to 4 dot-separated components)."""
            try:
                parts = [int(x) for x in v.split(".")]
                # Pad to 4 components so comparison is always equal-length
                parts += [0] * (4 - len(parts))
                return parts[0] * 10**9 + parts[1] * 10**6 + parts[2] * 10**3 + parts[3]
            except (ValueError, IndexError):
                return 0

        det_int = _ver_int(detected)
        candidates = sorted(available, key=lambda v: abs(_ver_int(v) - det_int))
        return candidates[0]

    @staticmethod
    def _detect_platform(text: str):
        """Return (Platform, version_hint) or (None, None)."""
        low = text[:4000].lower()

        # Palo Alto XML
        if "<config" in low and ("<vsys" in low or "<security>" in low or "pan-os" in low):
            m = re.search(r'version="([0-9]+\.[0-9]+)', text[:500])
            ver = m.group(1) if m else None
            return Platform.PALO_ALTO, ver

        # FortiGate
        if "config system global" in low or "config firewall policy" in low:
            m = re.search(r'#config-version=.*?-(\d+\.\d+)', text[:1000])
            ver = m.group(1) if m else None
            return Platform.FORTIGATE, ver

        # Cisco
        if "access-list" in low and "extended" in low:
            m = re.search(r'asa\s+version\s+([0-9]+\.[0-9]+)', low[:2000])
            ver = m.group(1) if m else None
            if "fwsm" in low or "firewall service module" in low:
                return Platform.CISCO_FWSM, ver
            if "ftd" in low or "firepower" in low or "flexconfig" in low:
                return Platform.CISCO_FTD, ver
            return Platform.CISCO_ASA, ver

        return None, None

    # ------------------------------------------------------------------ parse
    def _parse(self) -> None:
        text = self._src_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("No Input", "Paste or load a configuration first.")
            return

        platform = self._get_platform(self._src_platform.get())
        version  = self._src_version.get()

        self._set_status(f"Parsing {platform.value} {version}...")
        self.update_idletasks()

        def _do_parse():
            try:
                parser = get_parser(platform, version)
                cfg = parser.parse(text)
                analyzer = ConfigAnalyzer()
                stats = analyzer.analyse(cfg)
                self.after(0, lambda: self._on_parse_done(cfg, stats))
            except Exception as exc:
                self.after(0, lambda: self._on_parse_error(exc))

        threading.Thread(target=_do_parse, daemon=True).start()

    def _on_parse_done(self, cfg: FirewallConfig, stats: ConfigStats) -> None:
        self._cfg   = cfg
        self._stats = stats
        self._gen_warnings = []   # clear stale generation warnings from a prior target
        self._iface_map = {}      # interface overrides don't carry across configs
        self._refresh_stats(stats)
        self._refresh_warnings(cfg, stats)
        n = len(cfg.access_rules)
        w = len(cfg.parse_warnings)
        e = len(cfg.parse_errors)
        self._set_status(
            f"Parsed {cfg.platform.value} {cfg.version} — "
            f"{n} rules, {len(cfg.network_objects)} objects, "
            f"{len(cfg.nat_rules)} NAT rules, "
            f"{w} warnings, {e} errors"
        )
        self._update_info(cfg, stats)
        self._nb.select(1)

    def _on_parse_error(self, exc: Exception) -> None:
        self._set_status(f"Parse error: {exc}")
        messagebox.showerror("Parse Error", str(exc))

    # ------------------------------------------------------------------ generate
    def _generate(self) -> None:
        if self._cfg is None:
            messagebox.showwarning("Not Parsed", "Parse a source config first.")
            return

        platform = self._get_platform(self._tgt_platform.get())
        version  = self._tgt_version.get()

        self._set_status(f"Generating {platform.value} {version}...")
        self.update_idletasks()

        def _do_gen():
            try:
                gen = get_generator(platform, version)
                cfg = self._mapped_cfg(platform)
                output = gen.generate(cfg)
                warnings = list(gen.warnings)
                self.after(0, lambda: self._on_gen_done(output, warnings))
            except Exception as exc:
                self.after(0, lambda: self._on_gen_error(exc))

        threading.Thread(target=_do_gen, daemon=True).start()

    def _effective_iface_mapping(self, target: Platform) -> dict:
        """Merge target-convention suggestions with the user's interface overrides."""
        identities = collect_interface_names(self._cfg)
        keys = [idn.key for idn in identities]
        suggestions = suggest_target_names(identities, target)
        return {k: (self._iface_map.get(k) or suggestions.get(k, k)) for k in keys}

    def _mapped_cfg(self, target: Platform) -> FirewallConfig:
        """Apply the effective interface mapping to the parsed config for generation."""
        mapping = self._effective_iface_mapping(target)
        return apply_interface_mapping(self._cfg, mapping, target)

    # ------------------------------------------------------------------ interface map dialog
    def _open_iface_map(self) -> None:
        if self._cfg is None:
            messagebox.showwarning("Not Parsed", "Parse a source config first.")
            return

        rows = collect_interface_names(self._cfg)
        if not rows:
            messagebox.showinfo(
                "No Interfaces",
                "No interface or zone names were detected in the parsed config.",
            )
            return

        target = self._get_platform(self._tgt_platform.get())
        suggestions = suggest_target_names(rows, target)

        win = tk.Toplevel(self)
        win.title("Map Interface Names")
        win.configure(bg=BG)
        win.transient(self)
        win.geometry("620x460")

        tk.Label(
            win,
            text=f"Refactor interface names for target: {target.value}",
            bg=BG, fg=ACCENT, font=BOLD, anchor="w",
        ).pack(fill=tk.X, padx=12, pady=(10, 2))
        tk.Label(
            win,
            text="Edit the target names below. Applied to interfaces, rule zones, "
                 "NAT, ACL bindings and routes when you Generate. For a zone, enter a "
                 "comma-separated list to expand it to several interfaces (or click "
                 "→ members); ACL bindings are duplicated per member.",
            bg=BG, fg=FG_DIM, font=("Segoe UI", 9), anchor="w",
            justify="left", wraplength=580,
        ).pack(fill=tk.X, padx=12, pady=(0, 8))

        # Scrollable body
        body = tk.Frame(win, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=12)
        canvas = tk.Canvas(body, bg=BG, highlightthickness=0)
        vsb = ttk.Scrollbar(body, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=BG)
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Header row
        hdr = tk.Frame(inner, bg=BG)
        hdr.pack(fill=tk.X, pady=(0, 4))
        for text, w in (("Source (kind)", 22), ("nameif / members", 18), ("Target name", 20)):
            tk.Label(hdr, text=text, bg=BG, fg=FG_DIM, font=BOLD,
                     width=w, anchor="w").pack(side=tk.LEFT, padx=2)

        entries: dict = {}
        for idn in rows:
            key = idn.key
            row = tk.Frame(inner, bg=BG)
            row.pack(fill=tk.X, pady=1)

            label = f"{idn.physical or key}"
            if idn.kind == "zone":
                label = f"{key}  [zone]"
            tk.Label(row, text=label, bg=BG, fg=FG, font=MONO,
                     width=22, anchor="w").pack(side=tk.LEFT, padx=2)

            if idn.kind == "zone":
                detail = ", ".join(idn.members) if idn.members else "(empty)"
            else:
                detail = idn.logical or "-"
            tk.Label(row, text=detail, bg=BG, fg=FG_DIM, font=MONO,
                     width=18, anchor="w").pack(side=tk.LEFT, padx=2)

            var = tk.StringVar(value=self._iface_map.get(key) or suggestions.get(key, key))
            ent = tk.Entry(row, textvariable=var, bg=BG2, fg=FG,
                           insertbackground=FG, font=MONO, width=22, relief="flat")
            ent.pack(side=tk.LEFT, padx=2)
            entries[key] = var

            # For a zone, offer a one-click expansion to its (mapped) members so a
            # zone-based source resolves to interfaces on an interface-based target.
            if idn.kind == "zone" and idn.members:
                def _expand_to_members(v=var, members=list(idn.members)) -> None:
                    v.set(",".join(suggestions.get(m, m) for m in members))
                ttk.Button(row, text="→ members", width=10,
                           command=_expand_to_members).pack(side=tk.LEFT, padx=2)

        # Buttons
        btns = tk.Frame(win, bg=BG)
        btns.pack(fill=tk.X, padx=12, pady=10)

        def _reset() -> None:
            for key, var in entries.items():
                var.set(suggestions.get(key, key))

        def _apply() -> None:
            for key, var in entries.items():
                val = var.get().strip()
                if val and val != suggestions.get(key, key):
                    self._iface_map[key] = val
                else:
                    self._iface_map.pop(key, None)
            self._set_status(
                f"Interface mapping saved ({len(self._iface_map)} override"
                f"{'' if len(self._iface_map) == 1 else 's'}). Click Generate to apply."
            )
            win.destroy()

        ttk.Button(btns, text="Reset to suggestions", command=_reset).pack(side=tk.LEFT)
        ttk.Button(btns, text="Cancel", command=win.destroy).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(btns, text="Apply", style="Accent.TButton",
                   command=_apply).pack(side=tk.RIGHT)

        win.update_idletasks()
        win.grab_set()

    def _on_gen_done(self, output: str, warnings: list) -> None:
        self._out_text.configure(state="normal")
        self._out_text.delete("1.0", tk.END)
        self._out_text.insert("1.0", output)
        # Read-only like the stats/warnings tabs; tag-based highlighting still
        # works on a disabled widget (only insert/delete are blocked).
        self._out_text.configure(state="disabled")
        self.after(50, lambda: self._apply_highlight(self._out_text))

        # Re-render the warnings tab from scratch (parse warnings/risks + this
        # generation's warnings) so repeated generations don't accumulate.
        self._gen_warnings = list(warnings)
        if self._cfg is not None and self._stats is not None:
            self._refresh_warnings(self._cfg, self._stats)

        self._set_status(
            f"Generated {len(output):,} bytes — {len(warnings)} generation warnings."
        )
        self._nb.select(3)

    def _on_gen_error(self, exc: Exception) -> None:
        self._set_status(f"Generation error: {exc}")
        messagebox.showerror("Generate Error", str(exc))

    # ------------------------------------------------------------------ stats UI
    def _refresh_stats(self, stats: ConfigStats) -> None:
        # Clear cards
        for w in self._cards_frame.winfo_children():
            w.destroy()
        self._make_stat_cards(stats)

        # Detail text
        self._stats_text.configure(state="normal")
        self._stats_text.delete("1.0", tk.END)

        def section(title: str) -> None:
            self._stats_text.insert(tk.END, f"\n{'─'*60}\n  {title}\n{'─'*60}\n")

        def row(label: str, value, colour: str = FG) -> None:
            self._stats_text.insert(tk.END, f"  {label:<40}{value}\n")

        section("Rules")
        row("Total access rules",        stats.rule_count)
        row("  Permit",                  stats.permit_count)
        row("  Deny",                    stats.deny_count)
        row("  Disabled / inactive",     stats.disabled_rule_count)
        row("  With logging",            stats.logged_rule_count)
        row("  Without logging",         stats.unlogged_rule_count)
        row("  Logging coverage",        f"{stats.logging_coverage_pct}%")
        row("  Any-any permit (risky)",  stats.any_any_rule_count)
        row("  Potential duplicates",    stats.duplicate_rule_count)
        row("  Shadowed rules",          stats.shadowed_rule_count)
        row("Distinct ACL names",        stats.acl_count)
        if stats.largest_acl:
            row("Largest ACL / policy set",
                f"{stats.largest_acl} ({stats.largest_acl_size} rules)")

        if stats.rules_per_acl and len(stats.rules_per_acl) > 1:
            section("Rules per ACL / Policy Set")
            for acl, cnt in sorted(stats.rules_per_acl.items(), key=lambda x: -x[1]):
                row(f"  {acl}", cnt)

        section("Objects & Groups")
        row("Network objects",           stats.network_object_count)
        row("Service objects",           stats.service_object_count)
        row("Object groups (total)",     stats.object_group_count)
        row("  Network groups",          stats.network_group_count)
        row("  Service groups",          stats.service_group_count)
        for otype, cnt in stats.object_type_breakdown.items():
            row(f"  {otype} objects", cnt)

        section("NAT")
        row("Total NAT rules",           stats.nat_rule_count)
        row("  Static NAT",              stats.static_nat_count)
        row("  Dynamic NAT",             stats.dynamic_nat_count)
        row("  PAT / overload",          stats.pat_count)

        section("Network")
        row("Interfaces",                stats.interface_count)
        row("Static routes",             stats.route_count)
        row("  Default routes",          stats.default_route_count)

        section("Protocol Distribution")
        for proto, cnt in sorted(stats.protocol_breakdown.items(), key=lambda x: -x[1]):
            row(f"  {proto}", cnt)

        if stats.zone_usage:
            section("Zone / Interface Usage")
            for zone, cnt in sorted(stats.zone_usage.items(), key=lambda x: -x[1]):
                row(f"  {zone}", cnt)

        section("Complexity")
        score = stats.complexity_score
        bar_len = score // 5
        bar = "█" * bar_len + "░" * (20 - bar_len)
        self._stats_text.insert(tk.END, f"\n  Score: {score}/100  [{bar}]\n")
        label = "LOW" if score < 30 else ("MEDIUM" if score < 60 else "HIGH")
        self._stats_text.insert(tk.END, f"  Complexity: {label}\n")

        self._stats_text.configure(state="disabled")

    def _make_stat_cards(self, stats: ConfigStats) -> None:
        cards = [
            ("Rules",    stats.rule_count,          ACCENT),
            ("Permit",   stats.permit_count,         GREEN),
            ("Deny",     stats.deny_count,           RED),
            ("Objects",  stats.network_object_count, ACCENT),
            ("Groups",   stats.object_group_count,   ACCENT),
            ("NAT",      stats.nat_rule_count,       YELLOW),
            ("Risks",    len(stats.migration_risks), RED),
            ("Complexity", f"{stats.complexity_score}/100",
             GREEN if stats.complexity_score < 40 else (YELLOW if stats.complexity_score < 70 else RED)),
        ]
        for title, value, colour in cards:
            card = tk.Frame(self._cards_frame, bg=BG3, padx=14, pady=8, relief="flat")
            card.pack(side=tk.LEFT, padx=4)
            tk.Label(card, text=str(value), bg=BG3, fg=colour,
                     font=("Segoe UI", 18, "bold")).pack()
            tk.Label(card, text=title, bg=BG3, fg=FG_DIM,
                     font=("Segoe UI", 8)).pack()

    # ------------------------------------------------------------------ warnings UI
    def _refresh_warnings(self, cfg: FirewallConfig, stats: ConfigStats) -> None:
        self._warn_text.configure(state="normal")
        self._warn_text.delete("1.0", tk.END)

        def add(text: str, tag: str = "") -> None:
            if tag:
                self._warn_text.insert(tk.END, text + "\n", tag)
            else:
                self._warn_text.insert(tk.END, text + "\n")

        gen_warnings = getattr(self, "_gen_warnings", [])
        if not (cfg.parse_errors or cfg.parse_warnings or stats.migration_risks or gen_warnings):
            add("No warnings or risks detected.", "ok")
        else:
            if cfg.parse_errors:
                add(f"\n  Parse Errors ({len(cfg.parse_errors)})", "head")
                for e in cfg.parse_errors:
                    add(f"  ✗  {e}", "error")

            if cfg.parse_warnings:
                add(f"\n  Parse Warnings ({len(cfg.parse_warnings)})", "head")
                for w in cfg.parse_warnings:
                    add(f"  ⚠  {w}", "warn")

            if stats.migration_risks:
                add(f"\n  Migration Risks ({len(stats.migration_risks)})", "head")
                for rule_name, risk in stats.migration_risks:
                    add(f"  ⚠  [{rule_name}] {risk}", "risk")

            if gen_warnings:
                add(f"\n  Generation Warnings ({len(gen_warnings)})", "head")
                for w in gen_warnings:
                    add(f"  ⚠  {w}", "warn")

        self._warn_text.configure(state="disabled")

    # ------------------------------------------------------------------ info panel
    def _update_info(self, cfg: FirewallConfig, stats: ConfigStats) -> None:
        self._info_var.set(
            f"{cfg.platform.value} {cfg.version}  |  "
            f"{stats.rule_count} rules  |  "
            f"{stats.nat_rule_count} NAT  |  "
            f"{stats.network_object_count} objects  |  "
            f"Complexity: {stats.complexity_score}/100  |  "
            f"{len(stats.migration_risks)} risks"
        )

    # ------------------------------------------------------------------ copy / save
    def _copy_output(self) -> None:
        text = self._out_text.get("1.0", tk.END)
        if not text.strip():
            self._set_status("Nothing to copy — generate first.")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("Output copied to clipboard.")

    def _save_output(self) -> None:
        text = self._out_text.get("1.0", tk.END)
        if not text.strip():
            messagebox.showwarning("No Output", "Generate a config first.")
            return
        platform = self._get_platform(self._tgt_platform.get())
        ext = ".xml" if platform == Platform.PALO_ALTO else ".cfg"
        path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[("Config files", f"*{ext}"), ("All files", "*.*")],
            initialfile=f"migrated{ext}",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            self._set_status(f"Saved: {path}")
        except OSError as e:
            messagebox.showerror("Save Error", str(e))

    # ------------------------------------------------------------------ about
    def _show_about(self) -> None:
        win = tk.Toplevel(self)
        win.title("About ndFWMig")
        win.configure(bg=BG)
        win.transient(self)
        win.geometry("680x560")
        win.minsize(520, 420)

        # Header
        head = tk.Frame(win, bg=BG2)
        head.pack(fill=tk.X)
        tk.Label(head, text="ndFWMig", bg=BG2, fg=ACCENT,
                 font=("Segoe UI", 16, "bold"), anchor="w").pack(
            side=tk.LEFT, padx=12, pady=10)
        tk.Label(head, text="v0.22", bg=BG2, fg=FG_DIM, font=SANS).pack(
            side=tk.RIGHT, padx=12)

        tk.Label(
            win,
            text="Firewall configuration migration tool — "
                 "ASA · FWSM · FTD · PAN-OS · FortiOS",
            bg=BG, fg=FG_DIM, font=SANS, anchor="w", justify="left",
            wraplength=640,
        ).pack(fill=tk.X, padx=12, pady=(10, 6))

        # Scrollable disclaimer
        body = tk.Frame(win, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 6))
        text = tk.Text(body, bg=BG2, fg=FG, font=("Segoe UI", 9),
                       wrap="word", relief="flat", borderwidth=0,
                       padx=10, pady=10)
        vsb = ttk.Scrollbar(body, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=vsb.set)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        text.tag_configure("title", foreground=YELLOW,
                            font=("Segoe UI", 10, "bold"))
        lines = DISCLAIMER.split("\n", 1)
        text.insert(tk.END, lines[0] + "\n\n", "title")
        if len(lines) > 1:
            text.insert(tk.END, lines[1].lstrip("\n"))
        text.configure(state="disabled")

        ttk.Button(win, text="Close", style="Accent.TButton",
                   command=win.destroy).pack(side=tk.RIGHT, padx=12, pady=10)

        win.update_idletasks()
        win.grab_set()

    # ------------------------------------------------------------------ status
    def _set_status(self, msg: str) -> None:
        self._status_var.set(msg)
        self.update_idletasks()
