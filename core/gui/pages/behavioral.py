"""
Behavioral Analysis Page for APKSTUDIOAI 2.1
Behavior patterns, API call sequences, and anomaly detection.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("behavioral", "Behavioral", "📊")
class BehavioralPage(BasePage):
    """Behavioral analysis page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)

        ctk.CTkLabel(header, text="Behavioral Analysis", font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")

        # Behavior patterns
        patterns_frame = ctk.CTkFrame(self)
        patterns_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        patterns_frame.grid_columnconfigure((0, 1), weight=1)
        patterns_frame.grid_rowconfigure(1, weight=1)

        # Left: Detected Patterns
        left = ctk.CTkFrame(patterns_frame)
        left.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, 10))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left, text="Behavior Patterns", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=15)

        self.patterns_list = ctk.CTkScrollableFrame(left)
        self.patterns_list.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

        # Right: API Call Sequences
        right = ctk.CTkFrame(patterns_frame)
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(right, text="Sensitive API Sequences", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=15)

        self.sequences_list = ctk.CTkScrollableFrame(right)
        self.sequences_list.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

        # Anomaly scores
        anomaly_frame = ctk.CTkFrame(patterns_frame)
        anomaly_frame.grid(row=1, column=1, sticky="ew", padx=(10, 0))
        anomaly_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(anomaly_frame, text="Anomaly Scores", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=15)

        self.anomaly_frame = ctk.CTkFrame(anomaly_frame)
        self.anomaly_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 15))

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        behavior = self.analysis_results.get("behavior", {})
        dynamic = self.analysis_results.get("dynamic", {})

        # Patterns
        for w in self.patterns_list.winfo_children():
            w.destroy()

        patterns = behavior.get("patterns", [])
        for i, pattern in enumerate(patterns):
            self._add_pattern(i, pattern)

        # API sequences
        for w in self.sequences_list.winfo_children():
            w.destroy()

        sequences = behavior.get("api_sequences", [])
        for i, seq in enumerate(sequences[:20]):
            self._add_sequence(i, seq)

        # Anomaly scores
        for w in self.anomaly_frame.winfo_children():
            w.destroy()

        scores = behavior.get("anomaly_scores", {})
        for cat, score in scores.items():
            row = ctk.CTkFrame(self.anomaly_frame, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=5)
            ctk.CTkLabel(row, text=cat.replace("_", " ").title(), anchor="w").pack(side="left", padx=10)
            prog = ctk.CTkProgressBar(row, width=200)
            prog.pack(side="left", padx=10)
            prog.set(score / 100 if score > 1 else score)
            ctk.CTkLabel(row, text=f"{score:.1f}").pack(side="left", padx=10)

    def _add_pattern(self, idx: int, pattern: Dict):
        row = ctk.CTkFrame(self.patterns_list, fg_color=("gray95", "gray10") if idx % 2 == 0 else ("gray90", "gray15"))
        row.grid(row=idx, column=0, sticky="ew", pady=2)
        row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(row, text=pattern.get("name", "Pattern"), font=ctk.CTkFont(size=11, weight="bold")).grid(
            row=0, column=0, padx=10, pady=5, sticky="w")
        ctk.CTkLabel(row, text=pattern.get("description", ""), text_color=("gray50", "gray70")).grid(
            row=0, column=1, padx=10, pady=5, sticky="w")

    def _add_sequence(self, idx: int, seq: Dict):
        row = ctk.CTkFrame(self.sequences_list, fg_color=("gray95", "gray10") if idx % 2 == 0 else ("gray90", "gray15"))
        row.grid(row=idx, column=0, sticky="ew", pady=2)
        row.grid_columnconfigure(1, weight=1)

        calls = " -> ".join(seq.get("calls", [])[:5])
        ctk.CTkLabel(row, text=calls, anchor="w").grid(row=0, column=0, padx=10, pady=3, sticky="w")
        score = seq.get("score", 0)
        ctk.CTkLabel(row, text=f"Score: {score:.2f}", text_color="#e74c3c" if score > 0.7 else "#f39c12").grid(
            row=0, column=1, padx=10, pady=3)