"""
ML Classifier Page for APKStudioAI 2.1
ML model predictions, feature importance, and explanations.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("ml_classifier", "ML Classifier", "🤖")
class MLClassifierPage(BasePage):
    """ML classifier results page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)

        ctk.CTkLabel(header, text="ML Classifier", font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")

        # Model info
        info_frame = ctk.CTkFrame(self)
        info_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))
        info_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.model_cards = {}
        for i, (key, title) in enumerate([
            ("model", "Model"), ("family", "Predicted Family"),
            ("confidence", "Confidence"), ("method", "Method")
        ]):
            card = ctk.CTkFrame(info_frame)
            card.grid(row=0, column=i, padx=10, pady=10, sticky="ew")
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11)).pack(pady=(10, 0))
            label = ctk.CTkLabel(card, text="—", font=ctk.CTkFont(size=20, weight="bold"))
            label.pack(pady=(0, 10))
            self.model_cards[key] = label

        # Main content
        content = ctk.CTkFrame(self)
        content.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))
        content.grid_columnconfigure((0, 1), weight=1)
        content.grid_rowconfigure(0, weight=1)

        # Left: All Probabilities
        left = ctk.CTkFrame(content)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left, text="Family Probabilities", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=15)

        self.probs_frame = ctk.CTkScrollableFrame(left)
        self.probs_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

        # Right: Feature Importance / SHAP
        right = ctk.CTkFrame(content)
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(right, text="Top Features (SHAP)", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=15)

        self.shap_frame = ctk.CTkScrollableFrame(right)
        self.shap_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

        # Explainability section
        explain_frame = ctk.CTkFrame(self)
        explain_frame.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 20))
        explain_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(explain_frame, text="Explanation", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=15)

        self.explanation_text = ctk.CTkTextbox(explain_frame, height=100)
        self.explanation_text.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 15))

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        ml_results = self.analysis_results.get("ml", {})

        # Model info
        self.model_cards["model"].configure(text=ml_results.get("model_name", "Ensemble"))
        self.model_cards["family"].configure(text=ml_results.get("predicted_family", "Unknown"))
        self.model_cards["confidence"].configure(text=f"{ml_results.get('confidence', 0):.1%}")
        self.model_cards["method"].configure(text=ml_results.get("method", "RF + GNN"))

        # Probabilities
        for w in self.probs_frame.winfo_children():
            w.destroy()

        probs = ml_results.get("all_probabilities", {})
        sorted_probs = sorted(probs.items(), key=lambda x: x[1], reverse=True)

        for i, (family, prob) in enumerate(sorted_probs):
            row = ctk.CTkFrame(self.probs_frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.grid(row=i, column=0, sticky="ew", pady=2)
            row.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(row, text=family.replace("_", " ").title(), anchor="w").grid(
                row=0, column=0, padx=10, pady=5, sticky="w")

            prog = ctk.CTkProgressBar(row)
            prog.grid(row=0, column=1, sticky="ew", padx=10, pady=5)
            prog.set(prob)

            ctk.CTkLabel(row, text=f"{prob:.1%}", width=60).grid(row=0, column=2, padx=10, pady=5)

        # SHAP features
        for w in self.shap_frame.winfo_children():
            w.destroy()

        shap_values = ml_results.get("shap_values", {})
        sorted_shap = sorted(shap_values.items(), key=lambda x: abs(x[1]), reverse=True)[:20]

        for i, (feature, value) in enumerate(sorted_shap):
            row = ctk.CTkFrame(self.shap_frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.grid(row=i, column=0, sticky="ew", pady=1)
            row.grid_columnconfigure(1, weight=1)

            color = "#e74c3c" if value > 0 else "#3498db"
            ctk.CTkLabel(row, text=feature.replace("_", " "), anchor="w").grid(
                row=0, column=0, padx=10, pady=2, sticky="w")

            prog = ctk.CTkProgressBar(row, width=150)
            prog.grid(row=0, column=1, padx=10, pady=2)
            prog.set(min(abs(value), 1.0))
            prog.configure(progress_color=color)

            ctk.CTkLabel(row, text=f"{value:+.3f}", width=50, text_color=color).grid(
                row=0, column=2, padx=10, pady=2)

        # Explanation text
        self.explanation_text.delete("1.0", "end")
        explanation = ml_results.get("explanation", "No explanation available.")
        self.explanation_text.insert("1.0", explanation)