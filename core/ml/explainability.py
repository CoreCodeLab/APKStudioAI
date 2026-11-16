"""
Explainability Engine for APKStudioAI 2.1
SHAP and LIME integration for model interpretability.
"""
import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("explainability")


@dataclass
class ExplanationResult:
    """Result of model explanation."""
    feature_importance: Dict[str, float]
    shap_values: Optional[np.ndarray] = None
    lime_explanation: Optional[Dict] = None
    base_value: float = 0.0
    prediction: float = 0.0
    method: str = "shap"


class ExplainabilityEngine:
    """Provides SHAP and LIME explanations for ML model predictions."""

    def __init__(self, config: Dict = None):
        self.config = config or get_config().get_all()
        self.shap_available = False
        self.lime_available = False
        self._check_dependencies()

    def _check_dependencies(self):
        """Check for SHAP and LIME availability."""
        try:
            import shap
            self.shap = shap
            self.shap_available = True
        except ImportError:
            logger.warning("explainability_shap_not_available")

        try:
            import lime
            import lime.lime_tabular
            self.lime = lime
            self.lime_available = True
        except ImportError:
            logger.warning("explainability_lime_not_available")

    def explain_shap(self, model: Any, features: np.ndarray,
                     feature_names: List[str],
                     background_data: np.ndarray = None,
                     max_samples: int = 100) -> ExplanationResult:
        """
        Generate SHAP explanations for a prediction.

        Args:
            model: Trained model with predict/predict_proba method
            features: Feature vector to explain (1D array)
            feature_names: Names of features
            background_data: Background dataset for SHAP (optional)
            max_samples: Max background samples to use

        Returns:
            ExplanationResult with SHAP values and feature importance
        """
        if not self.shap_available:
            return self._fallback_explanation(model, features, feature_names, "shap")

        try:
            # Prepare background data
            if background_data is None:
                # Use a small synthetic background
                background_data = np.random.randn(min(50, max_samples), len(features))

            # Limit background size
            if len(background_data) > max_samples:
                idx = np.random.choice(len(background_data), max_samples, replace=False)
                background_data = background_data[idx]

            # Create explainer
            if hasattr(model, 'predict_proba'):
                predict_fn = model.predict_proba
            else:
                predict_fn = model.predict

            # Use KernelExplainer for model-agnostic explanations
            explainer = self.shap.KernelExplainer(predict_fn, background_data)

            # Explain single instance
            shap_values = explainer.shap_values(features.reshape(1, -1), nsamples=200)

            # Handle multi-class output
            if isinstance(shap_values, list):
                # Multi-class: use the predicted class
                pred_probs = predict_fn(features.reshape(1, -1))
                if len(pred_probs.shape) > 1:
                    pred_class = np.argmax(pred_probs[0])
                else:
                    pred_class = int(pred_probs[0])
                shap_vals = shap_values[pred_class][0]
                base_val = explainer.expected_value[pred_class] if isinstance(explainer.expected_value, list) else explainer.expected_value
            else:
                shap_vals = shap_values[0]
                base_val = explainer.expected_value

            # Feature importance (absolute SHAP values)
            importance = {name: float(abs(val)) for name, val in zip(feature_names, shap_vals)}
            importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))

            return ExplanationResult(
                feature_importance=importance,
                shap_values=shap_vals,
                base_value=float(base_val),
                prediction=float(predict_fn(features.reshape(1, -1)).max() if hasattr(model, 'predict_proba') else predict_fn(features.reshape(1, -1))[0]),
                method="shap",
            )

        except Exception as e:
            logger.error("explainability_shap_failed", error=str(e))
            return self._fallback_explanation(model, features, feature_names, "shap")

    def explain_lime(self, model: Any, features: np.ndarray,
                     feature_names: List[str],
                     training_data: np.ndarray = None,
                     num_features: int = 20,
                     num_samples: int = 1000) -> ExplanationResult:
        """
        Generate LIME explanations for a prediction.

        Args:
            model: Trained model with predict_proba method
            features: Feature vector to explain (1D array)
            feature_names: Names of features
            training_data: Training data for LIME (optional)
            num_features: Number of features to include in explanation
            num_samples: Number of perturbations for LIME

        Returns:
            ExplanationResult with LIME explanation
        """
        if not self.lime_available:
            return self._fallback_explanation(model, features, feature_names, "lime")

        try:
            # Prepare training data
            if training_data is None:
                training_data = np.random.randn(100, len(features))

            # Create LIME explainer
            explainer = self.lime.lime_tabular.LimeTabularExplainer(
                training_data,
                feature_names=feature_names,
                class_names=['benign', 'malicious'],
                mode='classification',
                random_state=42,
            )

            # Get prediction function
            if hasattr(model, 'predict_proba'):
                predict_fn = model.predict_proba
            else:
                # Wrap predict to return probabilities
                def predict_fn(x):
                    preds = model.predict(x)
                    # Convert to probability-like output
                    proba = np.zeros((len(preds), 2))
                    proba[np.arange(len(preds)), preds] = 1.0
                    return proba

            # Generate explanation
            exp = explainer.explain_instance(
                features,
                predict_fn,
                num_features=num_features,
                num_samples=num_samples,
            )

            # Extract feature importance
            lime_weights = dict(exp.as_list())
            importance = {name: float(abs(weight)) for name, weight in lime_weights.items()}
            importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))

            # Get prediction
            pred = predict_fn(features.reshape(1, -1))
            pred_val = float(pred[0][1]) if pred.shape[1] > 1 else float(pred[0])

            return ExplanationResult(
                feature_importance=importance,
                lime_explanation={
                    "weights": lime_weights,
                    "intercept": float(exp.intercept[1]) if len(exp.intercept) > 1 else float(exp.intercept[0]),
                    "score": float(exp.score),
                },
                base_value=float(exp.intercept[1]) if len(exp.intercept) > 1 else float(exp.intercept[0]),
                prediction=pred_val,
                method="lime",
            )

        except Exception as e:
            logger.error("explainability_lime_failed", error=str(e))
            return self._fallback_explanation(model, features, feature_names, "lime")

    def explain_model_global(self, model: Any, features_list: List[np.ndarray],
                             feature_names: List[str],
                             max_samples: int = 500) -> Dict[str, Any]:
        """
        Generate global feature importance using SHAP.

        Args:
            model: Trained model
            features_list: List of feature vectors
            feature_names: Names of features
            max_samples: Max samples to use for global explanation

        Returns:
            Dictionary with global feature importance
        """
        if not self.shap_available:
            return self._fallback_global_importance(model, features_list, feature_names)

        try:
            X = np.stack(features_list[:max_samples])

            if hasattr(model, 'predict_proba'):
                predict_fn = model.predict_proba
            else:
                predict_fn = model.predict

            # Use KernelExplainer for global importance
            explainer = self.shap.KernelExplainer(predict_fn, X[:min(100, len(X))])

            # Compute SHAP values for subset
            sample_size = min(100, len(X))
            shap_values = explainer.shap_values(X[:sample_size])

            # Handle multi-class
            if isinstance(shap_values, list):
                # Average across classes
                mean_shap = np.mean([np.abs(sv).mean(axis=0) for sv in shap_values], axis=0)
            else:
                mean_shap = np.abs(shap_values).mean(axis=0)

            # Global feature importance
            global_importance = {
                name: float(imp) for name, imp in zip(feature_names, mean_shap)
            }
            global_importance = dict(sorted(global_importance.items(), key=lambda x: x[1], reverse=True))

            return {
                "global_importance": global_importance,
                "method": "shap_global",
                "num_samples": sample_size,
            }

        except Exception as e:
            logger.error("explainability_global_failed", error=str(e))
            return self._fallback_global_importance(model, features_list, feature_names)

    def _fallback_explanation(self, model: Any, features: np.ndarray,
                              feature_names: List[str], method: str) -> ExplanationResult:
        """Fallback explanation using feature importance or permutation."""
        try:
            # Try to get feature importances from model
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
            elif hasattr(model, 'coef_'):
                importances = np.abs(model.coef_).mean(axis=0) if model.coef_.ndim > 1 else np.abs(model.coef_)
            else:
                # Permutation importance fallback
                importances = self._permutation_importance(model, features, feature_names)

            importance = {name: float(imp) for name, imp in zip(feature_names, importances)}
            importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))

            pred = model.predict(features.reshape(1, -1))[0] if hasattr(model, 'predict') else 0

            return ExplanationResult(
                feature_importance=importance,
                base_value=0.0,
                prediction=float(pred),
                method=f"{method}_fallback",
            )
        except Exception as e:
            logger.error("explainability_fallback_failed", error=str(e))
            return ExplanationResult(
                feature_importance={},
                method=f"{method}_failed",
            )

    def _permutation_importance(self, model: Any, features: np.ndarray,
                                feature_names: List[str]) -> np.ndarray:
        """Compute permutation importance."""
        baseline = model.predict(features.reshape(1, -1))[0] if hasattr(model, 'predict') else 0
        importances = np.zeros(len(features))

        for i in range(len(features)):
            perturbed = features.copy()
            perturbed[i] = np.random.randn()  # Random perturbation
            pred = model.predict(perturbed.reshape(1, -1))[0] if hasattr(model, 'predict') else 0
            importances[i] = abs(baseline - pred)

        return importances

    def _fallback_global_importance(self, model: Any, features_list: List[np.ndarray],
                                    feature_names: List[str]) -> Dict[str, Any]:
        """Fallback global importance using mean permutation importance."""
        importances = np.zeros(len(feature_names))

        for features in features_list[:100]:
            imp = self._permutation_importance(model, features, feature_names)
            importances += imp

        importances /= min(len(features_list), 100)

        global_importance = {
            name: float(imp) for name, imp in zip(feature_names, importances)
        }
        global_importance = dict(sorted(global_importance.items(), key=lambda x: x[1], reverse=True))

        return {
            "global_importance": global_importance,
            "method": "permutation_fallback",
            "num_samples": min(len(features_list), 100),
        }

    def generate_report(self, explanation: ExplanationResult,
                        feature_names: List[str],
                        top_k: int = 15) -> str:
        """Generate human-readable explanation report."""
        lines = [
            f"Model Explanation Report ({explanation.method.upper()})",
            "=" * 50,
            f"Prediction: {explanation.prediction:.4f}",
            f"Base Value: {explanation.base_value:.4f}",
            "",
            f"Top {top_k} Most Important Features:",
            "-" * 50,
        ]

        for i, (feature, importance) in enumerate(list(explanation.feature_importance.items())[:top_k]):
            lines.append(f"  {i+1:2d}. {feature}: {importance:.6f}")

        if explanation.shap_values is not None:
            lines.extend([
                "",
                f"SHAP Values Summary:",
                f"  Mean |SHAP|: {np.abs(explanation.shap_values).mean():.6f}",
                f"  Max |SHAP|: {np.abs(explanation.shap_values).max():.6f}",
            ])

        if explanation.lime_explanation:
            lines.extend([
                "",
                f"LIME Score: {explanation.lime_explanation.get('score', 0):.4f}",
            ])

        return "\n".join(lines)


_explainability_instance = None


def get_explainability_engine(config: Dict = None) -> ExplainabilityEngine:
    """Get singleton explainability engine instance."""
    global _explainability_instance
    if _explainability_instance is None:
        _explainability_instance = ExplainabilityEngine(config)
    return _explainability_instance