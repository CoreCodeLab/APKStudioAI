"""
Family-Disjoint Evaluator for APKStudioAI 2.1
Evaluates ML models using family-disjoint splits to prevent data leakage.
"""
import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("family_evaluator")


@dataclass
class EvaluationResult:
    """Result of family-disjoint evaluation."""
    family: str
    metrics: Dict[str, float]
    confusion_matrix: List[List[int]]
    support: int
    split_info: Dict[str, Any]


@dataclass
class FamilyDisjointResult:
    """Complete family-disjoint evaluation results."""
    per_family: List[EvaluationResult]
    aggregate_metrics: Dict[str, float]
    family_generalization: Dict[str, float]
    recommendations: List[str]


class FamilyDisjointEvaluator:
    """
    Evaluates ML models using family-disjoint cross-validation.
    This prevents data leakage by ensuring samples from the same malware family
    are never in both training and test sets.
    """

    # Known malware families for Android
    MALWARE_FAMILIES = [
        "banking_trojan", "spyware", "rat", "dropper", "ransomware",
        "adware", "sms_trojan", "cryptominer", "root_exploit", "benign",
    ]

    def __init__(self, config: Dict = None):
        self.config = config or get_config().get_all()
        self.family_labels = self.MALWARE_FAMILIES

    def create_family_disjoint_splits(self, data: List[Dict],
                                      n_splits: int = 5,
                                      test_families_per_split: int = 2) -> List[Dict]:
        """
        Create family-disjoint cross-validation splits.

        Args:
            data: List of samples with 'label' (family index) and 'features'
            n_splits: Number of CV splits
            test_families_per_split: Number of families to hold out per split

        Returns:
            List of splits, each with 'train_indices', 'test_indices', 'test_families'
        """
        # Group indices by family
        family_to_indices = defaultdict(list)
        for idx, sample in enumerate(data):
            label = sample.get("label", 9)  # Default to benign (index 9)
            if isinstance(label, str):
                label = self.family_labels.index(label) if label in self.family_labels else 9
            family_to_indices[label].append(idx)

        families = list(family_to_indices.keys())
        np.random.shuffle(families)

        splits = []
        families_per_split = max(1, len(families) // n_splits)

        for i in range(n_splits):
            # Select test families for this split
            start = i * families_per_split
            end = min(start + test_families_per_split, len(families))
            test_families = families[start:end]

            # If last split, include remaining families
            if i == n_splits - 1:
                test_families = families[start:]

            test_indices = []
            for fam in test_families:
                test_indices.extend(family_to_indices[fam])

            train_indices = []
            for fam in families:
                if fam not in test_families:
                    train_indices.extend(family_to_indices[fam])

            if len(train_indices) > 0 and len(test_indices) > 0:
                splits.append({
                    "train_indices": train_indices,
                    "test_indices": test_indices,
                    "test_families": [self.family_labels[f] for f in test_families],
                    "train_families": [self.family_labels[f] for f in families if f not in test_families],
                })

        return splits

    def evaluate_family_disjoint(self, model: Any, data: List[Dict],
                                  n_splits: int = 5,
                                  test_families_per_split: int = 2) -> FamilyDisjointResult:
        """
        Evaluate model using family-disjoint cross-validation.

        Args:
            model: Trained model with predict/predict_proba methods
            data: List of samples with 'features' and 'label'
            n_splits: Number of CV splits
            test_families_per_split: Families per test split

        Returns:
            FamilyDisjointResult with detailed evaluation
        """
        splits = self.create_family_disjoint_splits(data, n_splits, test_families_per_split)

        per_family_results = []
        all_predictions = []
        all_labels = []

        for split_idx, split in enumerate(splits):
            train_idx = split["train_indices"]
            test_idx = split["test_indices"]

            X_train = np.stack([data[i]["features"] for i in train_idx])
            y_train = np.array([data[i].get("label", 9) for i in train_idx])
            X_test = np.stack([data[i]["features"] for i in test_idx])
            y_test = np.array([data[i].get("label", 9) for i in test_idx])

            # Train on this split
            if hasattr(model, 'fit'):
                model.fit(X_train, y_train)

            # Predict
            y_pred = model.predict(X_test)

            # Collect for aggregate metrics
            all_predictions.extend(y_pred)
            all_labels.extend(y_test)

            # Per-family metrics for test families
            for fam_idx in split["test_families"]:
                fam_numeric = self.family_labels.index(fam_idx) if fam_idx in self.family_labels else 9
                fam_mask = (y_test == fam_numeric)

                if fam_mask.sum() > 0:
                    fam_y_test = y_test[fam_mask]
                    fam_y_pred = y_pred[fam_mask]

                    metrics = self._compute_metrics(fam_y_test, fam_y_pred)
                    cm = self._confusion_matrix(fam_y_test, fam_y_pred, len(self.family_labels))

                    per_family_results.append(EvaluationResult(
                        family=fam_idx,
                        metrics=metrics,
                        confusion_matrix=cm.tolist(),
                        support=int(fam_mask.sum()),
                        split_info={
                            "split": split_idx,
                            "train_families": split["train_families"],
                        },
                    ))

        # Aggregate metrics
        aggregate = self._compute_metrics(np.array(all_labels), np.array(all_predictions))

        # Family generalization analysis
        gen_analysis = self._analyze_family_generalization(per_family_results)

        # Recommendations
        recommendations = self._generate_recommendations(aggregate, gen_analysis)

        return FamilyDisjointResult(
            per_family=per_family_results,
            aggregate_metrics=aggregate,
            family_generalization=gen_analysis,
            recommendations=recommendations,
        )

    def evaluate_holdout_families(self, model: Any, data: List[Dict],
                                   holdout_families: List[str]) -> Dict[str, Any]:
        """
        Evaluate model on completely held-out families (simulating zero-day).

        Args:
            model: Pre-trained model
            data: All samples
            holdout_families: Family names to hold out

        Returns:
            Evaluation metrics on holdout families
        """
        holdout_indices = []
        train_indices = []

        for idx, sample in enumerate(data):
            label = sample.get("label", 9)
            if isinstance(label, str):
                label = self.family_labels.index(label) if label in self.family_labels else 9

            if label < len(self.family_labels) and self.family_labels[label] in holdout_families:
                holdout_indices.append(idx)
            else:
                train_indices.append(idx)

        if len(holdout_indices) == 0:
            return {"error": "No samples for holdout families"}

        X_holdout = np.stack([data[i]["features"] for i in holdout_indices])
        y_holdout = np.array([data[i].get("label", 9) for i in holdout_indices])

        y_pred = model.predict(X_holdout)

        metrics = self._compute_metrics(y_holdout, y_pred)

        # Per-family breakdown
        per_family = {}
        for fam in holdout_families:
            if fam in self.family_labels:
                fam_idx = self.family_labels.index(fam)
                mask = (y_holdout == fam_idx)
                if mask.sum() > 0:
                    per_family[fam] = self._compute_metrics(
                        y_holdout[mask], y_pred[mask]
                    )

        return {
            "holdout_families": holdout_families,
            "aggregate_metrics": metrics,
            "per_family_metrics": per_family,
            "support": len(holdout_indices),
            "scenario": "zero_day_simulation",
        }

    def evaluate_temporal_splits(self, model: Any, data: List[Dict],
                                  time_field: str = "timestamp",
                                  n_splits: int = 5) -> Dict[str, Any]:
        """
        Evaluate model using temporal splits (older samples train, newer test).

        Args:
            model: Model to evaluate
            data: Samples with timestamp field
            time_field: Field name for timestamp
            n_splits: Number of temporal splits

        Returns:
            Temporal evaluation results
        """
        # Sort by timestamp
        sorted_data = sorted(enumerate(data), key=lambda x: x[1].get(time_field, 0))
        indices = [i for i, _ in sorted_data]

        split_size = len(indices) // n_splits
        results = []

        for i in range(n_splits):
            train_end = (i + 1) * split_size
            test_start = train_end
            test_end = min(test_start + split_size, len(indices))

            if test_start >= len(indices):
                break

            train_idx = indices[:train_end]
            test_idx = indices[test_start:test_end]

            X_train = np.stack([data[i]["features"] for i in train_idx])
            y_train = np.array([data[i].get("label", 9) for i in train_idx])
            X_test = np.stack([data[i]["features"] for i in test_idx])
            y_test = np.array([data[i].get("label", 9) for i in test_idx])

            if hasattr(model, 'fit'):
                model.fit(X_train, y_train)

            y_pred = model.predict(X_test)
            metrics = self._compute_metrics(y_test, y_pred)

            results.append({
                "split": i,
                "train_size": len(train_idx),
                "test_size": len(test_idx),
                "metrics": metrics,
            })

        # Aggregate
        all_y_test = np.concatenate([np.array([data[i].get("label", 9) for i in indices[(j+1)*split_size:min((j+2)*split_size, len(indices))]]) for j in range(n_splits) if (j+1)*split_size < len(indices)])
        all_y_pred = np.concatenate([model.predict(np.stack([data[i]["features"] for i in indices[(j+1)*split_size:min((j+2)*split_size, len(indices))]])) for j in range(n_splits) if (j+1)*split_size < len(indices)])

        return {
            "per_split": results,
            "aggregate_metrics": self._compute_metrics(all_y_test, all_y_pred) if len(all_y_test) > 0 else {},
            "scenario": "temporal_generalization",
        }

    def _compute_metrics(self, y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
        """Compute classification metrics."""
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

        metrics = {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision_macro": float(precision_score(y_true, y_pred, average='macro', zero_division=0)),
            "recall_macro": float(recall_score(y_true, y_pred, average='macro', zero_division=0)),
            "f1_macro": float(f1_score(y_true, y_pred, average='macro', zero_division=0)),
            "precision_weighted": float(precision_score(y_true, y_pred, average='weighted', zero_division=0)),
            "recall_weighted": float(recall_score(y_true, y_pred, average='weighted', zero_division=0)),
            "f1_weighted": float(f1_score(y_true, y_pred, average='weighted', zero_division=0)),
        }

        # Per-class metrics
        for i, fam in enumerate(self.family_labels):
            mask = (y_true == i)
            if mask.sum() > 0:
                metrics[f"{fam}_precision"] = float(precision_score(y_true == i, y_pred == i, zero_division=0))
                metrics[f"{fam}_recall"] = float(recall_score(y_true == i, y_pred == i, zero_division=0))
                metrics[f"{fam}_f1"] = float(f1_score(y_true == i, y_pred == i, zero_division=0))

        return metrics

    def _confusion_matrix(self, y_true: np.ndarray, y_pred: np.ndarray,
                          n_classes: int) -> np.ndarray:
        """Compute confusion matrix."""
        cm = np.zeros((n_classes, n_classes), dtype=int)
        for t, p in zip(y_true, y_pred):
            if t < n_classes and p < n_classes:
                cm[t, p] += 1
        return cm

    def _analyze_family_generalization(self, per_family: List[EvaluationResult]) -> Dict[str, float]:
        """Analyze how well model generalizes across families."""
        if not per_family:
            return {}

        # Group by family
        family_metrics = defaultdict(list)
        for res in per_family:
            family_metrics[res.family].append(res.metrics)

        # Average metrics per family
        avg_per_family = {}
        for fam, metrics_list in family_metrics.items():
            avg_per_family[fam] = {
                k: np.mean([m[k] for m in metrics_list if k in m])
                for k in metrics_list[0].keys()
            }

        # Generalization gap: performance on held-out families vs overall
        all_f1 = [m.metrics.get("f1_macro", 0) for m in per_family]
        return {
            "mean_f1_heldout": float(np.mean(all_f1)),
            "std_f1_heldout": float(np.std(all_f1)),
            "min_f1_heldout": float(np.min(all_f1)),
            "max_f1_heldout": float(np.max(all_f1)),
            "per_family_f1": {fam: m.get("f1_macro", 0) for fam, m in avg_per_family.items()},
        }

    def _generate_recommendations(self, aggregate: Dict, gen_analysis: Dict) -> List[str]:
        """Generate recommendations based on evaluation."""
        recs = []

        if aggregate.get("f1_macro", 0) < 0.7:
            recs.append("Overall F1 below 0.7: Consider more training data or feature engineering")

        if gen_analysis.get("std_f1_heldout", 0) > 0.2:
            recs.append("High variance across families: Model may overfit to specific families")

        if gen_analysis.get("min_f1_heldout", 1) < 0.3:
            recs.append("Some families poorly detected: Add family-specific features or samples")

        if aggregate.get("precision_macro", 0) < aggregate.get("recall_macro", 0):
            recs.append("Precision lower than recall: High false positive rate, adjust threshold")

        if not recs:
            recs.append("Model shows good family-disjoint generalization")

        return recs

    def generate_report(self, result: FamilyDisjointResult) -> str:
        """Generate human-readable evaluation report."""
        lines = [
            "Family-Disjoint Cross-Validation Report",
            "=" * 50,
            "",
            "Aggregate Metrics:",
            "-" * 30,
        ]

        for metric, value in result.aggregate_metrics.items():
            lines.append(f"  {metric}: {value:.4f}")

        lines.extend([
            "",
            "Family Generalization:",
            "-" * 30,
        ])

        for key, value in result.family_generalization.items():
            if isinstance(value, dict):
                lines.append(f"  {key}:")
                for k, v in value.items():
                    lines.append(f"    {k}: {v:.4f}")
            else:
                lines.append(f"  {key}: {value:.4f}")

        lines.extend([
            "",
            "Per-Family Results (Held-Out):",
            "-" * 30,
        ])

        for fam_res in result.per_family:
            lines.append(f"  {fam_res.family}:")
            lines.append(f"    Support: {fam_res.support}")
            for metric, value in fam_res.metrics.items():
                if metric in ["accuracy", "f1_macro", "precision_macro", "recall_macro"]:
                    lines.append(f"    {metric}: {value:.4f}")

        lines.extend([
            "",
            "Recommendations:",
            "-" * 30,
        ])

        for rec in result.recommendations:
            lines.append(f"  - {rec}")

        return "\n".join(lines)


_family_evaluator_instance = None


def get_family_evaluator(config: Dict = None) -> FamilyDisjointEvaluator:
    """Get singleton family evaluator instance."""
    global _family_evaluator_instance
    if _family_evaluator_instance is None:
        _family_evaluator_instance = FamilyDisjointEvaluator(config)
    return _family_evaluator_instance