"""
Tests for ML & Graph Intelligence module.
"""
import pytest
import numpy as np
from core.ml import (
    get_feature_extractor, get_gnn_model,
    get_explainability_engine, get_family_evaluator,
    FeatureExtractor, GNNModel, ExplainabilityEngine, FamilyDisjointEvaluator
)
from core.ml.family_evaluator import FamilyDisjointResult, EvaluationResult
from core.ml.gnn_model import TrainingResult
from core.ml.explainability import ExplanationResult
from sklearn.ensemble import RandomForestClassifier


class TestFeatureExtractor:
    """Test feature extraction."""

    def test_extractor_initialization(self):
        """Test feature extractor initializes correctly."""
        extractor = get_feature_extractor()
        assert isinstance(extractor, FeatureExtractor)
        assert len(extractor.DANGEROUS_PERMISSIONS) == 17
        assert len(extractor.API_CATEGORIES) == 14
        assert len(extractor.FAMILY_LABELS) == 10

    def test_extract_manifest_features(self):
        """Test manifest feature extraction."""
        extractor = get_feature_extractor()
        manifest = {
            "debuggable": True,
            "uses_cleartext_traffic": False,
            "allow_backup": True,
            "shared_user_id": "com.test.shared",
            "activities": [{"name": "A1", "exported": True}, {"name": "A2", "exported": False}],
            "services": [{"name": "S1", "exported": True}],
            "receivers": [],
            "providers": [{"name": "P1", "exported": True, "permission": "perm"}],
            "min_sdk_version": 21,
            "target_sdk_version": 33,
            "version_code": 100,
        }
        features, names = extractor._extract_manifest_features(manifest)
        assert len(features) == len(names)
        assert features[0] == 1.0  # debuggable
        assert features[1] == 0.0  # cleartext
        assert "manifest_debuggable" in names
        assert "manifest_activities_count" in names

    def test_extract_permission_features(self):
        """Test permission feature extraction."""
        extractor = get_feature_extractor()
        manifest = {
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
            ]
        }
        features, names = extractor._extract_permission_features(manifest)
        assert len(features) == len(names)
        assert features[-2] == 3  # total count
        # INTERNET is also in dangerous list, so 3 dangerous permissions
        assert features[-1] == 3

    def test_extract_api_features(self):
        """Test API call feature extraction."""
        extractor = get_feature_extractor()
        dex = {
            "api_calls": [
                {"call": "LocationManager.getLastKnownLocation"},
                {"call": "HttpURLConnection"},
                {"call": "DexClassLoader.loadClass"},
                {"call": "Cipher.getInstance"},
                {"call": "Runtime.exec"},
            ]
        }
        features, names = extractor._extract_api_features(dex)
        assert len(features) == len(names)
        assert "api_location_rate" in names
        assert "api_network_rate" in names
        assert "api_dynamic_loading_rate" in names
        assert "api_execution_rate" in names

    def test_extract_string_features(self):
        """Test string feature extraction."""
        extractor = get_feature_extractor()
        strings = {
            "all_strings": ["http://example.com", "password", "api_key", "secret", "normal"],
            "decoded_strings": [{"decoded": "hidden_password"}],
            "urls": [{"url": "http://example.com"}],
            "domains": [{"domain": "example.com"}],
            "ips": ["192.168.1.1"],
            "firebase": ["myapp.firebaseio.com"],
            "telegram_bots": ["bot123"],
        }
        features, names = extractor._extract_string_features(strings)
        assert len(features) == len(names)
        assert "str_total_count_norm" in names
        assert "str_suspicious_password" in names
        assert "str_suspicious_api_key" in names

    def test_extract_network_features(self):
        """Test network feature extraction."""
        extractor = get_feature_extractor()
        network = {
            "urls": [{"url": "http://example.com"}, {"url": "https://secure.com"}],
            "domains": [{"domain": "malicious.top"}, {"domain": "normal.com"}],
            "ips": ["1.2.3.4"],
            "certificates": [{"subject": "CN=Test"}],
            "c2_config": [{"host": "c2.bad.com"}],
        }
        features, names = extractor._extract_network_features(network)
        assert len(features) == len(names)
        assert "net_https_ratio" in names
        assert "net_suspicious_tld_top" in names

    def test_extract_behavior_features(self):
        """Test behavior feature extraction."""
        extractor = get_feature_extractor()
        behavior = {
            "detected_behaviors": [
                {"category": "surveillance", "confidence": 90},
                {"category": "persistence", "confidence": 80},
            ]
        }
        features, names = extractor._extract_behavior_features(behavior)
        assert len(features) == len(names)
        assert "beh_surveillance_confidence" in names
        assert "beh_persistence_confidence" in names
        assert features[0] == 0.9  # surveillance confidence

    def test_extract_structural_features(self):
        """Test structural feature extraction."""
        extractor = get_feature_extractor()
        archive = {
            "file_size_mb": 25.5,
            "native_libs_count": 3,
            "native_architectures": ["arm64-v8a", "armeabi-v7a"],
            "certificates": [{"subject": "CN=Test"}],
            "files": [{"entropy": 6.5}, {"entropy": 7.2}],
        }
        dex = {"dex_count": 2, "total_classes": 500, "total_methods": 3000}
        features, names = extractor._extract_structural_features(archive, dex)
        assert len(features) == len(names)
        assert "struct_file_size_norm" in names
        assert "struct_dex_count_norm" in names

    def test_extract_advanced_static_features(self):
        """Test advanced static feature extraction."""
        extractor = get_feature_extractor()
        advanced = {
            "call_graph": {
                "statistics": {"nodes": 1000, "edges": 5000, "sensitive_apis": 15, "entry_points": 20},
                "sensitive_paths": [["a", "b"], ["c", "d"]],
            },
            "taint": {"statistics": {"tainted_methods": 25, "source_sink_paths": 8}},
            "icc": {"statistics": {"total_icc_edges": 12, "exported_components": 6, "unprotected_exported": 5}},
            "dynamic_loading": {"load_sites": [{"loader": "DexClassLoader"}]},
            "reflection": {"total_reflection_calls": 5, "resolved_count": 3},
            "obfuscation": {"risk_score": 45},
            "yara": {"matches": [{"rule": "TEST"}]},
        }
        features, names = extractor._extract_advanced_static_features(advanced)
        assert len(features) == len(names)
        assert "adv_cg_nodes_norm" in names
        assert "adv_obfu_risk_norm" in names

    def test_full_extraction(self):
        """Test full feature extraction pipeline."""
        extractor = get_feature_extractor()
        sample_data = {
            "apk_path": "/test/sample.apk",
            "manifest_analysis": {
                "package": "com.test", "debuggable": False,
                "activities": [], "services": [], "receivers": [], "providers": [],
                "permissions": ["android.permission.INTERNET"],
                "min_sdk_version": 21, "target_sdk_version": 33, "version_code": 1,
            },
            "dex_analysis": {"dex_count": 1, "total_classes": 50, "total_methods": 200, "api_calls": []},
            "string_analysis": {"all_strings": [], "decoded_strings": [], "urls": [], "domains": [], "ips": [], "firebase": [], "telegram_bots": []},
            "network_analysis": {"urls": [], "domains": [], "ips": [], "certificates": [], "c2_config": []},
            "behavior_analysis": {"detected_behaviors": []},
            "archive_analysis": {"file_size_mb": 5, "native_libs_count": 0, "native_architectures": [], "certificates": [], "files": []},
            "advanced_static": {},
        }
        fv = extractor.extract(sample_data)
        assert fv.features.shape[0] > 0
        assert len(fv.feature_names) == fv.features.shape[0]
        assert "total_features" in fv.metadata


class TestGNNModel:
    """Test GNN model."""

    def test_model_initialization(self):
        """Test GNN model initializes."""
        model = get_gnn_model()
        assert isinstance(model, GNNModel)
        assert model.config.hidden_dim == 128
        assert model.config.num_classes == 10

    def test_prepare_graph_data(self):
        """Test graph data preparation."""
        model = get_gnn_model()
        features = [np.random.randn(20) for _ in range(5)]
        data = model.prepare_graph_data(features)
        assert "x" in data or "features" in data

    def test_fallback_training(self):
        """Test fallback training with sklearn."""
        model = get_gnn_model()
        train_data = [{"features": np.random.randn(20), "label": i % 3} for i in range(30)]
        val_data = [{"features": np.random.randn(20), "label": i % 3} for i in range(10)]

        result = model.train(train_data, val_data)
        assert isinstance(result, TrainingResult)
        assert model.is_trained
        assert result.test_metrics.get("accuracy", 0) >= 0


class TestExplainabilityEngine:
    """Test explainability engine."""

    def test_engine_initialization(self):
        """Test engine initializes."""
        engine = get_explainability_engine()
        assert isinstance(engine, ExplainabilityEngine)

    def test_fallback_explanation(self):
        """Test fallback explanation."""
        engine = get_explainability_engine()
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        X = np.random.randn(50, 10)
        y = np.random.randint(0, 2, 50)
        model.fit(X, y)

        features = np.random.randn(10)
        feature_names = [f"feat_{i}" for i in range(10)]

        result = engine.explain_shap(model, features, feature_names, background_data=X[:10])
        assert isinstance(result, ExplanationResult)
        assert result.method in ["shap", "shap_fallback"]
        assert len(result.feature_importance) > 0

    def test_lime_explanation(self):
        """Test LIME explanation."""
        engine = get_explainability_engine()
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        X = np.random.randn(50, 10)
        y = np.random.randint(0, 2, 50)
        model.fit(X, y)

        features = np.random.randn(10)
        feature_names = [f"feat_{i}" for i in range(10)]

        result = engine.explain_lime(model, features, feature_names, training_data=X)
        assert isinstance(result, ExplanationResult)
        assert result.method in ["lime", "lime_fallback"]

    def test_generate_report(self):
        """Test report generation."""
        engine = get_explainability_engine()
        from core.ml.explainability import ExplanationResult
        result = ExplanationResult(
            feature_importance={"feat_1": 0.9, "feat_2": 0.5, "feat_3": 0.1},
            method="shap",
            prediction=0.8,
            base_value=0.5,
        )
        report = engine.generate_report(result, ["feat_1", "feat_2", "feat_3"], top_k=3)
        assert "Model Explanation Report" in report
        assert "feat_1" in report


class TestFamilyDisjointEvaluator:
    """Test family-disjoint evaluator."""

    def test_evaluator_initialization(self):
        """Test evaluator initializes."""
        evaluator = get_family_evaluator()
        assert isinstance(evaluator, FamilyDisjointEvaluator)
        assert len(evaluator.MALWARE_FAMILIES) == 10

    def test_create_family_disjoint_splits(self):
        """Test split creation."""
        evaluator = get_family_evaluator()
        data = []
        for fam_idx in range(10):
            for _ in range(5):
                data.append({"features": np.random.randn(20), "label": fam_idx})

        splits = evaluator.create_family_disjoint_splits(data, n_splits=3, test_families_per_split=2)
        assert len(splits) == 3
        for split in splits:
            assert "train_indices" in split
            assert "test_indices" in split
            assert "test_families" in split
            assert len(split["train_indices"]) > 0
            assert len(split["test_indices"]) > 0

    def test_evaluate_family_disjoint(self):
        """Test family-disjoint evaluation."""
        evaluator = get_family_evaluator()
        model = RandomForestClassifier(n_estimators=20, random_state=42)

        data = []
        for fam_idx in range(10):
            for _ in range(10):
                data.append({"features": np.random.randn(20), "label": fam_idx})

        result = evaluator.evaluate_family_disjoint(model, data, n_splits=3)
        assert isinstance(result, FamilyDisjointResult)
        assert "f1_macro" in result.aggregate_metrics
        assert len(result.per_family) > 0

    def test_holdout_evaluation(self):
        """Test holdout family evaluation."""
        evaluator = get_family_evaluator()
        model = RandomForestClassifier(n_estimators=20, random_state=42)
        model.fit(np.random.randn(50, 20), np.random.randint(0, 10, 50))

        data = []
        for fam_idx in range(10):
            for _ in range(5):
                data.append({"features": np.random.randn(20), "label": fam_idx})

        result = evaluator.evaluate_holdout_families(model, data, ["rat", "spyware"])
        assert "holdout_families" in result
        assert "aggregate_metrics" in result
        assert result["scenario"] == "zero_day_simulation"

    def test_generate_report(self):
        """Test report generation."""
        evaluator = get_family_evaluator()
        from core.ml.family_evaluator import FamilyDisjointResult, EvaluationResult
        result = FamilyDisjointResult(
            per_family=[EvaluationResult(
                family="rat",
                metrics={"f1_macro": 0.8, "accuracy": 0.85},
                confusion_matrix=[[1, 0], [0, 1]],
                support=10,
                split_info={},
            )],
            aggregate_metrics={"f1_macro": 0.75, "accuracy": 0.8},
            family_generalization={"mean_f1_heldout": 0.7},
            recommendations=["Good generalization"],
        )
        report = evaluator.generate_report(result)
        assert "Family-Disjoint Cross-Validation Report" in report
        assert "rat" in report


