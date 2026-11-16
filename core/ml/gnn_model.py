"""
Graph Neural Network Models for APKStudioAI 2.1
Code similarity, malware family classification, and function-level analysis.
"""
import json
import pickle
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import numpy as np
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("gnn_model")


@dataclass
class ModelConfig:
    """Configuration for GNN model."""
    hidden_dim: int = 128
    num_layers: int = 3
    num_classes: int = 10  # malware families + benign
    dropout: float = 0.3
    learning_rate: float = 0.001
    weight_decay: float = 1e-4
    max_epochs: int = 100
    early_stopping_patience: int = 10
    device: str = "cpu"


@dataclass
class TrainingResult:
    """Result of model training."""
    model_path: str
    train_loss: List[float]
    val_loss: List[float]
    train_acc: List[float]
    val_acc: List[float]
    best_epoch: int
    test_metrics: Dict[str, float]


class GNNModel:
    """
    Graph Neural Network for malware classification and code similarity.
    Uses a simplified implementation that can work with or without PyTorch Geometric.
    """

    def __init__(self, config: ModelConfig = None):
        self.config = config or ModelConfig()
        self.model = None
        self.is_trained = False
        self.feature_dim = None
        self._model_path = None

        # Try to import PyTorch
        self.torch_available = False
        self.pyg_available = False
        try:
            import torch
            self.torch = torch
            self.torch_available = True
            try:
                import torch_geometric
                self.pyg_available = True
            except ImportError:
                pass
        except ImportError:
            pass

        if not self.torch_available:
            logger.warning("gnn_pytorch_not_available", message="PyTorch not available, using fallback")

    def _build_model(self, input_dim: int):
        """Build the GNN model architecture."""
        if not self.torch_available:
            return None

        import torch.nn as nn
        import torch.nn.functional as F
        torch = self.torch

        class SimpleGNN(nn.Module):
            def __init__(self, input_dim, hidden_dim, num_layers, num_classes, dropout):
                super().__init__()
                self.num_layers = num_layers
                self.dropout = dropout
                self.torch = torch

                # Input projection
                self.input_proj = nn.Linear(input_dim, hidden_dim)

                # GNN layers (using simple message passing)
                self.gnn_layers = nn.ModuleList([
                    nn.Linear(hidden_dim, hidden_dim) for _ in range(num_layers)
                ])

                # Output layers
                self.classifier = nn.Sequential(
                    nn.Linear(hidden_dim, hidden_dim // 2),
                    nn.ReLU(),
                    nn.Dropout(dropout),
                    nn.Linear(hidden_dim // 2, num_classes)
                )

            def forward(self, x, edge_index, batch=None):
                # x: [num_nodes, input_dim]
                # edge_index: [2, num_edges]
                h = self.input_proj(x)

                # Simple message passing
                for i, layer in enumerate(self.gnn_layers):
                    # Aggregate neighbors
                    row, col = edge_index
                    agg = torch.zeros_like(h)
                    agg.index_add_(0, row, h[col])
                    # Normalize by degree
                    deg = torch.bincount(row, minlength=h.size(0)).float().clamp(min=1)
                    agg = agg / deg.unsqueeze(1)

                    h = layer(h + agg)
                    h = F.relu(h)
                    h = F.dropout(h, p=self.dropout, training=self.training)

                # Graph-level pooling (mean pooling per graph)
                if batch is not None:
                    out = torch.zeros(batch.max().item() + 1, h.size(1), device=h.device)
                    out.index_add_(0, batch, h)
                    batch_counts = torch.bincount(batch).float().clamp(min=1)
                    out = out / batch_counts.unsqueeze(1)
                else:
                    out = h.mean(dim=0, keepdim=True)

                return self.classifier(out)

        self.model = SimpleGNN(
            input_dim, self.config.hidden_dim,
            self.config.num_layers, self.config.num_classes,
            self.config.dropout
        )
        self.model.to(self.config.device)
        return self.model

    def prepare_graph_data(self, feature_vectors: List[np.ndarray],
                           edges: List[Tuple[int, int]] = None,
                           labels: List[int] = None) -> Dict:
        """Prepare graph data for training."""
        if not self.torch_available:
            return {"features": feature_vectors, "edges": edges or [], "labels": labels or []}

        # Stack features
        x = self.torch.tensor(np.stack(feature_vectors), dtype=self.torch.float32)

        # Create edges (fully connected if none provided)
        if edges is None:
            n = len(feature_vectors)
            row = []
            col = []
            for i in range(n):
                for j in range(n):
                    if i != j:
                        row.append(i)
                        col.append(j)
            edge_index = self.torch.tensor([row, col], dtype=self.torch.long)
        else:
            edge_index = self.torch.tensor(edges, dtype=self.torch.long).t()

        # Labels
        y = self.torch.tensor(labels, dtype=self.torch.long) if labels else None

        # Batch (each sample is its own graph for now)
        batch = self.torch.arange(len(feature_vectors))

        return {
            "x": x,
            "edge_index": edge_index,
            "y": y,
            "batch": batch,
        }

    def train(self, train_data: List[Dict], val_data: List[Dict] = None,
              family_labels: List[str] = None) -> TrainingResult:
        """Train the GNN model."""
        if not self.torch_available:
            logger.warning("gnn_train_fallback", message="Using sklearn fallback for training")
            return self._train_fallback(train_data, val_data, family_labels)

        import torch
        import torch.nn as nn
        import torch.optim as optim

        # Extract features and labels
        train_features = [d["features"] for d in train_data]
        train_labels = [d.get("label", 0) for d in train_data]

        self.feature_dim = len(train_features[0])
        self._build_model(self.feature_dim)

        # Prepare data
        train_graph = self.prepare_graph_data(train_features, labels=train_labels)

        val_graph = None
        if val_data:
            val_features = [d["features"] for d in val_data]
            val_labels = [d.get("label", 0) for d in val_data]
            val_graph = self.prepare_graph_data(val_features, labels=val_labels)

        # Optimizer
        optimizer = optim.Adam(
            self.model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay
        )
        criterion = nn.CrossEntropyLoss()

        # Training loop
        train_losses, val_losses = [], []
        train_accs, val_accs = [], []
        best_val_loss = float('inf')
        best_epoch = 0
        patience_counter = 0

        for epoch in range(self.config.max_epochs):
            self.model.train()
            optimizer.zero_grad()

            out = self.model(train_graph["x"], train_graph["edge_index"], train_graph["batch"])
            loss = criterion(out, train_graph["y"])
            loss.backward()
            optimizer.step()

            # Metrics
            train_losses.append(loss.item())
            train_acc = (out.argmax(dim=1) == train_graph["y"]).float().mean().item()
            train_accs.append(train_acc)

            # Validation
            if val_graph:
                self.model.eval()
                with torch.no_grad():
                    val_out = self.model(val_graph["x"], val_graph["edge_index"], val_graph["batch"])
                    val_loss = criterion(val_out, val_graph["y"])
                    val_losses.append(val_loss.item())
                    val_acc = (val_out.argmax(dim=1) == val_graph["y"]).float().mean().item()
                    val_accs.append(val_acc)

                    # Early stopping
                    if val_loss < best_val_loss:
                        best_val_loss = val_loss
                        best_epoch = epoch
                        patience_counter = 0
                        # Save best model
                        self._save_checkpoint()
                    else:
                        patience_counter += 1
                        if patience_counter >= self.config.early_stopping_patience:
                            logger.info("gnn_early_stopping", epoch=epoch, best_epoch=best_epoch)
                            break

            if epoch % 10 == 0:
                logger.debug("gnn_train_epoch", epoch=epoch, loss=loss.item(), acc=train_acc)

        self.is_trained = True

        # Load best model
        self._load_checkpoint()

        # Test metrics
        test_metrics = {}
        if val_graph:
            self.model.eval()
            with torch.no_grad():
                val_out = self.model(val_graph["x"], val_graph["edge_index"], val_graph["batch"])
                test_metrics = {
                    "accuracy": (val_out.argmax(dim=1) == val_graph["y"]).float().mean().item(),
                    "loss": criterion(val_out, val_graph["y"]).item(),
                }

        return TrainingResult(
            model_path=self._model_path or "",
            train_loss=train_losses,
            val_loss=val_losses,
            train_acc=train_accs,
            val_acc=val_accs,
            best_epoch=best_epoch,
            test_metrics=test_metrics,
        )

    def _train_fallback(self, train_data: List[Dict], val_data: List[Dict],
                        family_labels: List[str]) -> TrainingResult:
        """Fallback training using scikit-learn."""
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import accuracy_score, classification_report
        except ImportError:
            logger.error("gnn_sklearn_not_available")
            return TrainingResult("", [], [], [], [], 0, {})

        X_train = np.stack([d["features"] for d in train_data])
        y_train = np.array([d.get("label", 0) for d in train_data])

        X_val = np.stack([d["features"] for d in val_data]) if val_data else None
        y_val = np.array([d.get("label", 0) for d in val_data]) if val_data else None

        # Train Random Forest
        rf = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
        rf.fit(X_train, y_train)

        # Save model
        model_path = Path(self.config.device).parent / "gnn_fallback_model.pkl" if hasattr(self.config, 'device') else Path("./gnn_fallback_model.pkl")
        model_path = Path("./gnn_fallback_model.pkl")
        with open(model_path, "wb") as f:
            pickle.dump(rf, f)

        self.model = rf
        self.is_trained = True
        self._model_path = str(model_path)

        # Metrics
        train_acc = accuracy_score(y_train, rf.predict(X_train))
        test_metrics = {"accuracy": train_acc}

        if X_val is not None:
            val_acc = accuracy_score(y_val, rf.predict(X_val))
            test_metrics["val_accuracy"] = val_acc

        return TrainingResult(
            model_path=str(model_path),
            train_loss=[], val_loss=[],
            train_acc=[train_acc], val_acc=[test_metrics.get("val_accuracy", 0)],
            best_epoch=0,
            test_metrics=test_metrics,
        )

    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """Predict malware family for a feature vector."""
        if not self.is_trained or self.model is None:
            return {"error": "Model not trained"}

        if self.torch_available and hasattr(self.model, 'eval'):
            import torch
            self.model.eval()
            with torch.no_grad():
                x = torch.tensor(features).unsqueeze(0).float().to(self.config.device)
                # For single sample, create dummy edge_index and batch
                edge_index = torch.tensor([[0], [0]], dtype=torch.long).to(self.config.device)
                batch = torch.tensor([0], dtype=torch.long).to(self.config.device)
                out = self.model(x, edge_index, batch)
                probs = torch.softmax(out, dim=1).cpu().numpy()[0]
                pred = int(out.argmax(dim=1).item())
        else:
            # Sklearn fallback
            probs = self.model.predict_proba(features.reshape(1, -1))[0]
            pred = int(self.model.predict(features.reshape(1, -1))[0])

        family_names = [
            "banking_trojan", "spyware", "rat", "dropper", "ransomware",
            "adware", "sms_trojan", "cryptominer", "root_exploit", "benign",
        ]

        return {
            "predicted_family": family_names[pred] if pred < len(family_names) else "unknown",
            "predicted_index": pred,
            "confidence": float(probs[pred]),
            "all_probabilities": {
                family_names[i]: float(probs[i]) for i in range(min(len(family_names), len(probs)))
            },
        }

    def predict_batch(self, features_list: List[np.ndarray]) -> List[Dict]:
        """Predict for multiple samples."""
        return [self.predict(f) for f in features_list]

    def get_embeddings(self, features: np.ndarray) -> np.ndarray:
        """Get graph embeddings for similarity search."""
        if not self.is_trained or self.model is None:
            return np.array([])

        if self.torch_available and hasattr(self.model, 'eval'):
            import torch
            self.model.eval()
            with torch.no_grad():
                x = torch.tensor(features).unsqueeze(0).float().to(self.config.device)
                edge_index = torch.tensor([[0], [0]], dtype=torch.long).to(self.config.device)
                batch = torch.tensor([0], dtype=torch.long).to(self.config.device)

                # Get embeddings from penultimate layer
                h = self.model.input_proj(x)
                for layer in self.model.gnn_layers:
                    row, col = edge_index
                    agg = torch.zeros_like(h)
                    agg.index_add_(0, row, h[col])
                    deg = torch.bincount(row, minlength=h.size(0)).float().clamp(min=1)
                    agg = agg / deg.unsqueeze(1)
                    h = layer(h + agg)
                    h = torch.relu(h)

                return h.mean(dim=0).cpu().numpy()
        else:
            # For sklearn, use feature importances as pseudo-embeddings
            return features

    def _save_checkpoint(self):
        """Save model checkpoint."""
        if not self.torch_available:
            return

        import torch
        if self._model_path is None:
            self._model_path = "./gnn_model_best.pt"
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'config': self.config,
            'feature_dim': self.feature_dim,
        }, self._model_path, _use_new_zipfile_serialization=False)

    def _load_checkpoint(self):
        """Load model checkpoint."""
        if not self.torch_available or self._model_path is None:
            return

        import torch
        checkpoint = torch.load(self._model_path, map_location=self.config.device, weights_only=False)
        self.model.load_state_dict(checkpoint['model_state_dict'])

    def save(self, path: str):
        """Save model to disk."""
        if self.torch_available and hasattr(self.model, 'state_dict'):
            import torch
            torch.save({
                'model_state_dict': self.model.state_dict(),
                'config': self.config,
                'feature_dim': self.feature_dim,
            }, path)
        else:
            import pickle
            with open(path, "wb") as f:
                pickle.dump(self.model, f)

    @classmethod
    def load(cls, path: str, config: ModelConfig = None) -> 'GNNModel':
        """Load model from disk."""
        model = cls(config)
        if model.torch_available:
            import torch
            checkpoint = torch.load(path, map_location=model.config.device)
            model.config = checkpoint['config']
            model.feature_dim = checkpoint['feature_dim']
            model._build_model(model.feature_dim)
            model.model.load_state_dict(checkpoint['model_state_dict'])
            model.is_trained = True
        else:
            import pickle
            with open(path, "rb") as f:
                model.model = pickle.load(f)
            model.is_trained = True
        return model


_gnn_model_instance = None


def get_gnn_model(config: ModelConfig = None) -> GNNModel:
    """Get singleton GNN model instance."""
    global _gnn_model_instance
    if _gnn_model_instance is None:
        _gnn_model_instance = GNNModel(config)
    return _gnn_model_instance