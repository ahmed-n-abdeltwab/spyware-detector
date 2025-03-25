import os
import logging
import time
import numpy as np
from model_management.downloader import ModelDownloader
import joblib
from pathlib import Path

# Configure logging at the start of the file
log_dir = Path(__file__).parent.parent / "logs"

log_dir.mkdir(exist_ok=True, parents=True)
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_dir / "model_manager.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("model_manager")


class ModelManager:
    def __init__(self, model_url=None):
        """
        Initialize the enhanced model manager with support for:
        - Model
        - Scaler
        - Feature selector
        - Metadata and metrics
        - Feature structure information
        """
        self.model_url = model_url or os.getenv(
            "MODEL_URL",
            "https://github.com/ahmed-n-abdeltwab/spyware-detector-training/releases/latest/download/model_release.tar.gz",
        )
        self.model_refresh_interval = int(os.getenv("MODEL_REFRESH_INTERVAL", "3600"))
        self.downloader = ModelDownloader(
            self.model_url, models_dir="models", cache_time=self.model_refresh_interval
        )

        # Model components
        self.model = None
        self.scaler = None
        self.feature_selector = None
        self.metadata = {}
        self.metrics = {}
        self.package_info = {}
        self.selected_features = []
        self.feature_structure = {}
        self.model_loaded = False
        self.last_load_time = 0

    def load_model(self, force=False):
        """Load all model components into memory"""
        current_time = time.time()
        if (
            not force
            and self.model_loaded
            and (current_time - self.last_load_time) < self.model_refresh_interval
        ):
            return True

        try:
            if not self.downloader.ensure_model_available():
                logger.error("Failed to ensure model availability")
                return False

            # Load main model
            model_path = self.downloader.get_file_path("model.pkl")
            if not model_path.exists():
                logger.error("Model file not found")
                return False
            self.model = joblib.load(model_path)

            # Load scaler
            scaler_path = self.downloader.get_file_path("scaler.pkl")
            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
                logger.info("Scaler loaded successfully")
            else:
                logger.warning("No scaler found in model package")

            # Load feature selector
            selector_path = self.downloader.get_file_path("feature_selector.pkl")
            if selector_path.exists():
                self.feature_selector = joblib.load(selector_path)
                logger.info("Feature selector loaded successfully")
            else:
                logger.warning("No feature selector found in model package")

            # Load metadata files
            self.metadata = self.downloader.load_json_file("metadata.json") or {}
            self.metrics = self.downloader.load_json_file("metrics.json") or {}
            self.package_info = (
                self.downloader.load_json_file("package_info.json") or {}
            )
            self.selected_features = (
                self.downloader.load_json_file("selected_features.json") or []
            )
            self.feature_structure = (
                self.downloader.load_json_file("feature_structure.json") or {}
            )

            # Validate minimum requirements
            if not self.model:
                logger.error("No model loaded")
                return False

            self.model_loaded = True
            self.last_load_time = current_time
            logger.info("All model components loaded successfully")
            return True

        except Exception as e:
            logger.error(f"Error loading model components: {str(e)}")
            self._reset_state()
            return False

    def _reset_state(self):
        """Reset all loaded components"""
        self.model = None
        self.scaler = None
        self.feature_selector = None
        self.metadata = {}
        self.metrics = {}
        self.package_info = {}
        self.selected_features = []
        self.feature_structure = {}
        self.model_loaded = False

    def get_model_info(self):
        """Get comprehensive information about loaded components"""
        if not self.model_loaded:
            self.load_model()

        return {
            "loaded": self.model_loaded,
            "model_type": str(type(self.model)) if self.model else None,
            "scaler_loaded": self.scaler is not None,
            "feature_selector_loaded": self.feature_selector is not None,
            "metadata": self.metadata,
            "metrics": self.metrics,
            "package_info": self.package_info,
            "selected_features_count": len(self.selected_features),
            "feature_structure": self.feature_structure,
            "last_load_time": self.last_load_time,
            "refresh_interval": self.model_refresh_interval,
        }

    def preprocess_features(self, features):
        """
        Preprocess features using the loaded scaler and feature selector.
        Returns numpy array of processed features.
        """
        if not isinstance(features, np.ndarray):
            features = np.array(features, dtype=np.float32)

        # Reshape to (1, n_features) if flat vector
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        # Apply feature selection if available
        if self.feature_selector:
            try:
                return self.feature_selector.transform(features)
            except ValueError as e:
                logger.error(
                    f"Feature selection shape mismatch. Expected {self.feature_selector.n_features_in_} features, got {features.shape[1]}"
                )
                raise

        # Apply scaling if available
        if self.scaler is not None:
            try:
                features = self.scaler.transform(features.reshape(1, -1))
            except Exception as e:
                logger.error(f"Feature scaling failed: {str(e)}")
                raise RuntimeError("Feature scaling failed")

        return features

    def predict(self, features):
        """Make prediction using the complete pipeline"""
        if not self.model_loaded:
            self.load_model()

        if self.model is None:
            raise RuntimeError("Model is not available")

        try:
            processed_features = self.preprocess_features(features)
            return int(self.model.predict(processed_features)[0])
        except Exception as e:
            logger.error(f"Prediction error: {str(e)}")
            raise RuntimeError(f"Prediction failed: {str(e)}")

    def predict_proba(self, features):
        """Get prediction probabilities using the complete pipeline"""
        if not self.model_loaded:
            self.load_model()

        if self.model is None:
            raise RuntimeError("Model is not available")

        try:
            processed_features = self.preprocess_features(features)
            proba = self.model.predict_proba(processed_features)[0]
            return float(proba[1])  # Probability of malware class
        except Exception as e:
            logger.error(f"Probability prediction error: {str(e)}")
            raise RuntimeError(f"Probability prediction failed: {str(e)}")

    def get_model(self):
        """Get the loaded model"""
        if not self.model_loaded:
            self.load_model()
        return self.model

    def get_scaler(self):
        """Get the loaded scaler"""
        if not self.model_loaded:
            self.load_model()
        return self.scaler

    def get_feature_selector(self):
        """Get the loaded feature selector"""
        if not self.model_loaded:
            self.load_model()
        return self.feature_selector

    def get_feature_structure(self):
        """Get the feature structure information"""
        if not self.model_loaded:
            self.load_model()
        return self.feature_structure
