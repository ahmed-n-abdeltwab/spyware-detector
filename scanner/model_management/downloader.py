import requests
import tarfile
import json
import logging
import tempfile
import time
from pathlib import Path
import shutil
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
        logging.FileHandler(log_dir / "model_downloader.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("model_downloader")


class ModelDownloader:
    REQUIRED_FILES = [
        "model.pkl",
        "metadata.json",
        "metrics.json",
        "selected_features.json",
        "scaler.pkl",
        "package_info.json",
        "feature_structure.json",
        "feature_selector.pkl",
    ]

    def __init__(self, model_url, models_dir="models", cache_time=3600):
        """
        Initialize the model downloader with enhanced file support.

        Args:
            model_url: URL to download the model package
            models_dir: Directory to store models and supporting files
            cache_time: Time in seconds to cache the model before checking for updates
        """
        self.model_url = model_url
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True, parents=True)
        self.cache_time = cache_time
        self.last_check_path = self.models_dir / ".last_check"
        self.model_version_path = self.models_dir / ".model_version"

    def _get_etag(self):
        """Get the ETag from the remote URL without downloading the file"""
        try:
            response = requests.head(self.model_url, allow_redirects=True)
            if response.status_code == 200:
                return response.headers.get("ETag")
        except Exception as e:
            logger.error(f"Error getting ETag: {str(e)}")
        return None

    def _get_current_version(self):
        """Get the current model version from the local file"""
        if self.model_version_path.exists():
            with open(self.model_version_path, "r") as f:
                return f.read().strip()
        return None

    def _save_version(self, version):
        """Save the current model version to a file"""
        with open(self.model_version_path, "w") as f:
            f.write(version)

    def should_update(self):
        """
        Check if the model should be updated based on:
        - Missing files
        - Cache expiration
        - Version change
        """
        # Check if all required files exist
        if not all((self.models_dir / file).exists() for file in self.REQUIRED_FILES):
            logger.info("Required model files are missing, downloading...")
            return True

        # Check cache time
        if self.last_check_path.exists():
            last_check = float(self.last_check_path.read_text())
            if time.time() - last_check < self.cache_time:
                logger.info("Using cached model (checked recently)")
                return False

        # Check version
        current_version = self._get_current_version()
        remote_version = self._get_etag()

        if current_version != remote_version:
            logger.info(f"New model version available: {remote_version}")
            return True

        # Update last check time
        with open(self.last_check_path, "w") as f:
            f.write(str(time.time()))

        return False

    def download_model(self):
        """
        Download and extract the complete model package with all supporting files.
        Returns True if successful, False otherwise.
        """
        try:
            logger.info(f"Downloading model package from {self.model_url}")

            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                tar_path = temp_path / "model.tar.gz"

                # Download the package
                response = requests.get(self.model_url, stream=True)
                if response.status_code != 200:
                    logger.error(
                        f"Failed to download model: HTTP {response.status_code}"
                    )
                    return False

                etag = response.headers.get("ETag")

                # Save the package
                with open(tar_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                # Extract the package
                extract_dir = temp_path / "extracted"
                extract_dir.mkdir(exist_ok=True)

                with tarfile.open(tar_path, "r:gz") as tar:
                    tar.extractall(path=extract_dir)

                # Verify all required files are present
                missing_files = [
                    file
                    for file in self.REQUIRED_FILES
                    if not (extract_dir / file).exists()
                ]

                if missing_files:
                    logger.error(f"Missing required files in package: {missing_files}")
                    return False

                # Clear old files
                for file in self.models_dir.glob("*"):
                    if file.is_file() and file.name not in [
                        ".last_check",
                        ".model_version",
                    ]:
                        file.unlink()

                # Copy new files
                for file in extract_dir.glob("*"):
                    if file.is_file():
                        shutil.copy2(file, self.models_dir / file.name)

                # Save version and update last check
                if etag:
                    self._save_version(etag)

                with open(self.last_check_path, "w") as f:
                    f.write(str(time.time()))

                logger.info("Model package downloaded and extracted successfully")
                return True

        except Exception as e:
            logger.error(f"Error downloading model package: {str(e)}")
            return False

    def ensure_model_available(self):
        """Ensure the complete model package is available locally"""
        if self.should_update():
            return self.download_model()
        return True

    def get_file_path(self, filename):
        """Get the full path to a specific model file"""
        return self.models_dir / filename

    def load_json_file(self, filename):
        """Load a JSON file from the model directory"""
        file_path = self.get_file_path(filename)
        if file_path.exists():
            with open(file_path, "r") as f:
                return json.load(f)
        return None

    def load_pickle_file(self, filename):
        """Load a pickle file from the model directory"""
        file_path = self.get_file_path(filename)
        if file_path.exists():
            return joblib.load(file_path)
        return None
