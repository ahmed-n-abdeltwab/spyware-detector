import hashlib
import numpy as np
import re
import pefile
import logging
from pathlib import Path
from model_management.manager import ModelManager

# Configure logging
log_dir = Path(__file__).parent.parent / "logs"
log_dir.mkdir(exist_ok=True, parents=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_dir / "feature_extraction.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("FeatureExtraction")


def calculate_entropy(data):
    """Calculate the entropy of a file's content."""
    if not data:
        return 0.0
    try:
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = counts / len(data)
        entropy = -np.sum(
            probabilities * np.log2(probabilities, where=probabilities > 0)
        )
        return float(entropy)
    except Exception as e:
        logger.error(f"Entropy calculation error: {str(e)}")
        return 0.0


def extract_features(file_stream):
    """
    Complete feature extraction pipeline with heuristic mapping to model's expected features.
    Returns feature vector matching the 50 indices in selected_features.json.
    """
    try:
        file_stream.seek(0)
        file_data = file_stream.read()
        file_size = len(file_data)
        file_hash = hashlib.sha256(file_data).hexdigest()
        entropy = calculate_entropy(file_data)

        # Initialize feature vector (50 zeros)
        feature_vector = [0] * 50

        # --- Feature Extraction ---
        file_text = str(file_data, "latin-1", errors="replace")

        # 1. Extract APIs from PE Imports
        api_list = []
        try:
            pe = pefile.PE(data=file_data)
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            api_name = imp.name.decode(
                                "utf-8", errors="replace"
                            ).lower()
                            api_list.append(api_name)
        except Exception as e:
            logger.debug(f"PE parsing failed (non-PE file?): {str(e)}")

        # 2. Extract URLs and IPs
        url_list = re.findall(
            r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+", file_text, re.IGNORECASE
        )
        ip_list = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", file_text)

        # 3. Extract Strings
        strings = re.findall(r"[\w\-\.]+", file_text)  # Simple word-like patterns

        # --- Heuristic Feature Mapping ---
        # Since exact mappings are unknown, we distribute features intelligently
        # API-related features (indices 0-29)
        high_risk_apis = [
            "createthread",
            "writefile",
            "regsetvalue",
            "virtualalloc",
            "loadlibrary",
        ]
        for i, api in enumerate(high_risk_apis):
            if api in api_list:
                feature_vector[i] = 1  # Binary presence flag

        # URL/IP features (indices 30-39)
        suspicious_domains = ["malware", "evil", "attack", "exploit", "c2"]
        for i, domain in enumerate(suspicious_domains):
            feature_vector[30 + i] = sum(1 for url in url_list if domain in url.lower())

        # General API count features (indices 40-44)
        feature_vector[40] = len(api_list)  # Total API count
        feature_vector[41] = len(set(api_list))  # Unique API count
        feature_vector[42] = (
            1 if any("crypt" in api for api in api_list) else 0
        )  # Crypto APIs
        feature_vector[43] = (
            1 if any("net" in api for api in api_list) else 0
        )  # Network APIs
        feature_vector[44] = len(
            [api for api in api_list if api.startswith("nt")]
        )  # NT APIs

        # File characteristics (indices 45-49)
        feature_vector[45] = int(entropy * 10)  # Scaled entropy
        feature_vector[46] = 1 if file_size > 1_000_000 else 0  # Large file flag
        feature_vector[47] = file_size % 1000  # File size pattern
        feature_vector[48] = len(strings) // 100  # String count (scaled)
        feature_vector[49] = int(file_hash, 16) % 100  # Hash-derived feature

        # --- Debug Logging ---
        logger.info(f"Generated feature vector: {feature_vector}")
        logger.debug(
            f"APIs found: {api_list[:10]}{'...' if len(api_list) > 10 else ''}"
        )
        logger.debug(f"URLs found: {url_list[:5]}{'...' if len(url_list) > 5 else ''}")
        logger.debug(f"IPs found: {ip_list[:5]}{'...' if len(ip_list) > 5 else ''}")

        PAD_SIZE = 2762
        padded_features = np.zeros(PAD_SIZE, dtype=np.float32)
        padded_features[: len(feature_vector)] = feature_vector
        return {
            "features": padded_features,
            "details": {
                "apiList": api_list,
                "urlList": url_list,
                "ipList": ip_list,
                "fileHash": file_hash,
                "entropy": entropy,
                "fileSize": file_size,
                "notes": "Features heuristically mapped. For production use, provide exact feature mappings.",
            },
        }

    except Exception as e:
        logger.error(f"Feature extraction failed: {str(e)}", exc_info=True)
        return {"error": f"Feature extraction failed: {str(e)}"}


def classify_file(features):
    """
    Classify a file using the loaded model.
    Returns tuple of (prediction, confidence).
    """
    try:
        model_manager = ModelManager()
        if not model_manager.load_model():
            logger.error("Model failed to load")
            return {"error": "Model not available"}, 0.0

        if isinstance(features, dict) and "features" in features:
            feature_vector = features["features"]
        else:
            feature_vector = features

        prediction = model_manager.predict(feature_vector)
        confidence = model_manager.predict_proba(feature_vector)

        logger.info(
            f"Classification: {'Malware' if prediction else 'Clean'} (Confidence: {confidence:.2f})"
        )
        return prediction, confidence

    except Exception as e:
        logger.error(f"Classification error: {str(e)}", exc_info=True)
        return {"error": str(e)}, 0.0
