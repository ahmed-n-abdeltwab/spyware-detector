import logging
import time
from model_management.manager import ModelManager
from machine_learning.Classification import extract_features
from pathlib import Path

# Configure logging to use scanner/logs directory
log_dir = Path(__file__).parent / "logs"  # Points to scanner/logs

log_dir.mkdir(exist_ok=True, parents=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_dir / "scanner.log"), logging.StreamHandler()],
)
logger = logging.getLogger("scanner")


def classify_file(features):
    """
    Classify a file using the complete model pipeline.
    Returns tuple of (prediction, confidence)
    """
    try:
        model_manager = ModelManager()

        if not model_manager.load_model():
            logger.error("Failed to load model for classification")
            return {"error": "Model not available"}, 0.0

        # Get features in correct format
        if isinstance(features, dict) and "features" in features:
            feature_vector = features["features"]
        else:
            feature_vector = features

        # Get prediction and confidence
        prediction = model_manager.predict(feature_vector)
        confidence = model_manager.predict_proba(feature_vector)

        logger.info(
            f"Classification result: {'Malware' if prediction else 'Clean'} "
            f"with confidence {confidence:.2f}"
        )

        return prediction, confidence

    except Exception as e:
        logger.error(f"Classification error: {str(e)}")
        return {"error": f"Classification error: {str(e)}"}, 0.0


def scan_file(file_stream, file_name):
    """
    Complete file scanning pipeline:
    1. Extract features
    2. Classify using model
    3. Return comprehensive results
    """
    try:
        logger.info(f"Starting scan for file: {file_name}")

        # Initialize model manager
        model_manager = ModelManager()
        if not model_manager.load_model():
            return {"error": "Failed to load model"}

        # Extract features
        features = extract_features(file_stream)
        if isinstance(features, dict) and "error" in features:
            logger.error(f"Feature extraction failed: {features['error']}")
            return features

        # Classify the file
        prediction, confidence = classify_file(features)
        if isinstance(prediction, dict) and "error" in prediction:
            logger.error(f"Classification failed: {prediction['error']}")
            return prediction

        # Determine threat level
        threat_level = "Unknown"
        if prediction == 1:  # Malware
            if confidence > 0.9:
                threat_level = "Critical"
            elif confidence > 0.7:
                threat_level = "High"
            elif confidence > 0.5:
                threat_level = "Medium"
            else:
                threat_level = "Low"
        else:  # Clean
            threat_level = "Safe"

        # Get model information
        model_info = model_manager.get_model_info()
        model_metadata = model_manager.metadata
        model_metrics = model_manager.metrics

        # Build comprehensive result
        result = {
            "status": "success",
            "details": {
                "fileName": file_name,
                "isMalware": bool(prediction),
                "confidence": float(confidence),
                "threatLevel": threat_level,
                **features.get("details", {}),
            },
            "modelInfo": {
                "version": model_metadata.get("version", "unknown"),
                "trainedOn": model_metadata.get("trained_date", "unknown"),
                "accuracy": model_metrics.get("accuracy", "unknown"),
                "precision": model_metrics.get("precision", "unknown"),
                "recall": model_metrics.get("recall", "unknown"),
                "featureSelectorUsed": model_info["feature_selector_loaded"],
                "scalerUsed": model_info["scaler_loaded"],
            },
            "scanTimestamp": int(time.time()),
        }

        logger.info(
            f"Scan complete. Result: {result['details']['threatLevel']} "
            f"({'Malware' if result['details']['isMalware'] else 'Clean'}) "
            f"with {result['details']['confidence']:.2f} confidence"
        )

        return result

    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        return {"error": f"Scan error: {str(e)}"}
