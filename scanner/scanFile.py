import magic
from pathlib import Path
import hashlib
import joblib
import os
import numpy as np
import io
from machine_learning.Classification import extract_features, calculate_entropy, calculate_hash, get_file_type, get_mime_type, classify_file
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

try:
    parent_dir = Path(__file__).parent
    MODEL_PATH = os.path.join(parent_dir,  "models/")
    logistic_model = joblib.load(os.path.join(MODEL_PATH, "LOGISTIC_REGRESSION_MODEL.joblib"))
    support_model = joblib.load(os.path.join(MODEL_PATH, "SUPPORT.joblib"))
except Exception as e:
    raise RuntimeError(f"Error loading models: {str(e)}")


def scan_file(file_stream, file_name):
    try:
        # Ensure we reset the file pointer before each read
        file_stream.seek(0)
        file_hash = calculate_hash(file_stream)

        file_stream.seek(0)
        file_type = get_file_type(file_stream)

        file_stream.seek(0)
        mime_type = get_mime_type(file_stream)

        file_stream.seek(0)
        entropy = calculate_entropy(file_stream.read())

        file_stream.seek(0)
        features = extract_features(file_stream)

        # Ensure features were extracted successfully
        if isinstance(features, dict) and "error" in features:
            return features  # Return the extraction error

        # Classify the file
        prediction, confidence = classify_file(features, logistic_model, support_model)

        # Ensure classification was successful
        if isinstance(prediction, dict) and "error" in prediction:
            return prediction  # Return classification error

        return {
            "status": "success",
            "details": {
                "fileName": file_name,
                "isMalware": bool(prediction),
                "confidence": float(confidence),
            },
            "hash": file_hash,
            "fileType": file_type,
            "mimeType": mime_type,
            "entropy": entropy,
        }

    except Exception as e:
        return {"error": f"Scan error: {str(e)}"}
     
