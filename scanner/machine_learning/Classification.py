import hashlib
from pathlib import Path
import magic
import numpy as np
import math
import re
import pandas as pd
import mmap
import pefile
import os
from dotenv import load_dotenv
import joblib

# Load environment variables
load_dotenv()

try:
    parent_dir = Path(__file__).parent.parent
    DATASET_PATH = os.path.join(parent_dir, "datasets/")
    PathOfTheDataSet = os.path.join(DATASET_PATH, "malwares.csv")
    MODEL_PATH = os.path.join(parent_dir,  "models/")
    support_mask = joblib.load(os.path.join(MODEL_PATH, "SUPPORT.joblib"))
except Exception as e:
    raise RuntimeError(f"Error loading datasets : {str(e)}")


def extract_features(file_stream):
    try:
        # Read file content
        file_stream.seek(0)
        file_data = file_stream.read()

        URL_list, IP_list, API_list = [], [], []

        # Convert file content to string
        f = str(file_data, "latin-1").split('\n')
        for line in f:
            urls = re.findall(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+", line)
            ips = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)

            IP_list.extend(ip.replace(".", "_").lower() for ip in ips)
            URL_list.extend(url.replace(".", "_").replace(":", "_").replace("/", "_").replace("-", "_").lower() for url in urls)

        # 🛠 Fix: Read PE file from memory instead of using `fileno()`
        try:
            pe = pefile.PE(data=file_data)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for API in entry.imports:
                    API_list.append(str(API.name)[2:-1].lower())
        except Exception:
            pass  # Ignore errors if it's not a PE file

        final_list = IP_list + URL_list + API_list

        # Ensure the feature vector is always 2762 elements
        if len(final_list) < 980:
            final_list += ["unknown_feature"] * (980 - len(final_list))
        else:
            final_list = final_list[:980]
    
        # Apply the feature selection mask
        selected_features = np.array(final_list)[support_mask].tolist()

        # Load dataset
        dataset = pd.read_csv(PathOfTheDataSet)
        expected_features = dataset.keys()[1:-2]  # Ensure correct feature order
        features = [selected_features.count(key.lower()) for key in expected_features]

        # Calculate SHA-256 hash
        hash_sha256 = hashlib.sha256(file_data).hexdigest()

        # Calculate entropy (assuming `calculate_entropy` is defined elsewhere)
        entropy = calculate_entropy(file_data)
        
        return {
            "features": features,
            "details": {
                "apiList": API_list,
                "fileHash": hash_sha256,
                "entropy": entropy,
            },
        }
    except Exception as e:
        return {"error": f"Feature extraction error: {str(e)}"}

def calculate_entropy(data):
    try:
        if not data:
            return 0
        entropy = -sum(p * math.log2(p) for p in np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256) / len(data) if p > 0)
        return entropy
    except Exception as e:
        return {"error": f"Entropy calculation error: {str(e)}"}

def calculate_hash(file_stream):
    try:
        file_stream.seek(0)
        return hashlib.sha256(file_stream.read()).hexdigest()
    except Exception as e:
        return {"error": f"Hash calculation error: {str(e)}"}

def get_file_type(file_stream):
    try:
        file_stream.seek(0)
        mime = magic.Magic(mime=True)
        return mime.from_buffer(file_stream.read(2048))
    except Exception as e:
        return {"error": f"File type detection error: {str(e)}"}

def get_mime_type(file_stream):
    try:
        file_stream.seek(0)
        return magic.from_buffer(file_stream.read(2048), mime=True)
    except Exception as e:
        return {"error": f"MIME type detection error: {str(e)}"}


def classify_file(features, logistic_model, support_model):
    try:
        # Ensure the input features are properly formatted
        feature_vector = [features["features"]]

        # Get predictions from both models
        logistic_pred = logistic_model.predict(feature_vector)[0]
        logistic_conf = float(logistic_model.predict_proba(feature_vector)[0][1])

        support_pred = support_model.predict(feature_vector)[0]
        support_conf = float(support_model.predict_proba(feature_vector)[0][1])

        # Combine results (simple majority vote)
        final_prediction = int((logistic_pred + support_pred) >= 1)  # Majority voting
        final_confidence = (logistic_conf + support_conf) / 2  # Average confidence

        return final_prediction, final_confidence

    except Exception as e:
        return {"error": f"Classification error: {str(e)}"}, 0.0   # Error as a dictionary, confidence is None
