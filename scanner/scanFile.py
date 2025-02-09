import numpy as np
import joblib
import os
from machine_learning.Classification import extract_features

# Load the ML model
MODEL_PATH = os.path.join('models', 'LOGISTIC_REGRESSION_MODEL.joblib')

try:
    model = joblib.load(MODEL_PATH)  # Use joblib to load the model
except Exception as e:
    raise RuntimeError(f"Error loading model from {MODEL_PATH}: {str(e)}")
    
def scan_file(file_bytes, file_name):
    """
    Scan a file using the ML model to detect malware
    
    Args:
        file_bytes (bytes): Raw file content
        file_name (str): Name of the file
        
    Returns:
        dict: Scan results including prediction and confidence
    """
    try:
        # Extract features from the file
        features = extract_features(file_bytes)
        
        if features is None:
            return {
                'error': 'Could not extract features from file',
                'isMalware': False,
                'confidence': 0
            }

        # Make prediction
        features_array = np.array(features).reshape(1, -1)
        prediction = model.predict(features_array)[0]
        confidence = np.max(model.predict_proba(features_array)[0]) * 100

        return {
            'fileName': file_name,
            'isMalware': bool(prediction),
            'confidence': float(confidence),
            'features': features
        }

    except Exception as e:
        raise Exception(f'Error scanning file: {str(e)}')
        
