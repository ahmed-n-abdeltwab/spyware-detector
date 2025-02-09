import numpy as np
import math
import re
import os
import joblib

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))
SUPPORT = os.path.join(ROOT_PATH, 'models', 'SUPPORT.joblib')

def extract_features(file_bytes):
    """
    Extract features from a file for malware detection, ensuring compatibility
    with the trained model using SUPPORT.joblib.
    
    Args:
        file_bytes (bytes): Raw file content
        
    Returns:
        np.ndarray: Filtered feature vector
    """
    try:
        features = []
        
        # File size
        features.append(len(file_bytes))
        
        # Entropy
        entropy = calculate_entropy(file_bytes)
        features.append(entropy)
        
        # Printable characters ratio
        printable_ratio = calculate_printable_ratio(file_bytes)
        features.append(printable_ratio)
        
        # Suspicious patterns
        suspicious_patterns = [
            rb'CreateProcess',
            rb'WriteFile',
            rb'RegCreate',
            rb'Socket',
            rb'http://',
            rb'https://',
            rb'.exe',
            rb'.dll'
        ]
        
        for pattern in suspicious_patterns:
            count = count_pattern(file_bytes, pattern)
            features.append(count)
        
        # Convert to numpy array
        features = np.array(features)
        
        # Load feature filter from SUPPORT.joblib
        filter_arr = list(joblib.load(SUPPORT))
        features = features[filter_arr]
        
        # Reshape to match the model's input format
        return features.reshape(1, -1)
    
    except Exception as e:
        print(f"Error extracting features: {str(e)}")
        return None

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0
    
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy

def calculate_printable_ratio(data):
    """Calculate ratio of printable characters"""
    if not data:
        return 0
        
    printable = sum(32 <= x <= 126 for x in data)
    return printable / len(data)

def count_pattern(data, pattern):
    """Count occurrences of a pattern in data"""
    return len(re.findall(pattern, data))

