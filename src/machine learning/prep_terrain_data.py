from sklearn.model_selection import train_test_split
import pandas as pd
import random
import os

current_file = os.path.abspath(os.path.dirname(__file__))
DATA_FN = os.path.join(current_file, '../datasets/malwares.csv')
malwares = pd.read_csv(DATA_FN)

def makeTerrainData(n = 0.3):
    keys = malwares.keys()
    features = list(keys[1:])
    label = keys[0]
    X, y = malwares[features].values, malwares[label].values
    # Split data 70%-30% into training set and test set (X_train, X_test, y_train, y_test)
    return train_test_split(X, y, test_size=n, random_state=0)
