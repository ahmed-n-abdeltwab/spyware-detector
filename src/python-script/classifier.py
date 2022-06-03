import joblib
import numpy as np
import json

def Classifier(features):
    sample = samplePreprocessor(features, joblib.load('./static/support.json'))
    X_new = np.array([sample])

    # Get a prediction
    model = joblib.load('./models/StaticMalwareMatrix_LR')
    pred = model.predict(X_new)
    pred_pro = model.predict_proba(X_new)
    return {'prediction':int(pred[0]), 'details':{'prob':list(pred_pro[0]), 'top10reason':["reason1", "reason2","reason3"]}}

def samplePreprocessor(features, support):
    sample = []
    for i in range(len(support)):
        if support[i]:
            sample.append(features[i])
    return sample