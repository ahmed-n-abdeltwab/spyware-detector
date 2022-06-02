import joblib
import numpy as np

def Classifier(features):
    sample = samplePreprocessor(oldSample, joblib.load('static/support.json'))
    X_new = np.array([sample])

    # Get a prediction
    model = joblib.load('../models/')
    pred = model.predict(X_new)
    pred_pro = model.predict_proba(X_new)
    return {
        'prediction':pred[0],
        'details':{
            'prob':pred_pro[0],
            'top10reason':["reason1", "reason2","reason3"]}}

def samplePreprocessor(oldSample, support):
    sample = []
    for i in range(len(support)):
        if support[i]:
            sample.append(oldSample[i])
    return sample