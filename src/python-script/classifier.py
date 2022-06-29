import joblib
import numpy as np
import json


def Classifier(scannerResult):
    features = scannerResult[0]
    API_list = scannerResult[1]
    # filter the features list 
    features = np.array(features)
    filter_arr = list(joblib.load("./static/support.json"))
    features = features[filter_arr]

    # load the model
    model = joblib.load("./models/StaticMalwareMatrix_LR")

    # get the prediction
    prediction = int(model.predict([features])[0])
    pred_pro = list(model.predict_proba([features])[0])
    if prediction == -1 :
        return {"prediction": prediction, "details": {"prob": pred_pro, "topReason": API_list}}
    return {"prediction": prediction, "details": {"prob": pred_pro}}


def topReason():
    import pandas as pd

    df = pd.read_html('https://malapi.io/', attrs = {'id': 'main-table'})
    malapiSpyingList = (df[0]['Spying'][0]).split()
    malapiSpyingLower = list(map(lambda x: x.lower(), malapiSpying))

    malwares = pd.read_csv('../datasets/malwares.csv')
    malapiSpyingUsed = list(filter(lambda key: key in malapiSpyingLower , malwares.keys()))

