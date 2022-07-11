import joblib
import numpy as np
import os

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))
LOGISTIC_REGRESSION_MODEL = os.path.join(ROOT_PATH,'LOGISTIC_REGRESSION_MODEL.joblib')
SUPPORT = os.path.join(ROOT_PATH,'SUPPORT.joblib')

def Classifier(scannerResult):
    features = scannerResult[0]  
    API_list = scannerResult[1]
    # filter the features list
    features = np.array(features)
    filter_arr = list(joblib.load(SUPPORT))
    features = features[filter_arr]

    features = features.reshape(1, -1)

    # load the model
    model = joblib.load(LOGISTIC_REGRESSION_MODEL)

    # get the prediction
    prediction = int(model.predict(features)[0])
    pred_pro = list(model.predict_proba(features)[0])
    if prediction == 0:
        return {
            "prediction": prediction,
            "details": {"prob": pred_pro, "apiList": usedAPIs(API_list)},
        }
    return {"prediction": prediction, "details": {"prob": pred_pro}}


def usedAPIs(API_list):
    import pandas as pd
    try:
        df = pd.read_html("https://malapi.io/", attrs={"id": "main-table"})
        Spying = (df[0]["Spying"][0]).split()
        Evasion = (df[0]["Evasion"][0]).split()
        malapiList = Lower(Spying + Evasion)
        API_list = Lower(API_list)
        return list(filter(lambda api: api in API_list, malapiList))
    except:
        return API_list


def Lower(l: list):
    return list(map(lambda x: x.lower(), l))
