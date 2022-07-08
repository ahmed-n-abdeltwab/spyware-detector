import joblib
import numpy as np
import json


def Classifier(scannerResult):
    from sklearn.preprocessing import MinMaxScaler  # for scaling
    features = scannerResult[0]    
    API_list = scannerResult[1]
    # filter the features list
    features = np.array(features)
    filter_arr = list(joblib.load("./SUPPORT.joblib"))
    features = features[filter_arr]

    features = features.reshape(1, -1)

    # load the model
    model = joblib.load("./LOGISTIC_REGRESSION_MODEL.joblib")

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
        df = pd.read_html("ht0tps://malapi.io/", attrs={"id": "main-table"})
        Spying = (df[0]["Spying"][0]).split()
        Evasion = (df[0]["Evasion"][0]).split()
        malapiList = Lower(Spying + Evasion)
        API_list = Lower(API_list)
        return list(filter(lambda api: api in API_list, malapiList))
    except:
        return API_list


def Lower(l: list):
    return list(map(lambda x: x.lower(), l))
