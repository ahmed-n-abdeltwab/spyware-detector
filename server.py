from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
import os
import joblib
import numpy as np
from scanFile import scanFile
import time

PathOfTheDataSet = './dataSets/StaticMalwareMatrixVersion2.csv'
RANDOM_FOREST_CLASSIFIER_PL_MODEL_FN = './models/StaticMalwareMatrix_RFC_PL'
RANDOM_FOREST_CLASSIFIER_MODEL_FN = './models/StaticMalwareMatrix_RFC'
LOGISTIC_REGRESSION_PL_MODEL_FN = './models/StaticMalwareMatrix_LR_PL'
LOGISTIC_REGRESSION_MODEL_FN = './models/StaticMalwareMatrix_LR'
SUPPORT_FN = './static/support.json'
UPLOAD_FOLDER = '.\\static\\uploads'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/spyware', methods=['POST', 'GET'])
def spyware():
    if request.method == 'POST':
        f = request.files['file']
        fileName = f.filename
        sample = scanFile(PathOfTheDataSet, f)
        f.close()
        predict, probapilty = classification(sample)
        return render_template('index.html', predict=predict, spaywareProbapilty=probapilty,
                               fileName=fileName)


def classification(oldSample):
    sample = samplePreprocessor(oldSample, joblib.load(SUPPORT_FN))
    X_new = np.array([sample])

    # Get a prediction
    model = joblib.load(LOGISTIC_REGRESSION_MODEL_FN)
    pred = model.predict(X_new)
    pred_pro = model.predict_proba(X_new)
    return pred[0], pred_pro[0]


def samplePreprocessor(oldSample, support):
    sample = []
    for i in range(len(support)):
        if support[i]:
            sample.append(oldSample[i])
    return sample


if __name__ == '__main__':
    app.run(debug=True)
