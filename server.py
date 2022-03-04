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
        print(type(f))
        filePath = os.path.join(
            app.config['UPLOAD_FOLDER'], secure_filename(f.filename))
        f.save(filePath)

        sample = scanFile(PathOfTheDataSet, filePath)
        
        # time.sleep(5) 
        # delete_item(filePath)
        return classification(sample)


def delete_item(path):
    print(f"deleted {path}")
    os.unlink(path)
    os.remove(path)


def classification(oldSample):
    sample = samplePreprocessor(oldSample, joblib.load(SUPPORT_FN))
    X_new = np.array([sample])

    # Get a prediction
    model = joblib.load(LOGISTIC_REGRESSION_MODEL_FN)
    pred = model.predict(X_new)
    pred_pro = model.predict_proba(X_new)
    # The model returns an array of predictions - one for each set of features submitted
    # In our case, we only submitted one patient, so our prediction is the first one in the resulting array.
    return render_template('index.html', predict=pred[0], spaywareProbapilty=pred_pro[0])


def samplePreprocessor(oldSample, support):
    sample = []
    for i in range(len(support)):
        if support[i]:
            sample.append(oldSample[i])
    return sample


if __name__ == '__main__':
    app.run(debug=True)
