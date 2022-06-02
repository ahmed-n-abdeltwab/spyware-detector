from flask import Flask,flash, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
import os
import joblib
import numpy as np
from scanner import Scanner
from classifier import Classifier
import time
import json
import requests

current_file = os.path.abspath(os.path.dirname(__file__))
PathOfTheDataSet = os.path.join(current_file, '../datasets/malwares.csv')


app = Flask(__name__)

@app.route('/')
def index():
    return '<h1>Hello World! From python server</h1>'


@app.route('/api/v1/scanner', methods=['POST', 'GET'])
def scanner():
    if request.method == 'POST':
        print(request.file)
        features = Scanner(PathOfTheDataSet, request.file)
        print(features)
        return features

@app.route('/api/v1/classifier', methods=['POST', 'GET'])
def classifier():
    if request.method == 'POST':
        # features = request.features
        # print(features)
        # prediction = Classifier(features)
        prediction = -1
        return {'prediction':prediction,'details':{'prob':[0.5, 0.5], 'top10reason':["reason1", "reason2","reason3"]}}


if __name__ == '__main__':
    app.run(debug=True, port=6000)
