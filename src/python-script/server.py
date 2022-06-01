from flask import Flask,flash, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
import os
import joblib
import numpy as np
from scanner import scanner
from classifier import classifier
import time
import json
import requests

current_file = os.path.abspath(os.path.dirname(__file__))
PathOfTheDataSet = os.path.join(current_file, '../datasets/malwares.csv')


app = Flask(__name__)

@app.route('/')
def index():
    return '<h1>Hello World! From scanner server</h1>'


@app.route('/api/v1/scanner', methods=['POST', 'GET'])
def scanner():
    if request.method == 'POST':
        file = json.loads((request.data).decode())['data']
        features = scanner(PathOfTheDataSet, file)
        return features

@app.route('/api/v1/classifier', methods=['POST', 'GET'])
def classifier():
    if request.method == 'POST':
        features = json.loads((request.data).decode())['features']
        # prediction = classifier(features)
        prediction = -1
        return {'prediction':prediction,'details':{'prob':[0.5, 0.5], 'top10reason':["reason1", "reason2","reason3"]}}


if __name__ == '__main__':
    app.run(debug=True, port=6000)
