from flask import Flask,flash, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
import os
import joblib
import numpy as np
from scanner import scanner
from classifer import classifer
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

@app.route('/api/v1/scanner', methods=['POST', 'GET'])
def scanner():
    if request.method == 'POST':
        file = json.loads((request.data).decode())['data']
        features = scanner(PathOfTheDataSet, file)
        return features

@app.route('/api/v1/classifer', methods=['POST', 'GET'])
def classifer():
    if request.method == 'POST':
        ...

# {
#         prediction:1,
#         details:{
#             prob:[0.5, 0.5], 
#             top10reason:["reason1", "reason2","reason3"]
#         }}
if __name__ == '__main__':
    # app.secret_key = 'super secret key'
    app.run(debug=True, port=6000)
