from flask import Flask, render_template, request
import os
from scanner import Scanner
from classifier import Classifier
import traceback
current_file = os.path.abspath(os.path.dirname(__file__))
PathOfTheDataSet = os.path.join(current_file, '../datasets/malwares.csv')


app = Flask(__name__,
 static_folder=current_file +'/static',
 template_folder=current_file +'/templates')

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/v1/scanner', methods=['POST', 'GET'])
def scanner():
    if request.method == 'POST':
        try:
            file = request.files['file']
            fileName = file.filename
            features = Scanner(PathOfTheDataSet, file)
            file.close()
            return features, 200
        except Exception as e:
            traceback.print_exc()
            return {'msg':str(e)}, 400
        

@app.route('/api/v1/classifier', methods=['POST', 'GET'])
def classifier():
    if request.method == 'POST':
        features = request.get_json(force=True)
        prediction = Classifier(features)
        print(prediction)
        return prediction, 200


if __name__ == '__main__':
    app.run(debug=True, port=4000)
