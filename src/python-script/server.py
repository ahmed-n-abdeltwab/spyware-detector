from flask import Flask, render_template, request
import os
from scanner import Scanner
from classifier import Classifier
import traceback


ROOT_PATH = os.path.abspath(os.path.dirname(__file__))
PathOfTheDataSet = os.path.join(ROOT_PATH, '../datasets/malwares.csv')

app = Flask(
    __name__,
    static_folder=ROOT_PATH + "/static",
    template_folder=ROOT_PATH + "/templates",
)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/v1/scanner", methods=["POST", "GET"])
def scanner():
    if request.method == "POST":
        try:
            file = request.files["file"]
            fileName = file.filename
            features = Scanner(file)
            file.close()
            return features, 200
        except Exception as e:
            traceback.print_exc()
            return {"msg": str(e)}, 400


@app.route("/api/v1/classifier", methods=["POST", "GET"])
def classifier():
    if request.method == "POST":
        features = request.get_json(force=True)
        try:
            prediction = Classifier(features)
            print(prediction)
            return prediction, 200
        except Exception as e:
            traceback.print_exc()
            return {"msg": str(e)}, 400


if __name__ == "__main__":
    app.run(debug=True, port=4000)
