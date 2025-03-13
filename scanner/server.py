import os
from flask import Flask, request, jsonify
import base64
import numpy as np
from scanFile import scan_file
from flask_cors import CORS
from dotenv import load_dotenv
import io

# Load environment variables
load_dotenv()

# Get port from .env or use default 5000
PORT = int(os.getenv("FLASK_PORT", 5000))

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return "File Scanner and Classifier API"

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        if not data or 'fileName' not in data or 'fileContent' not in data:
            return jsonify({"error": "Invalid request. Provide fileName and fileContent."}), 400
        
        file_name = data['fileName']
        file_content = base64.b64decode(data['fileContent'])
        file_stream = io.BytesIO(file_content)
        scan_result = scan_file(file_stream, file_name)
        return jsonify(scan_result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=PORT)
