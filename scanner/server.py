import os
from flask import Flask, request, jsonify
import base64
import numpy as np
from scanFile import scan_file
from flask_cors import CORS
from dotenv import load_dotenv


# Load environment variables
load_dotenv()

# Get port from .env or use default 5000
PORT = int(os.getenv("FLASK_PORT", 5000))

app = Flask(__name__)
CORS(app)

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        
        if not data or 'fileContent' not in data or 'fileName' not in data:
            return jsonify({
                'error': 'Invalid request. Missing fileName or fileContent.'
            }), 400

        file_content = data['fileContent']
        file_name = data['fileName']

        # Decode base64 content
        try:
            file_bytes = base64.b64decode(file_content)
        except Exception as e:
            return jsonify({
                'error': f'Invalid base64 content: {str(e)}'
            }), 400

        # Scan the file
        try:
            result = scan_file(file_bytes, file_name)
            return jsonify(result)
        except Exception as e:
            return jsonify({
                'error': f'Scanning error: {str(e)}'
            }), 500

    except Exception as e:
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=PORT)
