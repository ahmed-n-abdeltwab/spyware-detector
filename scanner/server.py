import os
from flask import Flask, request, jsonify
import base64
from scanFile import scan_file
from model_management.manager import ModelManager
from flask_cors import CORS
from dotenv import load_dotenv
import io
import logging
from pathlib import Path

# Configure logging to use scanner/logs directory
log_dir = Path(__file__).parent / "logs"  # Points to scanner/logs

log_dir.mkdir(exist_ok=True, parents=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_dir / "server.log"), logging.StreamHandler()],
)
logger = logging.getLogger("server")

# Load environment variables
load_dotenv()

# Initialize the model manager
model_manager = ModelManager(
    model_url=os.getenv(
        "MODEL_URL",
        "https://github.com/ahmed-n-abdeltwab/spyware-detector-training/releases/download/main/model_release.tar.gz",
    )
)

app = Flask(__name__)
CORS(app)


@app.route("/")
def index():
    """Root endpoint with basic information"""
    model_info = model_manager.get_model_info()
    return jsonify(
        {
            "status": "running",
            "service": "Spyware Detector",
            "model_loaded": model_info["loaded"],
            "model_version": model_info["metadata"].get("version", "unknown"),
        }
    )


@app.route("/scan", methods=["POST"])
def scan():
    """Main scanning endpoint"""
    try:
        data = request.get_json()
        if not data or "fileName" not in data or "fileContent" not in data:
            return (
                jsonify(
                    {
                        "error": "Invalid request. Provide fileName and fileContent in base64."
                    }
                ),
                400,
            )

        file_name = data["fileName"]
        file_content = base64.b64decode(data["fileContent"])
        file_stream = io.BytesIO(file_content)

        logger.info(f"Received scan request for file: {file_name}")

        scan_result = scan_file(file_stream, file_name)
        return jsonify(scan_result)

    except Exception as e:
        logger.error(f"Error processing scan request: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/model/status", methods=["GET"])
def model_status():
    """Get detailed model status"""
    try:
        info = model_manager.get_model_info()
        return jsonify({"status": "success", "modelInfo": info})
    except Exception as e:
        logger.error(f"Error getting model status: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/model/update", methods=["POST"])
def update_model():
    """Force a model update"""
    try:
        success = model_manager.load_model(force=True)
        if success:
            return jsonify(
                {
                    "status": "success",
                    "message": "Model updated successfully",
                    "modelInfo": model_manager.get_model_info(),
                }
            )
        return jsonify({"status": "error", "message": "Failed to update model"}), 500
    except Exception as e:
        logger.error(f"Error updating model: {str(e)}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # Pre-load the model
    model_manager.load_model()
    app.run(
        debug=os.getenv("DEBUG", "False").lower() == "true",
        host="0.0.0.0",
        port=int(os.getenv("FLASK_PORT", 5000)),
    )
