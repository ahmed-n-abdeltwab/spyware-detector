This diagram breaks down each component and its sub-components.

User Interface (Web/API)
    - Frontend: HTML, CSS, JavaScript (React/Vue.js).
    - Backend API: Flask/FastAPI (Python) or Express.js (Node.js).

File Upload Service
    - File Validation: Checks file size (50 KB - 2 GB) and type.
    - Temporary Storage: Stores files temporarily (e.g., in-memory or local disk).

Virus Scanning Engine
    - ML Model: Pre-trained model for malware detection (e.g., TensorFlow/PyTorch).
    - Scanning Service: Microservice that runs the ML model on the uploaded file.

Workflow Orchestrator
    - File Routing: Routes files to the scanning engine.
    - Failure Handling: Retries or reroutes files if scanning fails.

Data Storage
    - Database: Stores scan results and metadata (e.g., PostgreSQL, MongoDB).
    - Logs: Tracks system activity and errors.
