

# 🏗️ Detailed Component Diagram

## **System Overview**
This system provides a real-time, scalable **file scanning service** using **machine learning (ML)** to detect malware in uploaded files. The architecture is divided into multiple components, ensuring **isolation, scalability, and security**.

---

## **📌 Major Components**

### **1️⃣ API Gateway**
- **Receives file uploads from users.**
- **Handles authentication & authorization** (JWT, API keys).
- Routes requests to backend services.

### **2️⃣ File Storage**
- **Stores uploaded files temporarily** for scanning.
- Uses **S3-compatible storage** for distributed scalability.
- Files are deleted after scanning.

### **3️⃣ Scanning Service (Isolated)**
- Runs in a **sandboxed virtual environment** (Docker/VM).
- **Extracts metadata** (file hash, size, type).
- **Runs multiple virus scanning engines** (open-source and custom).
- Passes results to ML service.

### **4️⃣ ML Detection Engine**
- Uses **trained ML models** for malware classification.
- Extracts **file signatures, byte patterns, and entropy analysis**.
- Returns **probability score & classification result**.

### **5️⃣ Result Processing**
- Aggregates results from virus scanners & ML model.
- Stores scan reports in a **database**.
- Notifies the user via **WebSocket/REST API**.

### **6️⃣ Database (PostgreSQL/NoSQL)**
- Stores scan reports, metadata, and user history.
- Optimized for fast retrieval and indexing.

### **7️⃣ Monitoring & Logging**
- Uses **Prometheus & Grafana** for monitoring.
- Logs security events using **Winston/Morgan**.
- Detects **failures, abnormal patterns, and system health**.

---

## **🖼️ Component Diagram (ASCII)**
```
          +---------------------------+
          |        Client (UI)         |
          +------------+--------------+
                       |
           +-----------v-----------+
           |     API Gateway       |
           +-----------+-----------+
                       |
   +-------------------+------------------+
   |                  |                   |
+--v--+           +---v---+            +--v--+
| S3  |           | Scan  |            | ML  |
|Storage         |Service|            |Engine|
+----+           +---+---+            +--+--+
      \_____________|__________________/
                   |
           +-------v--------+
           |  Result Store  |
           | (Database)     |
           +-------+--------+
                   |
           +-------v--------+
           | Monitoring &   |
           | Logging        |
           +----------------+
```

---

## **📌 Technologies Used**
- **Backend**: TypeScript (Node.js, Express)
- **ML Model**: Python (TensorFlow/PyTorch)
- **File Scanning**: Open-source AV engines + custom rules
- **Database**: PostgreSQL / MongoDB
- **Storage**: S3-compatible cloud storage
- **Monitoring**: Prometheus, Grafana, Loki
- **Security**: JWT, Rate Limiting, Isolation (Docker/VM)
- **Real-Time Updates**: WebSockets

---

## **📌 Future Enhancements**
- Support for **multi-cloud storage** (AWS, GCP, Azure).
- More **advanced ML models** for better detection.
- Integration with **threat intelligence feeds**.
- **Auto-sandboxing** for suspicious files.

---

**📢 Contributors**: Follow the [CONTRIBUTING.md](./CONTRIBUTING.md) guide to contribute! 🚀
