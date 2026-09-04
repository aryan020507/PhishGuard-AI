# PhishGuard-AI: AI-Powered Phishing URL & Message Threat Analyzer

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/FastAPI-0.141-emerald.svg)](https://fastapi.tiangolo.com/)
[![Deep Learning](https://img.shields.io/badge/TensorFlow-2.21-orange.svg)](https://www.tensorflow.org/)
[![Frontend](https://img.shields.io/badge/Frontend-Vanilla%20HTML5%20%2F%20CSS3%20%2F%20JS-yellow.svg)](#frontend)
[![Tests](https://img.shields.io/badge/Pytest-29%2F29%20Passed-brightgreen.svg)](#testing)

**PhishGuard-AI** is an enterprise-grade cyber threat intelligence platform that detects phishing URLs and social engineering messages in real time. It unifies two isolated deep learning pipelines behind an asynchronous FastAPI REST backend and a responsive, cybersecurity-themed Vanilla JavaScript frontend.

---

## 1. Architectural Blueprint

```
                                  ┌────────────────────────────────┐
                                  │      Vanilla SPA Frontend      │
                                  │    (HTML5, CSS3, ES6 JS)       │
                                  └───────────────┬────────────────┘
                                                  │ REST API (JSON)
                                  ┌───────────────▼────────────────┐
                                  │       FastAPI Application      │
                                  │  ├── Lifespan Model Loader     │
                                  │  ├── Risk Assessment Engine    │
                                  │  ├── Explanation Engine        │
                                  │  └── SQLite Audit History      │
                                  └───────┬────────────────┬───────┘
                                          │                │
                ┌─────────────────────────▼──┐          ┌──▼──────────────────────────┐
                │   Pipeline A: URL (ANN)    │          │  Pipeline B: Message (RNN)   │
                ├────────────────────────────┤          ├─────────────────────────────┤
                │ 16 Static Local Features   │          │ Text Cleaning & Normalization│
                │ StandardScaler (Joblib)    │          │ Vocabulary Tokenizer (Pickle)│
                │ Dense (32, ReLU)           │          │ Embedding Layer (5000 -> 32)│
                │ Dropout (0.3)              │          │ SimpleRNN (32 units)        │
                │ Dense (16, ReLU)           │          │ Dropout (0.3)               │
                │ Dropout (0.2)              │          │ Dense (16, ReLU)            │
                │ Dense (1, Sigmoid)         │          │ Dense (1, Sigmoid)          │
                └────────────────────────────┘          └─────────────────────────────┘
```

### Core Security Philosophy: Zero-Contact URL Safety
* **Never Execute User Submissions:** PhishGuard-AI **never resolves DNS, makes HTTP requests, or executes user-submitted links**.
* **Adversary Camouflage Protection:** Visiting an adversarial phishing link reveals telemetry to the attacker (e.g., verifying target phone numbers or exhausting one-time credentials). PhishGuard-AI operates **100% locally and statically**.
* **Risk Assessments, Not Guarantees:** Output scores are statistical likelihood estimations, accompanied by actionable security recommendations.

---

## 2. Technology Stack

* **Machine Learning & Core:** Python 3.11, TensorFlow 2.21, Keras 3.15, Scikit-learn 1.9, Pandas 3.0, NumPy 2.4, Joblib 1.6.
* **Backend:** FastAPI, Uvicorn (ASGI), Pydantic v2, SQLite.
* **Frontend:** Semantic HTML5, CSS3 Custom Properties (Dark Cyber-Defense Theme), Vanilla ES6 JavaScript (Zero React/Vue/Angular dependencies).
* **Testing & DevOps:** Pytest, HTTPX, Docker, Docker Compose.

---

## 3. Machine Learning Pipelines

### Pipeline A: Static URL Threat Detection (ANN)
* **Dataset:** 600 balanced verified URLs (300 live OpenPhish verified threat links + 300 realistic legitimate domains with natural path distributions).
* **16 Static Features Extracted Locally:**
  1. `url_length`: Overall character count.
  2. `num_dots`: Period count (identifies deep spoofed domains).
  3. `num_hyphens`: Hyphen count (common in brand-spoofing).
  4. `num_at`: Deceptive `@` authentication prefix detector.
  5. `num_question_marks`: Query parameter indicators.
  6. `num_equal_signs`: Assignment counts.
  7. `num_slashes`: Directory hierarchy depth.
  8. `num_digits`: Numeric character count.
  9. `digit_ratio`: Density of numeric characters.
  10. `has_https`: Boolean transport encryption presence.
  11. `has_ip`: Direct IP address used as hostname.
  12. `num_subdomains`: Calculated subdomain depth.
  13. `suspicious_keywords_count`: Presence of high-risk terms (`login`, `verify`, `update`, `banking`, `paypal`, `secure`, `webscr`).
  14. `has_port`: Non-standard TCP port definition.
  15. `entropy`: Shannon character entropy (detects algorithmically generated domains).
  16. `has_shortener`: Known URL shortener domain matching (e.g. `bit.ly`, `tinyurl.com`).
* **Evaluation on 15% Holdout Test Set:**
  * **Accuracy:** `88.89%`
  * **Precision:** `92.68%`
  * **Recall:** `84.44%`
  * **F1-Score:** `88.37%`
  * **ROC-AUC:** `0.9768`

### Pipeline B: Social Engineering & Message Threat Detection (RNN)
* **Dataset:** 5,572 samples from the UCI SMS Spam Collection (balanced via sample weighting during training).
* **Preprocessing:** Lowercasing, punctuation removal, currency and digit normalization, sequence padding (`maxlen=100`, post-padding).
* **Architecture:** `Embedding(5000, 32)` $\rightarrow$ `SimpleRNN(32)` $\rightarrow$ `Dropout(0.3)` $\rightarrow$ `Dense(16, ReLU)` $\rightarrow$ `Dense(1, Sigmoid)`.
* **Evaluation on 15% Holdout Test Set:**
  * **Accuracy:** `98.44%`
  * **Precision:** `96.26%`
  * **Recall:** `91.96%`
  * **F1-Score:** `94.06%`
  * **ROC-AUC:** `0.9875`

---

## 4. Risk Engine & Explanation System

### Standardized Threat Thresholds
The backend translates raw probabilities into actionable risk tiers:
* **LOW RISK ($P < 0.40$):** Benign characteristics; emerald badge (`#10b981`).
* **MEDIUM RISK ($0.40 \le P < 0.70$):** Suspicious signals; amber badge (`#f59e0b`).
* **HIGH RISK ($P \ge 0.70$):** Critical threat detected; crimson badge (`#ef4444`).

### Independent Heuristic Indicators
In addition to neural probabilities, human-understandable heuristic flags are generated:
* **URLs:** IP address hostname, insecure plaintext HTTP, excessive length, high character entropy, deep subdomain nesting, URL shortening service, deceptive `@` symbol, non-standard port.
* **Messages:** Artificial urgency pressure (`"immediately"`, `"suspended in 24h"`), financial/prize lures (`"claim $1000 prize"`, `"unpaid tax refund"`), brand impersonation (`"Wells Fargo"`, `"IRS"`, `"PayPal"`), explicit action prompts (`"click here"`, `"call now"`), premium-rate phone numbers.

---

## 5. Getting Started & Setup

### Prerequisites
* Linux / macOS / Windows WSL2
* Python 3.11+
* Git

### Local Installation
```bash
# 1. Clone repository
git clone https://github.com/aryanpandey/PhishGuard-AI.git
cd PhishGuard-AI

# 2. Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Dataset Preparation & Model Training
```bash
# Option A: Download live datasets (UCI SMS Spam & OpenPhish)
python training/datasets/download_datasets.py

# Option B: Or generate lightweight 100-row synthetic sets for fast test cycles
python training/datasets/generate_synthetic.py

# Train the URL ANN model
python training/train_url_ann.py

# Train the Message RNN model
python training/train_message_rnn.py
```
*Trained artifacts (`.keras`, `.joblib`, `.pkl`, and `.json`) will be generated into the `models/` directory.*

### Running the Application
```bash
# Launch FastAPI backend with Uvicorn
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
Open your browser and navigate to **`http://localhost:8000/`** to interact with the web application.
Interactive API documentation is available at **`http://localhost:8000/api/docs`**.

---

## 6. REST API Reference

### `GET /health`
Returns application uptime, pipeline readiness, and safety disclaimer.
```json
{
  "status": "healthy",
  "app_name": "PhishGuard-AI",
  "version": "1.0.0",
  "models_loaded": {
    "url_ann": true,
    "url_scaler": true,
    "message_rnn": true,
    "message_tokenizer": true
  },
  "uptime_seconds": 124.5,
  "disclaimer": "Predictions are automated risk assessments, not absolute guarantees."
}
```

### `POST /api/v1/predict/url`
Static, zero-contact URL threat inspection.
```bash
curl -X POST http://localhost:8000/api/v1/predict/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://192.168.1.100/paypal/login/verify.php"}'
```
**Response (Sample):**
```json
{
  "id": 1,
  "input_url": "http://192.168.1.100/paypal/login/verify.php",
  "features": {
    "url_length": 45.0,
    "num_dots": 4.0,
    "has_https": 0.0,
    "has_ip": 1.0,
    "suspicious_keywords_count": 2.0
  },
  "risk": {
    "risk_level": "HIGH",
    "probability": 1.0,
    "confidence_percentage": 100.0,
    "risk_color": "#ef4444",
    "recommendation": "CRITICAL ALERT: High probability of phishing or social engineering attack!"
  },
  "indicators": [
    {
      "code": "URL_IP_HOSTNAME",
      "name": "IP Address Used as Hostname",
      "description": "The destination relies directly on a numeric IP address instead of a domain.",
      "severity": "danger",
      "matched": true
    }
  ],
  "model_loaded": true,
  "model_used": "Artificial Neural Network (Dense-Dropout-Sigmoid)",
  "timestamp": "2026-09-04T08:57:59.615387+00:00"
}
```

### `POST /api/v1/predict/message`
Social engineering analysis on SMS/text content.
```bash
curl -X POST http://localhost:8000/api/v1/predict/message \
  -H "Content-Type: application/json" \
  -d '{"message": "URGENT: Your bank account has been locked. Call 08712345678 immediately."}'
```

### `GET /api/v1/models/metrics`
Serves verified benchmark test-set metrics directly from training artifacts.

### `GET /api/v1/history`
Retrieves past scans recorded in the local SQLite database.

---

## 7. Automated Test Suite

PhishGuard-AI includes a comprehensive 29-test automated test suite covering feature extraction, sequence padding, risk tier bounds, heuristic triggers, FastAPI endpoints, input validation, and error boundaries:

```bash
pytest -v tests/
```
**Result:** `29 passed in 6.93s`

---

## 8. Docker Deployment

### Run with Docker Compose
```bash
# Build and launch container in detached mode
docker-compose up --build -d

# Check logs
docker-compose logs -f

# Check container health status
curl http://localhost:8000/health
```

### Run with Docker CLI
```bash
docker build -t phishguard-ai .
docker run -d -p 8000:8000 --name phishguard-app phishguard-ai
```

---

## 9. Limitations & Ethical Considerations

1. **Adversarial Drift:** Cyber adversaries continuously engineer new evasive patterns (e.g. homoglyph attacks, zero-width spaces). Regular retraining on fresh threat feeds is required.
2. **Benign Urgency False Positives:** Legitimate password-reset emails and bank transaction security codes often employ urgency language; the Heuristic Engine surfaces these triggers transparently so analysts can distinguish context.
3. **Defense-in-Depth:** PhishGuard-AI should be deployed as one layer in a comprehensive security perimeter alongside SPF/DKIM/DMARC verification, multi-factor authentication (MFA), and user security awareness training.

---

## 10. License
Apache-2.0 License. Designed and engineered for high-assurance cybersecurity defense.
