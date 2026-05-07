# Malicious Email Scorer (Gmail Add-on)

An end-to-end Machine Learning pipeline and contextual Gmail Add-on that analyzes emails to score their likelihood of being malicious (phishing, spam, or malware).

## Architecture
This project is built on a decoupled, microservice architecture:
1. **Frontend (Google Apps Script):** A native Gmail Add-on that securely extracts email metadata and body content (Plain/HTML), rendering dynamic UX components based on the threat analysis.
2. **Backend API (FastAPI):** A high-performance Python web server that sanitizes inputs and manages the inference pipeline.
3. **ML Pipeline (LightGBM):** A custom feature extraction module (`feature_extractor.py`) parses raw text/HTML into heuristic features, evaluated by a LightGBM classifier. 

## Security
Communication between Google's servers and the backend is secured via a **Stable Signature Protocol**. The Apps Script calculates an HMAC-SHA256 signature using a shared secret and a stable payload string (Message ID + Date). The FastAPI middleware verifies this signature in real-time, completely rejecting unauthorized traffic and preventing payload tampering.

## Local Development Environment
This project uses Dev Containers to guarantee a reproducible environment.
1. Clone the repository and open in VS Code.
2. Select **"Reopen in Container"** to build the Docker environment.
3. Install dependencies: `pip install -r requirements.txt`
4. Train the ML model: `python -m scripts.train`
5. Start the backend: `uvicorn app.main:app --reload`
6. Expose the local port via ngrok: `ngrok http 8000`

## Trade-offs & Future Work
Given the time-boxed nature of this assignment, I made the following architectural decisions:
- **Dataset Selection:** The model is currently trained on the public **Apache SpamAssassin corpus**. This successfully demonstrates the end-to-end feature extraction and serving pipeline. However, in a production environment, this would be replaced with a modern threat-intelligence dataset strictly focused on phishing and malware payloads.
- **Background Processing:** Right now, the backend processes emails on the spot, meaning the user's screen waits while the model "thinks." For larger emails, I would move this to a background queue (like Redis) so the model can run without freezing or timing out the user's interface.