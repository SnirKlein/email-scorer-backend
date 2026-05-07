import os
import tarfile
import urllib.request
import email
from email.policy import default
import pandas as pd
import lightgbm as lgb
import joblib
from bs4 import BeautifulSoup

from app.models.schemas import AnalyzeRequest, EmailHeader
from app.services.feature_extractor import extract_features

# URLs for the SpamAssassin Public Corpus
DATASETS = {
    "easy_ham": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    "spam": "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2"
}
DATA_DIR = "data"

def download_and_extract():
    os.makedirs(DATA_DIR, exist_ok=True)
    for label, url in DATASETS.items():
        tar_path = os.path.join(DATA_DIR, f"{label}.tar.bz2")
        extract_path = os.path.join(DATA_DIR, label)
        
        if not os.path.exists(extract_path):
            print(f"Downloading {label} dataset...")
            urllib.request.urlretrieve(url, tar_path)
            print(f"Extracting {label} dataset...")
            with tarfile.open(tar_path, "r:bz2") as tar:
                tar.extractall(path=extract_path)
            os.remove(tar_path)
    print("Data ready!")

def parse_eml_to_request(file_path: str) -> AnalyzeRequest:
    """Read a raw .eml file and convert it to our Pydantic schema."""
    try:
        with open(file_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=default)
            
        # Extract basic fields
        subject = msg.get('Subject', '')
        sender = msg.get('From', '')
        reply_to = msg.get('Reply-To', '')
        
        # Extract headers
        headers = [EmailHeader(name=k, value=str(v)) for k, v in msg.items()]
        
        # Extract body
        body_plain = ""
        body_html = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    body_plain += part.get_content()
                elif content_type == 'text/html':
                    body_html += part.get_content()
        else:
            if msg.get_content_type() == 'text/html':
                body_html = msg.get_content()
            else:
                body_plain = msg.get_content()
                
        # If there's HTML but no plain text, extract text from HTML for our extractors
        if body_html and not body_plain:
            soup = BeautifulSoup(body_html, "html.parser")
            body_plain = soup.get_text(separator=" ")

        return AnalyzeRequest(
            subject=subject[:2000] if subject else "",
            sender=sender[:500] if sender else "",
            reply_to=reply_to[:500] if reply_to else "",
            headers=headers,
            body_plain=body_plain[:50000] if body_plain else "",
            body_html=body_html[:100000] if body_html else ""
        )
    except Exception as e:
        return None

def main():
    download_and_extract()
    
    raw_requests = []
    labels = []
    
    print("Parsing emails into features (this may take a minute)...")
    for label_name, is_malicious in [("easy_ham", 0), ("spam", 1)]:
        # The tarball extracts into a subfolder with the same name
        folder_path = os.path.join(DATA_DIR, label_name, label_name)
        
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            if os.path.isfile(file_path):
                req = parse_eml_to_request(file_path)
                if req:
                    # Run it through your custom feature extractor!
                    features = extract_features(req)
                    raw_requests.append(features)
                    labels.append(is_malicious)

    # Train Model
    df = pd.DataFrame(raw_requests)
    
    # Fill any missing values (NaNs) created by the extractor with 0
    df = df.fillna(0)
    
    print(f"Training LightGBM on {len(df)} real emails...")
    model = lgb.LGBMClassifier(n_estimators=100, learning_rate=0.05, random_state=42)
    model.fit(df, labels)
    
    # Save the model
    os.makedirs("models", exist_ok=True)
    model_data = {
        "model": model,
        "feature_names": list(df.columns)
    }
    
    model_path = "models/classifier.joblib"
    joblib.dump(model_data, model_path)
    print(f"✅ Real model successfully saved to {model_path}!")

if __name__ == "__main__":
    main()