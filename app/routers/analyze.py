import os
import joblib
import pandas as pd
from fastapi import APIRouter, Depends, HTTPException
from app.models.schemas import AnalyzeRequest, AnalyzeResponse, Verdict, ScoringReason
from app.services.feature_extractor import extract_features
from app.core.security import verify_addon_signature

router = APIRouter()

# Load the model once when the application starts
MODEL_PATH = "models/classifier.joblib"
model_data = None

if os.path.exists(MODEL_PATH):
    model_data = joblib.load(MODEL_PATH)
    print(f"✅ Model loaded successfully from {MODEL_PATH}")
else:
    print(f"⚠️ Warning: Model not found at {MODEL_PATH}.")

@router.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(verify_addon_signature)])
async def analyze_email(request: AnalyzeRequest):
    # 1. Extract features
    features = extract_features(request)
    
    # Safety check
    if not model_data:
        raise HTTPException(status_code=500, detail="ML Model not loaded on the backend.")
        
    model = model_data["model"]
    feature_names = model_data["feature_names"]
    
    # 2. Format features into a Pandas DataFrame for LightGBM
    df = pd.DataFrame([features])
    
    # Ensure columns match the exact order the model was trained on. 
    # Fill missing features with 0 to prevent crashes.
    for col in feature_names:
        if col not in df.columns:
            df[col] = 0.0
    df = df[feature_names]
    
    # 3. Generate Prediction
    # predict_proba returns a 2D array: [[prob_safe, prob_malicious]]
    prob_malicious = float(model.predict_proba(df)[0][1])
    
    # 4. Determine Verdict based on thresholds
    if prob_malicious < 0.4:
        verdict = Verdict.SAFE
        label = "Likely Safe"
    elif prob_malicious < 0.7:
        verdict = Verdict.SUSPICIOUS
        label = "Suspicious"
    else:
        verdict = Verdict.MALICIOUS
        label = "Highly Malicious"
        
    # 5. Extract Explainability (Top Reasons)
    reasons = []
    
    # Only calculate and return threat indicators if the email is actually flagged
    if verdict != Verdict.SAFE:
        importances = model.feature_importances_
        
        feature_impacts = []
        for i, col in enumerate(feature_names):
            val = float(df[col].iloc[0])
            if val > 0 and importances[i] > 0:
                feature_impacts.append((col, val, importances[i]))
                
        feature_impacts.sort(key=lambda x: x[2], reverse=True)
        
        friendly_explanations = {
            "caps_ratio": "Contains an unusually high proportion of capitalized letters, a common tactic in urgent phishing requests.",
            "body_length": "The overall length and structure of the email text strongly aligns with known spam patterns.",
            "url_max_length": "Contains abnormally long web links, which are often used to obscure malicious destinations or tracking tokens.",
            "url_count": "Includes a high volume of embedded links, frequently seen in aggressive spam campaigns.",
            "has_suspicious_words": "Contains vocabulary or urgent language frequently associated with scams.",
            "domain_mismatch": "The sender's address does not appear to match the actual underlying routing domains."
        }
        
        for col, val, imp in feature_impacts[:3]:
            clean_name = col.replace("_", " ").title()
            default_explanation = f"The email's {clean_name.lower()} flagged our security baseline thresholds."
            explanation = friendly_explanations.get(col, default_explanation)
            
            reasons.append(
                ScoringReason(
                    signal=col,
                    label=clean_name,
                    description=explanation,
                    weight=float(imp),
                    is_positive=True
                )
            )
            
        if not reasons:
            reasons.append(
                ScoringReason(
                    signal="baseline",
                    label="Baseline Text Patterns",
                    description="Score derived from general NLP baseline text patterns.",
                    weight=prob_malicious,
                    is_positive=prob_malicious > 0.5
                )
            )
    
    return AnalyzeResponse(
        score=prob_malicious,
        verdict=verdict,
        verdict_label=label,
        summary=f"Analysis complete. The calculated threat probability is {prob_malicious:.0%}.",
        reasons=reasons,
        model_version="spamassassin-lgbm-1.0"
    )