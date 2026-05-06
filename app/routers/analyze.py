from fastapi import APIRouter, Depends, Request
from app.models.schemas import AnalyzeRequest, AnalyzeResponse, Verdict, ScoringReason
from app.services.feature_extractor import extract_features
from app.core.security import verify_addon_signature

# We are temporarily leaving out the signature verification dependency 
# so you can test the connection with Apps Script. 
# Once connected, we will add: dependencies=[Depends(verify_addon_signature)]
router = APIRouter()

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_email(request: AnalyzeRequest):
    # 1. Run the feature extractors on the incoming payload
    features = extract_features(request)
    
    # Print features to your terminal so you can see it working!
    print("Extracted Features:", features)
    
    # 2. Return a dummy response for Phase 1 skeleton testing
    return AnalyzeResponse(
        score=0.85,
        verdict=Verdict.SUSPICIOUS,
        verdict_label="Highly Suspicious",
        summary="This is a skeleton response. The email exhibits signs of urgency.",
        reasons=[
            ScoringReason(
                signal="urgency_phrase_count",
                label="Urgent Language Detected",
                description="The email contains phrases commonly used to create a false sense of urgency.",
                weight=0.5,
                is_positive=True
            ),
            ScoringReason(
                signal="dummy_signal",
                label="Backend Connected",
                description="The FastAPI backend successfully received the Apps Script payload.",
                weight=0.0,
                is_positive=True
            )
        ],
        model_version="stub-0.1"
    )