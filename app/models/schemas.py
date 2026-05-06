from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


# ── Request ──────────────────────────────────────────────────────────────────

class EmailHeader(BaseModel):
    name: str
    value: str


class EmailAttachment(BaseModel):
    filename: str
    mime_type: str
    size_bytes: int


class AnalyzeRequest(BaseModel):
    """
    Payload sent by the Gmail Add-on.
    All fields are optional so the Add-on can send whatever it can access
    without failing if a field is unavailable.
    """
    message_id: Optional[str] = Field(None, description="Gmail message ID")
    subject: Optional[str] = Field(None, max_length=2000)
    sender: Optional[str] = Field(None, max_length=500)
    reply_to: Optional[str] = Field(None, max_length=500)
    recipients: Optional[list[str]] = Field(default_factory=list)
    date: Optional[str] = None
    headers: Optional[list[EmailHeader]] = Field(default_factory=list)
    body_plain: Optional[str] = Field(None, max_length=50_000)
    body_html: Optional[str] = Field(None, max_length=100_000)
    attachments: Optional[list[EmailAttachment]] = Field(default_factory=list)


# ── Response ──────────────────────────────────────────────────────────────────

class Verdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class ScoringReason(BaseModel):
    signal: str          # e.g. "reply_to_mismatch"
    label: str           # e.g. "Reply-To differs from sender"
    description: str     # human-readable explanation
    weight: float        # contribution to overall score (0-1)
    is_positive: bool    # True = bad signal, False = good signal


class AnalyzeResponse(BaseModel):
    score: float = Field(..., ge=0.0, le=1.0, description="Maliciousness probability 0–1")
    verdict: Verdict
    verdict_label: str       # e.g. "Likely Safe"
    summary: str             # one-sentence plain-English summary
    reasons: list[ScoringReason]
    model_version: str = "stub-0.1"