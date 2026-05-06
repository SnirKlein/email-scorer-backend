"""
Feature extraction for email maliciousness scoring.

Each extractor is a pure function: EmailFeatures → dict[str, float | int | bool].
This makes them independently testable and easy to add to.
"""

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from app.models.schemas import AnalyzeRequest, EmailHeader


# ── Helpers ────────────────────────────────────────────────────────────────────

_URL_RE = re.compile(
    r"https?://[^\s\"'<>)(\[\]]+", re.IGNORECASE
)

_URGENCY_PHRASES = [
    "act now", "urgent", "immediately", "account suspended", "verify now",
    "limited time", "expires", "click here", "confirm your", "your account",
    "unusual activity", "security alert", "password reset", "won a prize",
    "congratulations", "inheritance", "bank transfer", "wire transfer",
    "tax refund", "invoice attached",
]

_RISKY_EXTENSIONS = {".exe", ".bat", ".cmd", ".vbs", ".js", ".jar", ".zip",
                     ".rar", ".7z", ".scr", ".pif", ".com", ".msi", ".ps1"}


def _get_header(headers: list[EmailHeader], name: str) -> Optional[str]:
    name_lower = name.lower()
    for h in headers:
        if h.name.lower() == name_lower:
            return h.value
    return None


def _extract_domain(address: str) -> str:
    """Extract domain from an email address or URL."""
    address = address.strip().lower()
    # Handle display name + address: "Name <addr@domain>"
    m = re.search(r"<([^>]+)>", address)
    if m:
        address = m.group(1)
    if "@" in address:
        return address.split("@")[-1]
    try:
        return urllib.parse.urlparse(address).netloc
    except Exception:
        return address


def _extract_urls(text: str) -> list[str]:
    return _URL_RE.findall(text or "")


# ── Individual signal extractors ───────────────────────────────────────────────

def auth_signals(headers: list[EmailHeader]) -> dict:
    """Parse SPF / DKIM / DMARC results from Authentication-Results header."""
    auth_header = _get_header(headers, "Authentication-Results") or ""
    auth_lower = auth_header.lower()

    spf_pass = "spf=pass" in auth_lower
    dkim_pass = "dkim=pass" in auth_lower
    dmarc_pass = "dmarc=pass" in auth_lower

    return {
        "spf_pass": int(spf_pass),
        "dkim_pass": int(dkim_pass),
        "dmarc_pass": int(dmarc_pass),
        # If all three fail it's a strong signal
        "auth_total_pass": int(spf_pass) + int(dkim_pass) + int(dmarc_pass),
    }


def sender_signals(request: AnalyzeRequest) -> dict:
    """Signals derived from sender / reply-to relationship."""
    sender_domain = _extract_domain(request.sender or "")
    reply_to_domain = _extract_domain(request.reply_to or request.sender or "")

    reply_to_mismatch = (
        bool(request.reply_to)
        and sender_domain != reply_to_domain
    )

    # Display name spoofing: "PayPal <attacker@evil.com>"
    display_name = ""
    if request.sender and "<" in request.sender:
        display_name = request.sender.split("<")[0].strip().lower()

    known_brands = ["paypal", "amazon", "google", "apple", "microsoft",
                    "netflix", "bank", "fedex", "ups", "dhl", "irs"]
    display_name_spoof = any(
        brand in display_name for brand in known_brands
    ) and sender_domain not in [
        "paypal.com", "amazon.com", "google.com", "apple.com",
        "microsoft.com", "netflix.com", "fedex.com", "ups.com",
        "dhl.com", "irs.gov",
    ]

    return {
        "reply_to_mismatch": int(reply_to_mismatch),
        "display_name_spoof": int(display_name_spoof),
        "sender_domain_len": len(sender_domain),
        # Very long or numeric-heavy domains are suspicious
        "sender_domain_digit_ratio": (
            sum(c.isdigit() for c in sender_domain) / max(len(sender_domain), 1)
        ),
    }


def url_signals(request: AnalyzeRequest) -> dict:
    """Signals derived from URLs in the email body."""
    text = (request.body_plain or "") + " " + (request.body_html or "")
    urls = _extract_urls(text)

    if not urls:
        return {
            "url_count": 0,
            "http_ratio": 0.0,
            "url_domain_mismatch": 0,
            "url_max_length": 0,
        }

    http_count = sum(1 for u in urls if u.startswith("http://"))
    domains = [_extract_domain(u) for u in urls]
    unique_domains = set(domains)

    # Check if anchor text domains differ from href domains (HTML only)
    href_re = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    anchor_re = re.compile(r'<a[^>]+>([^<]+)</a>', re.IGNORECASE)
    hrefs = href_re.findall(request.body_html or "")
    anchors = anchor_re.findall(request.body_html or "")

    mismatch_count = 0
    for href, anchor in zip(hrefs, anchors):
        href_domain = _extract_domain(href)
        # If anchor text looks like a URL but points elsewhere
        if re.search(r"\.[a-z]{2,}", anchor.lower()):
            anchor_domain = _extract_domain(anchor.lower())
            if href_domain and anchor_domain and href_domain != anchor_domain:
                mismatch_count += 1

    return {
        "url_count": len(urls),
        "url_unique_domains": len(unique_domains),
        "http_ratio": http_count / len(urls),
        "url_domain_mismatch": mismatch_count,
        "url_max_length": max(len(u) for u in urls),
    }


def content_signals(request: AnalyzeRequest) -> dict:
    """Signals derived from email body content."""
    text = (request.body_plain or "").lower()

    urgency_hits = sum(1 for phrase in _URGENCY_PHRASES if phrase in text)
    body_len = len(text)

    # HTML-only (no plain text) is a phishing signal
    html_only = bool(request.body_html) and not bool(request.body_plain)

    # Excessive punctuation / caps (shouting)
    cap_ratio = sum(1 for c in (request.body_plain or "") if c.isupper()) / max(body_len, 1)
    exclamation_count = (request.body_plain or "").count("!")

    return {
        "urgency_phrase_count": urgency_hits,
        "body_length": body_len,
        "html_only": int(html_only),
        "caps_ratio": cap_ratio,
        "exclamation_count": exclamation_count,
    }


def attachment_signals(request: AnalyzeRequest) -> dict:
    """Signals derived from attachments."""
    if not request.attachments:
        return {"attachment_count": 0, "risky_attachment": 0, "attachment_total_size": 0}

    risky = any(
        any(att.filename.lower().endswith(ext) for ext in _RISKY_EXTENSIONS)
        for att in request.attachments
    )
    total_size = sum(att.size_bytes for att in request.attachments)

    return {
        "attachment_count": len(request.attachments),
        "risky_attachment": int(risky),
        "attachment_total_size": total_size,
    }


# ── Master extractor ───────────────────────────────────────────────────────────

def extract_features(request: AnalyzeRequest) -> dict:
    """
    Run all extractors and return a flat feature dict.
    This is what gets passed to the ML model (once trained).
    """
    features = {}
    features.update(auth_signals(request.headers or []))
    features.update(sender_signals(request))
    features.update(url_signals(request))
    features.update(content_signals(request))
    features.update(attachment_signals(request))
    return features