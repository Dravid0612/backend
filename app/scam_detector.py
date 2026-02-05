SCAM_KEYWORDS = [
    "blocked", "suspended", "verify", "upi",
    "otp", "bank", "account", "urgent"
]

def detect_scam(text: str) -> dict:
    text_lower = text.lower()
    score = sum(1 for k in SCAM_KEYWORDS if k in text_lower)

    is_scam = score >= 2

    return {
        "isScam": is_scam,
        "confidence": min(score / len(SCAM_KEYWORDS), 1.0),
        "scamType": "UPI_FRAUD" if "upi" in text_lower else "GENERIC_FRAUD"
    }
