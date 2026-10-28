"""
SpamSentry - Bulletproof Security Analysis Engine
Synthesizes message pattern analysis, phishing indicators, and URL threat heuristics
into an explainable, zero-crash cybersecurity risk assessment.
"""

import os
import pickle
import re
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

from phishing_detector import detect_phishing
from url_analyzer import extract_urls

BASE_DIR = Path(__file__).resolve().parent

_model = None
_vectorizer = None
_model_loaded = False


def _find_model_file(filename: str) -> Optional[Path]:
    candidates = [
        BASE_DIR / "models" / filename,
        BASE_DIR / filename
    ]
    for p in candidates:
        if p.exists() and p.is_file():
            return p
    return None


def auto_train_fallback():
    """Trains a baseline classifier in memory if model files are ever missing."""
    global _model, _vectorizer, _model_loaded
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.naive_bayes import MultinomialNB

        corpus = [
            ("ham", "meeting scheduled tomorrow please bring report update project status"),
            ("ham", "invoice attached review payment transfer notes client presentation"),
            ("ham", "flight booking confirmed gate opens schedule calendar invite"),
            ("ham", "monthly overview document updated pull request github review"),
            ("ham", "appointment confirmed doctor please arrive 10 minutes early"),
            ("spam", "congratulations promotional winner claim free gift card vouchers cash reward"),
            ("spam", "winner instant prize lottery claim cash reward call now promo"),
            ("spam", "urgent promotion discount luxury buy now free shipping special offer"),
            ("spam", "pre-approved instant loan zero interest credit check claim funds"),
            ("spam", "exclusive offer bonus free spins deposit instant cash reward prize")
        ]
        X = [t[1] for t in corpus]
        y = [0 if t[0] == "ham" else 1 for t in corpus]

        vec = TfidfVectorizer(stop_words='english', ngram_range=(1, 2))
        X_vec = vec.fit_transform(X)
        mdl = MultinomialNB(alpha=0.1)
        mdl.fit(X_vec, y)

        _model = mdl
        _vectorizer = vec
        _model_loaded = True
        return _model, _vectorizer
    except Exception:
        _model_loaded = False
        return None, None


def load_ml_models() -> Tuple[Any, Any]:
    global _model, _vectorizer, _model_loaded
    if _model_loaded and _model is not None and _vectorizer is not None:
        return _model, _vectorizer

    model_path = _find_model_file("model.pkl")
    vectorizer_path = _find_model_file("vectorizer.pkl")

    if model_path and vectorizer_path:
        try:
            with open(model_path, "rb") as f:
                _model = pickle.load(f)
            with open(vectorizer_path, "rb") as f:
                _vectorizer = pickle.load(f)
            _model_loaded = True
            return _model, _vectorizer
        except Exception:
            pass

    # Auto-train fallback in memory so it NEVER crashes
    return auto_train_fallback()


def preprocess_text(text: str) -> str:
    if not text:
        return ""
    try:
        cleaned = re.sub(r"\s+", " ", str(text).strip())
        return cleaned.lower()
    except Exception:
        return ""


def get_spam_prediction(text: str) -> Tuple[float, str]:
    try:
        model, vectorizer = load_ml_models()
        cleaned = preprocess_text(text)
        
        if not cleaned or model is None or vectorizer is None:
            # Rule-based fallback if ML is unavailable
            spam_words = ["congratulations", "winner", "lottery", "claim", "free", "$", "prize", "cash", "loan", "offer", "discount"]
            match_count = sum(1 for w in spam_words if w in cleaned)
            prob = min(0.95, match_count * 0.25)
            return round(prob, 2), "Spam" if prob >= 0.50 else "Safe"

        vec = vectorizer.transform([cleaned])
        probs = model.predict_proba(vec)[0]
        
        spam_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        label = "Spam" if spam_prob >= 0.50 else "Safe"
        return round(spam_prob, 4), label
    except Exception:
        return 0.15, "Safe"


def generate_recommendation(prediction: str, risk_level: str, has_urls: bool, has_creds: bool) -> str:
    if prediction == "PHISHING":
        if has_creds and has_urls:
            return "Do NOT click any links, enter login credentials, or share passwords. Report this message to your security administrator and block the sender."
        elif has_urls:
            return "Do NOT open the links in this message. Visit the official service directly by typing the verified web address into your browser."
        else:
            return "Exercise extreme caution. Do not respond, transfer funds, or provide personal details. Verify the sender's identity through a separate, trusted channel."
    elif prediction == "SPAM":
        return "Mark this message as spam and delete it. Avoid clicking unsubscribe links in unsolicited messages as they may confirm your contact address is active."
    else:
        if risk_level == "MEDIUM":
            return "This message appears largely legitimate, but contains external references. Continue to observe standard caution before taking sensitive actions."
        return "This message appears safe based on the available indicators. Continue to remain cautious with unexpected requests."


def generate_email_summary(text: str, prediction: str, reasons: List[str], risk_level: str) -> str:
    if prediction == "PHISHING":
        top_reasons = "; ".join(reasons[:2]) if reasons else "suspicious deceptive patterns"
        return f"Threat Assessment: High-risk phishing indicators detected ({top_reasons}). This communication appears designed to deceive the recipient into taking urgent action or divulging sensitive credentials."
    elif prediction == "SPAM":
        top_reasons = "; ".join(reasons[:2]) if reasons else "unsolicited promotional patterns"
        return f"Threat Assessment: Unsolicited spam characteristics detected ({top_reasons}). This message aligns with bulk automated marketing or low-reputation messaging."
    else:
        return "Threat Assessment: No significant threat indicators, urgency manipulation, or suspicious link structures were detected."


def analyze_email(email_text: str, sender_email: Optional[str] = None) -> Dict[str, Any]:
    # Bulletproof fallback for empty inputs
    if not email_text or not str(email_text).strip():
        return {
            "prediction": "SAFE",
            "confidence": 0.0,
            "confidence_percent": "0%",
            "spam_score": 0.0,
            "phishing_score": 0.0,
            "url_risk_score": 0.0,
            "risk_score": 0,
            "risk_level": "LOW",
            "reasons": ["No message text was provided for analysis."],
            "recommendation": "Please enter or paste message content to perform security analysis.",
            "summary": "No text provided.",
            "urls_detected": 0,
            "suspicious_urls_count": 0,
            "urls": []
        }

    try:
        spam_prob, ml_label = get_spam_prediction(email_text)
    except Exception:
        spam_prob, ml_label = 0.15, "Safe"

    try:
        phishing_result = detect_phishing(email_text, sender_email)
    except Exception:
        phishing_result = {
            "phishing_score": 0.0,
            "risk_level": "LOW",
            "suspicious_urls": [],
            "reasons": [],
            "url_analysis": {}
        }

    phishing_score = phishing_result.get("phishing_score", 0.0)
    phishing_reasons = phishing_result.get("reasons", [])
    url_analysis = phishing_result.get("url_analysis", {})
    url_risk_score = url_analysis.get("url_risk_score", 0.0)
    url_details = url_analysis.get("url_details", [])

    reasons: List[str] = []
    
    if spam_prob >= 0.75:
        reasons.append("Contains strong promotional vocabulary and automated bulk messaging patterns.")
    elif spam_prob >= 0.50:
        reasons.append("Contains common unsolicited marketing and promotional phrasing.")

    for pr in phishing_reasons:
        if pr not in reasons and "No notable" not in pr and "Empty message" not in pr:
            reasons.append(pr)

    is_phishing = (
        phishing_score >= 0.45 or
        (phishing_score >= 0.30 and url_risk_score >= 0.35) or
        (phishing_score >= 0.25 and any(u.get("risk_level") == "HIGH" for u in url_details))
    )

    if is_phishing:
        prediction = "PHISHING"
        composite_score = max(phishing_score, (phishing_score * 0.6 + url_risk_score * 0.25 + spam_prob * 0.15))
        confidence = round(max(0.70, composite_score), 2)
    elif spam_prob >= 0.50:
        prediction = "SPAM"
        composite_score = spam_prob * 0.75 + phishing_score * 0.25
        confidence = round(spam_prob, 2)
    else:
        prediction = "SAFE"
        composite_score = max(spam_prob, phishing_score) * 0.4
        confidence = round(1.0 - spam_prob, 2)

    risk_score_100 = int(round(min(1.0, max(0.0, composite_score)) * 100))

    if risk_score_100 >= 60:
        risk_level = "HIGH"
    elif risk_score_100 >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if not reasons:
        reasons = [
            "No suspicious links detected",
            "No unusual account verification requests detected",
            "No high-pressure urgency or fear tactics detected",
            "Message structure aligns with safe correspondence"
        ]

    has_creds = any("credential" in r.lower() or "password" in r.lower() for r in reasons)
    has_urls = len(url_details) > 0
    recommendation = generate_recommendation(prediction, risk_level, has_urls, has_creds)
    summary = generate_email_summary(email_text, prediction, reasons, risk_level)
    confidence_percent = f"{int(round(confidence * 100))}%"

    return {
        "prediction": prediction,
        "confidence": confidence,
        "confidence_percent": confidence_percent,
        "spam_score": spam_prob,
        "phishing_score": phishing_score,
        "url_risk_score": url_risk_score,
        "risk_score": risk_score_100,
        "risk_level": risk_level,
        "reasons": reasons,
        "recommendation": recommendation,
        "summary": summary,
        "urls_detected": len(url_details),
        "suspicious_urls_count": len([u for u in url_details if u.get("risk_score", 0) >= 0.30]),
        "urls": url_details
    }