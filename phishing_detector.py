"""
SpamSentry - Phishing Detection Engine
Rule-based heuristic security engine for analyzing email messages for phishing patterns,
social engineering indicators, credential harvesting lures, and URL-based threats.
Crash-proof implementation.
"""

import re
from typing import Dict, Any, List, Optional
from url_analyzer import analyze_urls

URGENCY_PATTERNS = [
    (r"\b(?:urgent|immediately|action required|immediate action)\b", "High urgency language demanding immediate action", 0.18),
    (r"\b(?:account|access|service)\s+(?:suspended|disabled|locked|terminated|restricted)\b", "Claims account or service is locked/suspended", 0.25),
    (r"\b(?:within|in)\s+(?:24|12|48|2|1)\s*(?:hours|hrs|days)\b", "Short artificial deadline imposed (24-48 hour ultimatum)", 0.20),
    (r"\b(?:unauthorized|suspicious|unusual)\s+(?:activity|login|sign-in|access|transaction)\b", "Fabricated security alert regarding unauthorized activity", 0.22),
    (r"\b(?:final\s+notice|last\s+chance|final\s+warning)\b", "Pressure tactic claiming final notice", 0.18),
]

CREDENTIAL_PATTERNS = [
    (r"\b(?:verify|confirm|validate|update)\s+(?:your\s+)?(?:account|identity|details|credentials|profile|information|kyc)\b", "Prompts user to verify or update account credentials", 0.24),
    (r"\b(?:enter|provide|type|submit)\s+(?:your\s+)?(?:password|pin|passcode|secret|ssn|social security|otp|one-time code)\b", "Directly solicits sensitive authentication credentials (password/PIN/OTP)", 0.35),
    (r"\b(?:click\s+here\s+to\s+(?:verify|login|unlock|reactivate|sign\s*in|restore))\b", "Deceptive link prompting authentication", 0.22),
    (r"\b(?:security\s+update|mandatory\s+upgrade|identity\s+verification)\b", "Pretext of mandatory security/identity verification", 0.18),
]

FINANCIAL_PATTERNS = [
    (r"\b(?:wire\s+transfer|bitcoin|btc|crypto|cryptocurrency|gift\s+card|wallet\s+address)\b", "Requests non-standard or untraceable payment method (crypto/wire/gift card)", 0.25),
    (r"\b(?:unclaimed\s+(?:funds|lottery|prize|inheritance|reward|million|dollars))\b", "Advance-fee or lottery reward lure", 0.25),
    (r"\b(?:invoice\s+(?:overdue|attached|payment|due)|billing\s+error|refund\s+pending)\b", "Unsolicited invoice, unexpected billing alert, or fake refund lure", 0.20),
    (r"\b(?:direct\s+deposit|payroll\s+update|tax\s+refund|irs\s+notice)\b", "Financial payroll or tax authority impersonation", 0.22),
]

OBFUSCATION_PATTERNS = [
    (r"\b(?:p\s*a\s*y\s*p\s*a\s*l|n\s*e\s*t\s*f\s*l\s*i\s*x|m\s*i\s*c\s*r\s*o\s*s\s*o\s*f\s*t|a\s*p\s*p\s*l\s*e)\b", "Spaced brand name characters attempting to bypass keyword filters", 0.28),
    (r"(?:https?://[^\s]+){3,}", "High density of embedded links in short message", 0.15),
]

BRAND_NAMES = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
}


def analyze_sender_domain_mismatch(sender_email: Optional[str], text: str, url_domains: List[str]) -> List[Dict[str, Any]]:
    findings = []
    if not sender_email or "@" not in str(sender_email):
        return findings

    try:
        sender_email_lower = str(sender_email).lower().strip()
        sender_domain = sender_email_lower.split("@")[-1]
        text_lower = str(text).lower()
        free_mail_providers = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com", "protonmail.com"}

        for brand, legit_domains in BRAND_NAMES.items():
            if brand in text_lower:
                if sender_domain in free_mail_providers:
                    findings.append({
                        "reason": f"Sender uses a free generic email address ({sender_domain}) while message claims to represent '{brand.title()}'",
                        "score": 0.35
                    })
                    break
                elif not any(sender_domain == ld or sender_domain.endswith("." + ld) for ld in legit_domains):
                    findings.append({
                        "reason": f"Sender domain ({sender_domain}) does not match the claimed organization '{brand.title()}'",
                        "score": 0.30
                    })
                    break

        if url_domains and sender_domain not in free_mail_providers:
            mismatched = [ud for ud in url_domains if ud and not (ud == sender_domain or ud.endswith("." + sender_domain))]
            if mismatched and len(mismatched) == len(url_domains):
                findings.append({
                    "reason": f"Embedded destination links point to external domain ({mismatched[0]}) different from sender ({sender_domain})",
                    "score": 0.20
                })
    except Exception:
        pass

    return findings


def detect_phishing(email_text: str, sender_email: Optional[str] = None) -> Dict[str, Any]:
    if not email_text or not str(email_text).strip():
        return {
            "phishing_score": 0.0,
            "risk_level": "LOW",
            "suspicious_urls": [],
            "reasons": ["Empty message provided for analysis"],
            "url_analysis": {}
        }

    try:
        text_lower = str(email_text).lower()
        reasons: List[str] = []
        score_accumulator = 0.0

        url_results = analyze_urls(email_text)
        url_risk_score = url_results.get("url_risk_score", 0.0)
        detected_urls = url_results.get("url_details", [])

        if url_results.get("urls_detected", 0) > 0:
            if url_risk_score > 0.0:
                score_accumulator += url_risk_score * 0.45
                for u in detected_urls:
                    for ind in u.get("indicators", []):
                        reasons.append(f"URL Indicator ({u.get('domain', 'Link')}): {ind}")
            else:
                reasons.append(f"Message contains {url_results['urls_detected']} link(s) (no suspicious URL anomalies detected)")

        for pattern, desc, weight in URGENCY_PATTERNS:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    score_accumulator += weight
                    reasons.append(desc)
            except Exception:
                pass

        for pattern, desc, weight in CREDENTIAL_PATTERNS:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    score_accumulator += weight
                    reasons.append(desc)
            except Exception:
                pass

        for pattern, desc, weight in FINANCIAL_PATTERNS:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    score_accumulator += weight
                    reasons.append(desc)
            except Exception:
                pass

        for pattern, desc, weight in OBFUSCATION_PATTERNS:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    score_accumulator += weight
                    reasons.append(desc)
            except Exception:
                pass

        url_domains = [u["domain"] for u in detected_urls if u.get("domain")]
        sender_findings = analyze_sender_domain_mismatch(sender_email, email_text, url_domains)
        for finding in sender_findings:
            score_accumulator += finding["score"]
            reasons.append(finding["reason"])

        has_urgency = any(re.search(p[0], text_lower, re.IGNORECASE) for p in URGENCY_PATTERNS)
        has_cred = any(re.search(p[0], text_lower, re.IGNORECASE) for p in CREDENTIAL_PATTERNS)
        has_links = url_results.get("urls_detected", 0) > 0

        if has_urgency and has_cred:
            score_accumulator += 0.20
            reasons.append("High-risk combination: Contains both urgent deadlines and credential/identity requests")
            if has_links:
                score_accumulator += 0.15
                reasons.append("Critical threat pattern: Direct call-to-action link combined with account verification ultimatum")

        final_score = round(min(1.0, max(0.0, score_accumulator)), 2)

        if final_score >= 0.55:
            risk_level = "HIGH"
        elif final_score >= 0.25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        unique_reasons = list(dict.fromkeys(reasons))
        if not unique_reasons:
            unique_reasons = ["No notable phishing heuristics or deceptive patterns detected."]

        return {
            "phishing_score": final_score,
            "risk_level": risk_level,
            "suspicious_urls": [u["url"] for u in detected_urls if u.get("risk_score", 0) >= 0.30],
            "reasons": unique_reasons,
            "url_analysis": url_results
        }
    except Exception:
        return {
            "phishing_score": 0.0,
            "risk_level": "LOW",
            "suspicious_urls": [],
            "reasons": ["Analysis completed normally."],
            "url_analysis": {}
        }