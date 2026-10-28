"""
SpamSentry - URL Analyzer Module
Extracts and performs static heuristic risk assessment on URLs found within emails
WITHOUT making network requests or executing any links. Crash-proof implementation.
"""

import re
from urllib.parse import urlparse
from typing import List, Dict, Any

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "tiny.cc", "rebrand.ly", "cutt.ly", "shorturl.at", "qr.ae",
    "hyperurl.co", "soo.gd", "s.id", "trib.al", "bl.ink"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "loan",
    "buzz", "club", "support", "vip", "icu", "rest", "cam", "fit", "monster",
    "gdn", "date", "racing", "win", "party", "review", "country", "kim", "cricket"
}

SUSPICIOUS_URL_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "account", "banking", "secure", "update", "password", "credential",
    "confirm", "wallet", "token", "auth", "authenticate", "validation",
    "suspended", "unlock", "security-alert", "billing", "reactivate"
]

TARGET_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "facebook",
    "instagram", "chase", "bankofamerica", "wellsfargo", "citibank", "dropbox",
    "yahoo", "adobe", "outlook", "office365", "binance", "coinbase"
]

IP_ADDRESS_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

URL_REGEX = re.compile(
    r'(?:(?:https?|ftp)://[^\s/$.?#].[^\s]*)|(?:www\.[^\s/$.?#].[^\s]*)',
    re.IGNORECASE
)


def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    try:
        matches = URL_REGEX.findall(str(text))
        cleaned_urls = []
        for match in matches:
            cleaned = match.rstrip(".,;!?'\")>]} ")
            if cleaned:
                cleaned_urls.append(cleaned)
        return list(dict.fromkeys(cleaned_urls))
    except Exception:
        return []


def analyze_single_url(raw_url: str) -> Dict[str, Any]:
    if not raw_url:
        return {
            "url": "",
            "domain": "Unknown",
            "is_https": False,
            "is_ip": False,
            "is_shortened": False,
            "risk_score": 0.0,
            "risk_level": "LOW",
            "indicators": []
        }

    url = str(raw_url).strip()
    if not (url.startswith("http://") or url.startswith("https://") or url.startswith("ftp://")):
        url = "http://" + url
        
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
        is_https = parsed.scheme.lower() == "https"
    except Exception:
        return {
            "url": str(raw_url)[:100],
            "domain": "Malformed Host",
            "is_https": False,
            "is_ip": False,
            "is_shortened": False,
            "risk_score": 0.6,
            "risk_level": "HIGH",
            "indicators": ["Malformed or deceptive URL syntax"]
        }
        
    indicators: List[str] = []
    risk_points = 0.0

    if not is_https:
        risk_points += 0.25
        indicators.append("Unencrypted connection (HTTP instead of HTTPS)")

    is_ip = False
    try:
        is_ip = bool(IP_ADDRESS_PATTERN.match(hostname))
        if is_ip:
            risk_points += 0.45
            indicators.append("Direct numerical IP address used as hostname instead of verified domain name")
    except Exception:
        pass

    is_shortened = False
    try:
        is_shortened = hostname in SHORTENER_DOMAINS or any(hostname.endswith("." + s) for s in SHORTENER_DOMAINS)
        if is_shortened:
            risk_points += 0.30
            indicators.append("URL shortener hides the true destination address")
    except Exception:
        pass

    try:
        parts = hostname.split(".")
        if len(parts) >= 4 and not is_ip:
            risk_points += 0.25
            indicators.append(f"Excessive subdomain depth ({len(parts)} segments) frequently used to disguise origin")

        tld = parts[-1] if len(parts) > 1 else ""
        if tld in SUSPICIOUS_TLDS:
            risk_points += 0.30
            indicators.append(f"High-risk top-level domain (.{tld}) commonly associated with disposable phishing campaigns")
    except Exception:
        pass

    try:
        matched_keywords = [kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in path or kw in query]
        if matched_keywords:
            risk_points += min(0.35, 0.15 * len(matched_keywords))
            indicators.append(f"Contains authentication/credential path keywords: {', '.join(matched_keywords[:3])}")
    except Exception:
        pass

    try:
        for brand in TARGET_BRANDS:
            if brand in hostname:
                legitimate_domains = [f"{brand}.com", f"{brand}.org", f"{brand}.net", f"{brand}.co.uk"]
                if not any(hostname == ld or hostname.endswith("." + ld) for ld in legitimate_domains):
                    risk_points += 0.40
                    indicators.append(f"Potential brand impersonation: '{brand}' appears inside untrusted host '{hostname}'")
                    break
    except Exception:
        pass

    try:
        if "@" in parsed.netloc:
            risk_points += 0.50
            indicators.append("URL contains deceptive '@' authentication prefix")
    except Exception:
        pass

    final_score = round(min(1.0, max(0.0, risk_points)), 2)
    
    if final_score >= 0.60:
        risk_level = "HIGH"
    elif final_score >= 0.30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "url": str(raw_url)[:150],
        "domain": hostname or "Unknown Host",
        "is_https": is_https,
        "is_ip": is_ip,
        "is_shortened": is_shortened,
        "risk_score": final_score,
        "risk_level": risk_level,
        "indicators": indicators
    }


def analyze_urls(text: str) -> Dict[str, Any]:
    try:
        raw_urls = extract_urls(text)
        url_details = [analyze_single_url(u) for u in raw_urls]
        
        total_urls = len(url_details)
        suspicious_urls = [u for u in url_details if u.get("risk_score", 0) >= 0.30]
        high_risk_urls = [u for u in url_details if u.get("risk_level") == "HIGH"]
        
        if not url_details:
            aggregate_score = 0.0
            risk_level = "LOW"
        else:
            max_score = max((u.get("risk_score", 0) for u in url_details), default=0.0)
            boost = min(0.2, (len(suspicious_urls) - 1) * 0.08) if len(suspicious_urls) > 1 else 0.0
            aggregate_score = round(min(1.0, max_score + boost), 2)
            
            if aggregate_score >= 0.60:
                risk_level = "HIGH"
            elif aggregate_score >= 0.30:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

        return {
            "urls_detected": total_urls,
            "suspicious_count": len(suspicious_urls),
            "high_risk_count": len(high_risk_urls),
            "url_risk_score": aggregate_score,
            "risk_level": risk_level,
            "url_details": url_details
        }
    except Exception:
        return {
            "urls_detected": 0,
            "suspicious_count": 0,
            "high_risk_count": 0,
            "url_risk_score": 0.0,
            "risk_level": "LOW",
            "url_details": []
        }