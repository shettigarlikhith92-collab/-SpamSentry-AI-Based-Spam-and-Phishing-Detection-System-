# SpamSentry – Cybersecurity Web Application

**SpamSentry** is an AI-powered threat detection platform built with Python Flask and SQLite. It provides real-time protection against malicious messages by combining **Machine Learning Lexical Classification** with an **Explainable Phishing Heuristic Engine** and **Zero-Execution Static URL Analysis**.

> **Tagline**: *"Stay Safe. Detect Threats Before They Reach You."*

---

## 🛡️ Core Capabilities

- **Spam Checker**: Evaluates message structures for bulk distribution and promotional phrasing.
- **Phishing Checker**: Identifies credential theft, urgency ultimatums, and fraudulent sender domains.
- **Static Link Inspection**: Zero-execution decomposition of web addresses checking encryption, IP hosts, and shorteners.
- **Security Score & Reports**: Transparent LOW / MEDIUM / HIGH risk ratings with plain-English indicator checklists.
- **Interactive Security Assistant**: Defensive cybersecurity guidance answering user questions on threat avoidance.
- **Private Audit History**: Searchable, filterable scan archive with complete past report views.
- **Administrator Portal**: Global telemetry stream, user account directory, and system-wide threat breakdown.

---

## 🚀 Quick Launch (Windows)

```powershell
# 1. Open project directory
cd c:\Users\shett\OneDrive\Pictures\Desktop\SpamSentry

# 2. Start the web server
python app.py
```

Open your browser and navigate to: **`http://127.0.0.1:5000`**

---

## 🔑 Default Credentials

| Portal | URL | Email | Password |
|---|---|---|---|
| **User Sign In** | `/login` | `shettigarlikhith92@gmail.com` | `1234` |
| **New User Registration** | `/register` | *(Any valid email)* | *(Any password)* |
| **Administrator Console** | `/admin/login` | `admin@spamsentry.com` | `Admin@1234` |
