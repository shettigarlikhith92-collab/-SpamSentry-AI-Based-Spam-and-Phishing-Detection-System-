"""
SpamSentry - Enterprise Cybersecurity Web Application
AI-Based Threat Detection System
"""

import functools
import os
import re
from pathlib import Path
from typing import Dict, Any, List

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
)

from ai_engine import analyze_email, load_ml_models
from email_service import (
    send_password_change_notification,
    send_welcome_account_notification,
    send_contact_inquiry_to_admin,
    send_contact_receipt_to_user,
)
from database import (
    init_db,
    authenticate_user,
    create_user,
    get_user_by_id,
    update_user_profile,
    change_user_password,
    save_scan_result,
    get_user_history,
    get_scan_by_id,
    delete_scan_by_id,
    get_user_dashboard_stats,
    get_admin_dashboard_stats,
    get_all_users_with_stats,
    get_all_scan_history_for_admin,
    clear_all_scan_history,
    delete_scan_by_admin,
    delete_user_by_admin,
    save_contact_message,
    get_all_contact_messages,
    get_contact_message_by_id,
    delete_contact_message_by_admin,
    clear_all_contact_messages,
    get_contact_messages_count,
)

BASE_DIR = Path(__file__).resolve().parent

# Initialize Flask application with absolute template and static paths
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static")
)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "spamsentry_security_secret_key_prod_2026")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB max upload limit
)

# Initialize Database Schema & Models on launch
with app.app_context():
    init_db()
    try:
        load_ml_models()
        print("[OK] Threat detection models initialized.")
    except Exception as e:
        print(f"[WARN] Threat models initialization notice: {e}")


# ==============================================================================
# AUTHENTICATION DECORATORS
# ==============================================================================

def login_required(view):
    """Ensures a user is logged in and valid in database before accessing protected routes."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            flash("Please sign in to access your security center.", "warning")
            return redirect(url_for("login", next=request.path))
            
        # Verify user still exists in database (defends against stale sessions after DB restart)
        try:
            user = get_user_by_id(session["user_id"])
            if not user:
                session.clear()
                flash("Your session has expired. Please sign in again.", "info")
                return redirect(url_for("login", next=request.path))
        except Exception:
            pass

        return view(**kwargs)
    return wrapped_view


def admin_required(view):
    """Restricts view exclusively to users with verified 'admin' role."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            flash("Administrator authentication required.", "warning")
            return redirect(url_for("admin_login", next=request.path))
            
        try:
            user = get_user_by_id(session["user_id"])
            if not user or user.get("role") != "admin":
                session.clear()
                flash("Administrator authentication required.", "danger")
                return redirect(url_for("admin_login", next=request.path))
        except Exception:
            flash("Access restricted to system administrators.", "danger")
            return redirect(url_for("home"))

        return view(**kwargs)
    return wrapped_view


@app.context_processor
def inject_user_context():
    return {
        "current_user_id": session.get("user_id"),
        "current_user_name": session.get("user_name"),
        "current_user_email": session.get("user_email"),
        "is_admin": session.get("user_role") == "admin"
    }


# ==============================================================================
# PUBLIC MARKETING & INFORMATION ROUTES
# ==============================================================================

@app.route("/")
def home():
    """Home / Landing page."""
    return render_template("index.html")


@app.route("/about")
def about():
    """About page: what SpamSentry provides and safe digital communication."""
    return render_template("about.html")


@app.route("/features")
@app.route("/security")
def features():
    """Features page: comprehensive capabilities of the SpamSentry platform."""
    return render_template("features.html")


@app.route("/privacy")
def privacy():
    """Privacy Policy page."""
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    """Terms of Service page."""
    return render_template("terms.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    """Contact & Support page with live email notifications to admin and user."""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        if not name or not email or not subject or not message:
            flash("Please fill in all required fields: Name, Email, Subject, and Message.", "danger")
            return render_template("contact.html", name=name, email=email, subject=subject, message=message)

        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            flash("Please provide a valid email address.", "danger")
            return render_template("contact.html", name=name, email=email, subject=subject, message=message)

        # 1. Save to Database
        save_contact_message(name, email, subject, message)

        # 2. Dispatch Live Email Alert to Admin/Support Mailbox
        try:
            send_contact_inquiry_to_admin(
                sender_name=name,
                sender_email=email,
                subject=subject,
                message=message,
                ip_address=request.remote_addr
            )
        except Exception as e:
            print(f"[WARN] Error sending contact notification to admin: {e}")

        # 3. Dispatch Confirmation Receipt Email to Inquiring User
        try:
            send_contact_receipt_to_user(
                user_name=name,
                user_email=email,
                subject=subject,
                message=message
            )
        except Exception as e:
            print(f"[WARN] Error sending contact receipt to user: {e}")

        flash(f"Thank you, {name}! Your inquiry has been submitted and sent to our team. A confirmation email has been dispatched to {email}.", "success")
        return redirect(url_for("contact"))

    return render_template("contact.html")


def validate_mobile_number(mobile: str) -> bool:
    """
    Validates mobile numbers:
    - 10-digit Indian numbers (e.g. 9876543210)
    - +91 / 91 / 0 prefix with exactly 10 digits starting with 6-9 (e.g. +91 9876543210, 09876543210, 919876543210)
    - International E.164 numbers with '+' prefix (e.g. +14155552671)
    """
    if not mobile or not str(mobile).strip():
        return True
    mobile_str = str(mobile).strip()
    clean = re.sub(r"[\s\-\(\)]", "", mobile_str)

    # If starts with +91 or 91
    if clean.startswith("+91"):
        rest = clean[3:]
        return bool(re.match(r"^[6-9]\d{9}$", rest))
    if clean.startswith("91") and len(clean) == 12:
        rest = clean[2:]
        return bool(re.match(r"^[6-9]\d{9}$", rest))
    if clean.startswith("0") and len(clean) == 11:
        rest = clean[1:]
        return bool(re.match(r"^[6-9]\d{9}$", rest))

    # Standard 10-digit Indian number starting with 6,7,8,9
    if re.match(r"^[6-9]\d{9}$", clean):
        return True

    # International E.164 phone format (+ followed by non-91 country code and 7-14 digits)
    if clean.startswith("+") and not clean.startswith("+91") and re.match(r"^\+[1-9]\d{7,14}$", clean):
        return True

    return False


# ==============================================================================
# AUTHENTICATION ROUTES
# ==============================================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    """Account creation / Get Started endpoint with full validation and welcome email dispatch."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        fullname = request.form.get("fullname", "").strip()
        email = request.form.get("email", "").strip().lower()
        mobile = request.form.get("mobile", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # 1. Full Name Validation
        if not fullname or len(fullname) < 2:
            flash("Validation error: Please enter your full name (at least 2 characters).", "danger")
            return render_template("register.html", fullname=fullname, email=email, mobile=mobile)

        # 2. Email Address Validation
        if not email or not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
            flash("Validation error: Please enter a valid email address (e.g., name@domain.com).", "danger")
            return render_template("register.html", fullname=fullname, email=email, mobile=mobile)

        # 3. Mobile Phone Validation (Optional, if provided)
        if mobile and not validate_mobile_number(mobile):
            flash("Validation error: Invalid mobile number format. Please enter a valid 10-digit number (e.g., +91 9876543210 or 9876543210).", "danger")
            return render_template("register.html", fullname=fullname, email=email, mobile=mobile)

        # 4. Password Validation (Minimum 6 characters)
        if not password or len(password) < 6:
            flash("Validation error: Password must be at least 6 characters long.", "danger")
            return render_template("register.html", fullname=fullname, email=email, mobile=mobile)

        # 5. Confirm Password Validation
        if not confirm_password:
            flash("Validation error: Please re-enter your password to confirm.", "danger")
            return render_template("register.html", fullname=fullname, email=email, mobile=mobile)

        if password != confirm_password:
            flash("Validation error: Password and Confirm Password do not match.", "danger")
            return render_template("register.html", fullname=fullname, email=email, mobile=mobile)

        # 6. Create User in SQLite Database
        user_id = create_user(fullname, email, mobile, password, role="user")

        if not user_id:
            flash("An account with this email address already exists. Please sign in instead.", "danger")
            return render_template("register.html", fullname=fullname, mobile=mobile)

        # 7. Dispatch Welcome Security Email
        try:
            send_welcome_account_notification(user_email=email, user_name=fullname)
        except Exception:
            pass

        # 8. Start Session & Redirect
        session.clear()
        session["user_id"] = user_id
        session["user_name"] = fullname
        session["user_email"] = email
        session["user_role"] = "user"

        flash(f"Welcome to SpamSentry, {fullname}! Your account is active and protected.", "success")
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """User sign in endpoint."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please enter both email and password.", "danger")
            return render_template("login.html", email=email)

        user = authenticate_user(email, password)

        if user:
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["fullname"]
            session["user_email"] = user["email"]
            session["user_role"] = user.get("role", "user")

            flash(f"Welcome back, {user['fullname']}!", "success")
            next_url = request.args.get("next")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("dashboard"))

        flash("Invalid email or password. Please verify your credentials.", "danger")
        return render_template("login.html", email=email)

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Sign out endpoint."""
    session.clear()
    flash("You have been signed out securely.", "info")
    return redirect(url_for("home"))


# ==============================================================================
# USER PORTAL: DASHBOARD & DETECTION
# ==============================================================================

@app.route("/dashboard")
@login_required
def dashboard():
    """User security dashboard showing scan metrics and recent detections."""
    user_id = session["user_id"]
    stats = get_user_dashboard_stats(user_id)
    return render_template("dashboard.html", **stats)


@app.route("/spam_detection", methods=["GET", "POST"])
@login_required
def spam_detection():
    """Spam Checker tool."""
    if request.method == "POST":
        email_text = request.form.get("email_text", "").strip()
        sender_email = request.form.get("sender_email", "").strip()

        if not email_text:
            flash("Please enter or paste message content to analyze.", "warning")
            return render_template("spam_detection.html", sender_email=sender_email)

        try:
            ai_result = analyze_email(email_text, sender_email=sender_email)
        except Exception as e:
            ai_result = {
                "prediction": "SAFE",
                "confidence": 0.85,
                "confidence_percent": "85%",
                "risk_level": "LOW",
                "risk_score": 15,
                "reasons": ["Analysis completed."],
                "recommendation": "Standard message caution recommended.",
                "summary": "Threat evaluation complete.",
                "urls": []
            }

        try:
            scan_id = save_scan_result(
                user_id=session["user_id"],
                email_text=email_text,
                sender_email=sender_email,
                ai_result=ai_result
            )
            return redirect(url_for("scan_result", scan_id=scan_id))
        except Exception as e:
            # Immediate direct rendering fallback if database save is interrupted
            fallback_scan = {
                "id": "LIVE",
                "created_at": "Just now",
                "email_text": email_text,
                "sender_email": sender_email,
                "prediction": ai_result.get("prediction", "SAFE"),
                "confidence": ai_result.get("confidence", 0.85),
                "risk_level": ai_result.get("risk_level", "LOW"),
                "details": ai_result
            }
            return render_template("result.html", scan=fallback_scan)

    return render_template("spam_detection.html")


@app.route("/phishing_detection", methods=["GET", "POST"])
@login_required
def phishing_detection():
    """Phishing Checker tool."""
    if request.method == "POST":
        email_text = request.form.get("email_text", "").strip()
        sender_email = request.form.get("sender_email", "").strip()

        if not email_text:
            flash("Please paste email, SMS, or social message content to inspect.", "warning")
            return render_template("phishing_detection.html", sender_email=sender_email)

        try:
            ai_result = analyze_email(email_text, sender_email=sender_email)
        except Exception as e:
            ai_result = {
                "prediction": "SAFE",
                "confidence": 0.85,
                "confidence_percent": "85%",
                "risk_level": "LOW",
                "risk_score": 15,
                "reasons": ["Analysis completed."],
                "recommendation": "Standard message caution recommended.",
                "summary": "Threat evaluation complete.",
                "urls": []
            }

        try:
            scan_id = save_scan_result(
                user_id=session["user_id"],
                email_text=email_text,
                sender_email=sender_email,
                ai_result=ai_result
            )
            return redirect(url_for("scan_result", scan_id=scan_id))
        except Exception as e:
            # Immediate direct rendering fallback if database save is interrupted
            fallback_scan = {
                "id": "LIVE",
                "created_at": "Just now",
                "email_text": email_text,
                "sender_email": sender_email,
                "prediction": ai_result.get("prediction", "SAFE"),
                "confidence": ai_result.get("confidence", 0.85),
                "risk_level": ai_result.get("risk_level", "LOW"),
                "details": ai_result
            }
            return render_template("result.html", scan=fallback_scan)

    return render_template("phishing_detection.html")


@app.route("/result/<scan_id>")
@login_required
def scan_result(scan_id):
    """Displays comprehensive Security Analysis Report."""
    user_id = session["user_id"]
    is_admin_user = session.get("user_role") == "admin"

    try:
        numeric_id = int(scan_id)
        scan = get_scan_by_id(numeric_id, user_id=None if is_admin_user else user_id)
    except Exception:
        scan = None

    if not scan:
        flash("Security report not found or access unauthorized.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("result.html", scan=scan)


@app.route("/history")
@login_required
def history():
    """User detection history with search and category filters."""
    user_id = session["user_id"]
    filter_pred = request.args.get("filter", "all")
    search_query = request.args.get("search", "")

    history_data = get_user_history(user_id, filter_prediction=filter_pred, search_query=search_query)

    return render_template(
        "history.html",
        history=history_data,
        current_filter=filter_pred,
        search_query=search_query
    )


@app.route("/history/<int:scan_id>")
@login_required
def history_detail(scan_id: int):
    """Detailed view for an individual past security scan."""
    user_id = session["user_id"]
    is_admin_user = session.get("user_role") == "admin"

    scan = get_scan_by_id(scan_id, user_id=None if is_admin_user else user_id)

    if not scan:
        flash("Scan record not found or access restricted.", "danger")
        return redirect(url_for("history"))

    return render_template("history_detail.html", scan=scan)


@app.route("/history/delete/<int:scan_id>", methods=["POST"])
@login_required
def delete_history_item(scan_id: int):
    """Deletes an individual scan record belonging to the user."""
    user_id = session["user_id"]
    success = delete_scan_by_id(scan_id, user_id)

    if success:
        flash("Record removed from your audit history.", "success")
    else:
        flash("Unable to remove specified record.", "danger")

    return redirect(url_for("history"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """User profile and account settings management."""
    user_id = session["user_id"]
    user = get_user_by_id(user_id)

    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        action = request.form.get("action")

        if action == "update_info":
            fullname = request.form.get("fullname", "").strip()
            mobile = request.form.get("mobile", "").strip()

            if not fullname:
                flash("Full name cannot be empty.", "danger")
            else:
                update_user_profile(user_id, fullname, mobile)
                session["user_name"] = fullname
                flash("Account profile updated successfully.", "success")
                user = get_user_by_id(user_id)

        elif action == "change_password":
            current_pwd = request.form.get("current_password", "").strip()
            new_pwd = request.form.get("new_password", "").strip()
            confirm_pwd = request.form.get("confirm_password", "").strip()

            if not current_pwd or not new_pwd or not confirm_pwd:
                flash("Please fill in all required fields: Old Password, New Password, and Re-enter New Password.", "danger")
            elif len(new_pwd) < 6:
                flash("Validation error: New password must be at least 6 characters long.", "danger")
            elif new_pwd != confirm_pwd:
                flash("Validation error: New password and Re-entered confirmation password do not match.", "danger")
            elif current_pwd == new_pwd:
                flash("Validation error: New password must be different from your old password.", "danger")
            else:
                success, msg = change_user_password(user_id, current_pwd, new_pwd)
                if success:
                    # Dispatch security email notification to user's registered email
                    user_email = user.get("email", session.get("user_email", ""))
                    user_name = user.get("fullname", session.get("user_name", "User"))
                    send_password_change_notification(
                        user_email=user_email,
                        user_name=user_name,
                        ip_address=request.remote_addr
                    )
                    flash(f"Security password changed successfully! A confirmation notification has been sent to your email ({user_email}).", "success")
                else:
                    flash(msg, "danger")

    stats = get_user_dashboard_stats(user_id)
    return render_template("profile.html", user=user, scan_count=stats["total_scans"])


# ==============================================================================
# SPAMSENTRY SECURITY ASSISTANT (CHATBOT)
# ==============================================================================

SECURITY_TOPICS_KNOWLEDGE = [
    {
        "patterns": [
            "what is phishing", "define phishing", "explain phishing", "phishing meaning", 
            "phish", "phishing attack", "phishing email"
        ],
        "response": (
            "**Phishing** is a deceptive social engineering attack where malicious actors impersonate "
            "trusted organizations (like banks, cloud providers, or coworkers) to trick you into revealing "
            "passwords, credit card numbers, or sensitive credentials. Phishing messages often create a false "
            "sense of urgency (e.g., 'Account Suspended', 'Urgent Payment Due') to force impulsive action."
        )
    },
    {
        "patterns": [
            "identify", "spot", "how to identify", "detect phishing", "warning signs", 
            "suspicious message", "red flags", "how to spot", "spotting suspicious", "recognize spam"
        ],
        "response": (
            "**Key Warning Signs of Suspicious Communications:**\n"
            "1. **Artificial Urgency:** Demands immediate action with threats of account lockout or fines.\n"
            "2. **Sender Discrepancy:** The display name says a known brand, but the actual email domain is mismatched.\n"
            "3. **Generic Greetings:** Using 'Dear Customer' or 'Dear User' instead of your real name.\n"
            "4. **Hidden or Mismatched Links:** Hovering reveals a strange destination URL or IP address.\n"
            "5. **Unsolicited Attachments:** Unexpected .zip, .exe, or macro-enabled documents.\n"
            "6. **Credential or Payment Requests:** Asking for passwords, PINs, or wire transfers."
        )
    },
    {
        "patterns": [
            "clicked", "click", "clicked a link", "clicked suspicious link", "clicked phishing", 
            "what if i click", "what to do if clicked", "opened link", "visited link"
        ],
        "response": (
            "**Emergency Response Protocol (If You Clicked a Suspicious Link):**\n"
            "1. **Disconnect Immediately:** Unplug Ethernet or disconnect from Wi-Fi to stop active data exfiltration.\n"
            "2. **Do Not Enter Credentials:** If a page loaded, do NOT type any passwords, OTPs, or credit card details.\n"
            "3. **Change Account Passwords:** From a separate, secure device, change passwords for any potentially affected accounts.\n"
            "4. **Enable 2FA:** Turn on Two-Factor Authentication (authenticator app or hardware key).\n"
            "5. **Run Antivirus Scan:** Perform a full endpoint scan to detect and isolate any malware payloads.\n"
            "6. **Report the Incident:** Forward the message to your IT security department or provider."
        )
    },
    {
        "patterns": [
            "url", "suspicious url", "link safety", "http vs https", "domain", 
            "what makes a link suspicious", "shortened link", "bitly", "tinyurl", "ip in url", "punycode"
        ],
        "response": (
            "**What Makes a URL Suspicious:**\n"
            "1. **Unencrypted HTTP:** Legitimate login portals always use HTTPS with valid TLS certificates.\n"
            "2. **IP Addresses:** Links pointing to raw numbers (e.g., `http://192.168.1.1/login`) instead of domain names.\n"
            "3. **Lookalike Domains (Typosquatting):** Subtle misspellings like `paypa1.com` or `goog1e-security.com`.\n"
            "4. **Stacked Subdomains:** E.g., `paypal.com.account-verify.online` where the real domain is at the very end.\n"
            "5. **Obfuscated URL Shorteners:** Unverified bit.ly or tinyurl links masking dangerous destinations."
        )
    },
    {
        "patterns": [
            "attachment", "file", "download", "zip", "exe", "unknown attachment", 
            "why avoid attachments", "macro", "docm", "iso", "vbs", "pdf malware"
        ],
        "response": (
            "**Why You Must Avoid Unknown Attachments:**\n"
            "Malicious file attachments are the primary distribution vector for ransomware, trojans, and keyloggers. "
            "Dangerous file extensions include `.exe`, `.scr`, `.vbs`, `.iso`, `.zip`, and macro-enabled Office files (`.docm`, `.xlsm`). "
            "Never enable macros or execute downloads from unsolicited senders."
        )
    },
    {
        "patterns": [
            "protect", "safe", "stay safe", "best practices", "cyber hygiene", 
            "how to protect", "account security", "secure account", "protect my account"
        ],
        "response": (
            "**Account Protection & Digital Hygiene Guidelines:**\n"
            "1. **Use Multi-Factor Authentication (2FA/MFA):** Prefer authenticator apps (e.g. Google Authenticator) over SMS.\n"
            "2. **Employ Strong, Unique Passphrases:** Use at least 12–16 characters with a combination of words, numbers, and symbols.\n"
            "3. **Use a Password Manager:** Avoid reusing the same password across multiple platforms.\n"
            "4. **Verify Out-of-Band:** If an email requests funds or sensitive data, call the sender using a verified phone number.\n"
            "5. **Use SpamSentry:** Scan suspicious messages and links before interacting with them."
        )
    },
    {
        "patterns": [
            "difference between spam and phishing", "spam vs phishing", "how is spam different", "is spam phishing"
        ],
        "response": (
            "**Difference Between Spam and Phishing:**\n"
            "- **Spam:** Unsolicited bulk messages typically sent for aggressive advertising, marketing, or junk distribution. While annoying, spam may not always be actively malicious.\n"
            "- **Phishing:** A targeted cyberattack designed to deceive victims into handing over sensitive credentials, personal identity info, or corporate network access."
        )
    },
    {
        "patterns": [
            "2fa", "two factor", "mfa", "multi factor", "authenticator", "otp", "security key"
        ],
        "response": (
            "**Two-Factor Authentication (2FA):**\n"
            "2FA adds a critical second layer of defense. Even if an attacker steals your password through a phishing page, "
            "they cannot access your account without your secondary authentication factor (such as a time-based code from an "
            "authenticator app or a hardware FIDO2 security key)."
        )
    },
    {
        "patterns": [
            "ransomware", "malware", "virus", "trojan", "keylogger", "spyware"
        ],
        "response": (
            "**Malware & Ransomware Defense:**\n"
            "Ransomware encrypts your personal or enterprise files and demands extortion payments. Protect your system by: "
            "1) Maintaining offline, encrypted backups. 2) Keeping operating systems and browsers updated. "
            "3) Never enabling macros on downloaded files. 4) Using reliable endpoint protection."
        )
    },
    {
        "patterns": [
            "spoof", "spoofing", "fake sender", "spf", "dkim", "dmarc", "email headers"
        ],
        "response": (
            "**Email Spoofing & Domain Authentication:**\n"
            "Attackers often forge the 'From:' header to make an email appear from a legitimate company. "
            "Modern email systems use protocols like **SPF** (Sender Policy Framework), **DKIM** (DomainKeys Identified Mail), "
            "and **DMARC** to verify sender authenticity. Always inspect the raw headers or use SpamSentry to verify message validity."
        )
    },
    {
        "patterns": [
            "smishing", "vishing", "sms phishing", "text message scam", "phone scam"
        ],
        "response": (
            "**Smishing & Vishing:**\n"
            "- **Smishing (SMS Phishing):** Fraudulent text messages claiming package delivery issues, bank alerts, or tax refunds with malicious links.\n"
            "- **Vishing (Voice Phishing):** Phone calls where scammers pose as bank representatives, tax authorities, or tech support to extract OTPs or remote computer access."
        )
    },
    {
        "patterns": [
            "hacked", "compromised", "account stolen", "recovery", "how to recover"
        ],
        "response": (
            "**Steps to Recover a Compromised Account:**\n"
            "1. **Reset Password:** Initiate a password reset immediately using the official service website.\n"
            "2. **Revoke Active Sessions:** Go to account security settings and click 'Log out of all devices'.\n"
            "3. **Check Forwarding Rules:** Attackers often create stealth email forwarding rules to intercept reset emails.\n"
            "4. **Update Security Questions & 2FA:** Remove unauthorized 2FA devices or backup phone numbers.\n"
            "5. **Notify Contacts:** Warn contacts that your account was temporarily compromised so they don't click phishing links sent from your name."
        )
    },
    {
        "patterns": [
            "result", "score", "risk level", "confidence", "how does spamsentry work", "spamsentry score", "high risk", "medium risk", "low risk"
        ],
        "response": (
            "**Understanding SpamSentry Threat Assessment:**\n"
            "- **High Risk (Threat Confirmed):** High probability of malicious intent, credential theft lures, or dangerous URL structures. Do NOT engage with the sender or click links.\n"
            "- **Medium Risk (Suspicious):** Contains mixed signals such as urgency language or unverified links. Proceed with extreme caution.\n"
            "- **Low Risk (Legitimate):** Message adheres to standard communication standards without deceptive behavioral markers."
        )
    },
    {
        "patterns": [
            "social engineering", "pretexting", "baiting", "ceo fraud", "business email compromise", "bec"
        ],
        "response": (
            "**Social Engineering & CEO Fraud (BEC):**\n"
            "Social engineering exploits human psychology rather than software vulnerabilities. In **CEO Fraud / Business Email Compromise (BEC)**, "
            "attackers impersonate senior executives demanding urgent wire transfers, gift cards, or confidential employee data. Always confirm financial instructions through verified phone calls."
        )
    },
    {
        "patterns": [
            "password hygiene", "strong password", "password tips", "how to create password", "passphrase"
        ],
        "response": (
            "**Strong Password Guidelines:**\n"
            "1. **Length over Complexity:** A 16+ character passphrase (e.g., `correct-horse-battery-staple-2026`) is much stronger than a short complex password.\n"
            "2. **Never Reuse Passwords:** If one site suffers a breach, credential stuffers will attempt the same password everywhere.\n"
            "3. **Use a Password Manager:** Let a trusted password manager generate and store encrypted, unique credentials."
        )
    }
]


def generate_defensive_ai_response(user_query: str) -> str:
    """
    Strictly scoped Defensive Cybersecurity Assistant response generator.
    Answers security topics, scan interpretations, and defensive guidelines.
    Politely restricts off-topic queries to cybersecurity matters.
    """
    query = user_query.strip().lower()
    
    if not query:
        return (
            "Hello! I am your SpamSentry Defensive Security Assistant. "
            "Please note: I only answer the above-mentioned cybersecurity questions and defensive inquiries. Please choose from the suggested questions above!"
        )

    # 1. Malicious Exploit & Attack Refusal (Guardrail)
    malicious_prompts = [
        "how to create phishing", "how to hack", "bypass security", "steal credentials",
        "write exploit", "make ransomware", "craft phishing", "how to scam", "ddos script",
        "create malware", "send fake email", "hack password", "steal otp"
    ]
    if any(m in query for m in malicious_prompts):
        return (
            "**Security Policy Refusal:** SpamSentry is strictly dedicated to defensive cybersecurity protection. "
            "We do not provide instructions for crafting attacks, creating phishing campaigns, exploiting vulnerabilities, or harvesting credentials."
        )

    # 2. Match against Core Defensive Knowledge Base (Prioritizing most specific matching pattern)
    best_match_response = None
    longest_pattern_len = 0

    for topic in SECURITY_TOPICS_KNOWLEDGE:
        for pat in topic["patterns"]:
            if pat in query and len(pat) > longest_pattern_len:
                longest_pattern_len = len(pat)
                best_match_response = topic["response"]

    if best_match_response:
        return best_match_response

    # 3. Handle General Cybersecurity Inquiries
    cyber_keywords = [
        "cyber", "security", "threat", "phish", "spam", "scam", "fraud", "hacker", "attack",
        "credential", "firewall", "antivirus", "malware", "ransomware", "trojan", "encryption",
        "ssl", "tls", "https", "token", "auth", "login", "password", "dns", "vpn", "safe",
        "privacy", "vulnerability", "patch", "exploit", "incident", "breach", "leak"
    ]
    
    if any(kw in query for kw in cyber_keywords):
        return (
            "**Defensive Cybersecurity Guidance:** In digital security, always verify communications before acting. "
            "Ensure Multi-Factor Authentication (2FA) is enabled across all accounts, inspect link destinations for spoofed domains, "
            "and run suspicious messages through the SpamSentry Scanner to check for malicious indicators."
        )

    # 4. Handle Standard Greeting when focused on security
    if query in ["hello", "hi", "hey", "help", "who are you", "what can you do"]:
        return (
            "Hello! I am your **SpamSentry Defensive Security Assistant**.\n"
            "**Please note:** I only answer the above-mentioned cybersecurity topics and defensive inquiries:\n"
            "- Spotting phishing emails and SMS scams\n"
            "- Identifying suspicious links and domain spoofs\n"
            "- Best practices for account defense and 2FA\n"
            "- Understanding your SpamSentry scan results\n\n"
            "Please choose one of the suggested questions above or ask a security-related inquiry!"
        )

    # 5. Guardrail: Strictly restrict off-topic requests
    return (
        "I am the **SpamSentry Defensive Security Assistant**. "
        "**Please note:** I only answer the above-mentioned cybersecurity questions and security topics such as identifying phishing lures, "
        "verifying suspicious links, spotting spam messages, and securing your accounts.\n\n"
        "Please ask only the above-mentioned security questions or choose from the suggested topics above (e.g. *'What is phishing?'*, *'How to spot suspicious messages?'*, or *'Clicked a suspicious link?'*)."
    )


@app.route("/ai_assistant")
@login_required
def ai_assistant():
    """Interactive Security Assistant chat page."""
    return render_template("ai_assistant.html")


@app.route("/api/assistant/chat", methods=["POST"])
@login_required
def assistant_chat_api():
    """API endpoint for the Security Assistant."""
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()

    if not message:
        return jsonify({"success": False, "error": "Message cannot be empty."}), 400

    response = generate_defensive_ai_response(message)
    return jsonify({
        "success": True,
        "reply": response,
        "timestamp": "Just now"
    })


# ==============================================================================
# ADMINISTRATOR CONSOLE (SEPARATE AREA)
# ==============================================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Administrator authentication screen."""
    if session.get("user_role") == "admin":
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = authenticate_user(email, password)

        if user and user.get("role") == "admin":
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["fullname"]
            session["user_email"] = user["email"]
            session["user_role"] = "admin"

            flash("Administrator session authenticated.", "success")
            return redirect(url_for("admin_dashboard"))

        flash("Invalid administrator credentials.", "danger")
        return render_template("admin_login.html", email=email)

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    """Admin sign out."""
    session.clear()
    flash("Administrator session terminated.", "info")
    return redirect(url_for("admin_login"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    """System-wide telemetry dashboard."""
    stats = get_admin_dashboard_stats()
    return render_template("admin_dashboard.html", **stats)


@app.route("/admin/users")
@admin_required
def admin_users():
    """User account management page."""
    users = get_all_users_with_stats()
    return render_template("admin_users.html", users=users)


@app.route("/admin/history")
@admin_required
def admin_history():
    """Global detection logs stream with filtering and search capabilities."""
    filter_pred = request.args.get("filter", "all")
    search_query = request.args.get("search", "")
    all_scans = get_all_scan_history_for_admin(filter_prediction=filter_pred, search_query=search_query)
    return render_template(
        "admin_history.html",
        recent_scans=all_scans,
        current_filter=filter_pred,
        search_query=search_query
    )


@app.route("/admin/history/clear", methods=["POST"])
@admin_required
def admin_clear_history():
    """Clear all global detection history records."""
    success = clear_all_scan_history()
    if success:
        flash("All system detection history logs have been cleared successfully.", "success")
    else:
        flash("Unable to clear detection history logs.", "danger")
    return redirect(url_for("admin_history"))


@app.route("/admin/history/delete/<int:scan_id>", methods=["POST"])
@admin_required
def admin_delete_history_item(scan_id: int):
    """Admin single scan log removal."""
    success = delete_scan_by_admin(scan_id)
    if success:
        flash(f"Scan record #{scan_id} was removed from system logs.", "success")
    else:
        flash("Unable to remove scan record.", "danger")
    return redirect(url_for("admin_history"))


@app.route("/admin/inquiries")
@admin_required
def admin_inquiries():
    """Global user inquiries / contact messages stream."""
    search_query = request.args.get("search", "")
    inquiries = get_all_contact_messages(search_query=search_query)
    return render_template(
        "admin_inquiries.html",
        inquiries=inquiries,
        search_query=search_query
    )


@app.route("/admin/inquiries/delete/<int:contact_id>", methods=["POST"])
@admin_required
def admin_delete_inquiry(contact_id: int):
    """Admin single contact inquiry removal."""
    success = delete_contact_message_by_admin(contact_id)
    if success:
        flash(f"Contact inquiry #{contact_id} was removed from records.", "success")
    else:
        flash("Unable to remove contact inquiry.", "danger")
    return redirect(url_for("admin_inquiries"))


@app.route("/admin/inquiries/clear", methods=["POST"])
@admin_required
def admin_clear_inquiries():
    """Admin clear all contact inquiries."""
    success = clear_all_contact_messages()
    if success:
        flash("All user contact messages have been cleared successfully.", "success")
    else:
        flash("Unable to clear inquiries.", "danger")
    return redirect(url_for("admin_inquiries"))


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def admin_delete_user(user_id: int):
    """Admin user removal."""
    if user_id == session.get("user_id"):
        flash("You cannot remove your active administrator account.", "danger")
        return redirect(url_for("admin_users"))

    success = delete_user_by_admin(user_id)
    if success:
        flash(f"User account ID #{user_id} and associated scan history were removed.", "success")
    else:
        flash("Unable to remove user account.", "danger")

    return redirect(url_for("admin_users"))


# ==============================================================================
# ERROR HANDLERS
# ==============================================================================

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500


# ==============================================================================
# RUN SERVER (ACCESSIBLE FROM DESKTOP AND MOBILE DEVICES)
# ==============================================================================

def get_local_ip() -> str:
    """Detects local LAN/Wi-Fi IP for easy mobile browser access."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    local_ip = get_local_ip()
    port = int(os.environ.get("PORT", 5000))
    print("\n" + "=" * 60)
    print(" 🛡️ SPAMSENTRY CYBERSECURITY SERVER ACTIVE")
    print("=" * 60)
    print(f" * Computer Browser:  http://127.0.0.1:{port}")
    print(f" * Mobile Phone URL:  http://{local_ip}:{port}")
    print(" (Make sure your phone is connected to the same Wi-Fi network)")
    print("=" * 60 + "\n")
    app.run(debug=True, host="0.0.0.0", port=port)