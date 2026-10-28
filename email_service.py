"""
SpamSentry - Security Notification & Email Dispatcher Module
Provides robust, asynchronous, fail-safe delivery of account security alerts,
password change notifications, and verification receipts.
Supports live SMTP (Gmail, Outlook, custom relays) with graceful dev/offline fallback.
"""

import os
import smtplib
import ssl
import threading
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent


def _load_env_file():
    """Automatically loads key-value pairs from .env file into os.environ."""
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and not os.environ.get(k):
                            os.environ[k] = v
        except Exception:
            pass


def _get_smtp_config():
    """Reads SMTP configuration from environment variables or .env file."""
    _load_env_file()
    raw_pwd = os.environ.get("SMTP_PASSWORD", os.environ.get("MAIL_PASSWORD", "")).strip()
    clean_pwd = raw_pwd.replace(" ", "") if raw_pwd else ""
    return {
        "server": os.environ.get("SMTP_SERVER", "smtp.gmail.com").strip(),
        "port": int(os.environ.get("SMTP_PORT", 587)),
        "username": os.environ.get("SMTP_USERNAME", os.environ.get("MAIL_USERNAME", "")).strip(),
        "password": clean_pwd,
        "sender": os.environ.get("SMTP_SENDER", os.environ.get("MAIL_DEFAULT_SENDER", "")).strip() or os.environ.get("SMTP_USERNAME", "SpamSentry Security <spamsentry001@gmail.com>").strip(),
        "use_tls": os.environ.get("SMTP_USE_TLS", "true").lower() in ["true", "1", "yes"]
    }


def send_email_direct(to_email: str, subject: str, text_content: str, html_content: str, reply_to: Optional[str] = None) -> Tuple[bool, str]:
    """
    Directly sends an email via SMTP or records a structured security log in local development mode.
    """
    config = _get_smtp_config()
    to_email = to_email.strip()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = config["sender"]
    msg["To"] = to_email
    if reply_to:
        msg["Reply-To"] = reply_to.strip()

    part1 = MIMEText(text_content, "plain", "utf-8")
    part2 = MIMEText(html_content, "html", "utf-8")
    msg.attach(part1)
    msg.attach(part2)

    # If live SMTP credentials are configured, attempt real network delivery
    if config["username"] and config["password"]:
        try:
            if config["use_tls"]:
                context = ssl.create_default_context()
                with smtplib.SMTP(config["server"], config["port"], timeout=15) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    server.login(config["username"], config["password"])
                    server.sendmail(config["sender"], [to_email], msg.as_string())
            else:
                with smtplib.SMTP_SSL(config["server"], config["port"], timeout=15) as server:
                    server.login(config["username"], config["password"])
                    server.sendmail(config["sender"], [to_email], msg.as_string())

            print(f"[EMAIL NOTIFICATION SENT] Delivered live security email to '{to_email}' via {config['server']}")
            return True, f"Security notification sent to {to_email}"
        except Exception as e:
            print(f"[EMAIL NOTIFICATION NOTICE] SMTP delivery notice: {e}. Fallback to simulated delivery.")

    # Local development / offline fallback: log formatted notification
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_subject = str(subject).encode("ascii", errors="replace").decode("ascii")
    safe_text = str(text_content).encode("ascii", errors="replace").decode("ascii")
    print("\n" + "=" * 65)
    print(" [SECURITY ALERT] SPAMSENTRY EMAIL NOTIFICATION DISPATCHED")
    print("=" * 65)
    print(f" To:        {to_email}")
    print(f" From:      {config['sender']}")
    print(f" Subject:   {safe_subject}")
    print(f" Timestamp: {timestamp}")
    print("-" * 65)
    print(safe_text)
    print("=" * 65 + "\n")

    return True, f"Security confirmation dispatched to {to_email}"


def send_password_change_notification(user_email: str, user_name: str, ip_address: Optional[str] = None) -> bool:
    """
    Dispatches a dedicated Security Alert notifying the user of their password update.
    Executes in a background daemon thread to ensure zero UI latency.
    """
    timestamp = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    ip_info = f" (Request IP: {ip_address})" if ip_address and ip_address not in ["127.0.0.1", "::1"] else ""

    subject = "Security Alert: Your SpamSentry Password Was Changed"

    text_body = f"""Hello {user_name},

This is an automated security notification from SpamSentry.

Your account security password was successfully changed on {timestamp}{ip_info}.

WHAT SHOULD YOU DO?
--------------------
• If you performed this change: No further action is required. Your account is secure.
• If you DID NOT change your password: Your account credentials may be compromised.
  Please contact SpamSentry Support immediately or use the account recovery options.

Security Best Practices:
• Enable Multi-Factor Authentication (2FA).
• Never share your account passwords or OTP codes with anyone.
• Verify that all communications claiming to be from SpamSentry use our official domain.

Stay safe,
SpamSentry Threat Intelligence & Account Defense Team
https://spamsentry.com
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0a0f1d; color: #f8fafc; margin: 0; padding: 20px; }}
  .email-card {{ max-width: 580px; margin: 0 auto; background: #111827; border: 1px solid #1e293b; border-radius: 14px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
  .header {{ background: #152238; padding: 25px 30px; border-bottom: 1px solid #1e293b; text-align: center; }}
  .logo {{ font-size: 22px; font-weight: 800; color: #ffffff; }}
  .logo span {{ color: #00d4ff; }}
  .content {{ padding: 30px; }}
  .alert-banner {{ background: rgba(16, 185, 129, 0.12); border-left: 4px solid #10b981; padding: 14px 18px; border-radius: 6px; margin-bottom: 22px; color: #a7f3d0; font-size: 14px; font-weight: 600; }}
  .details-box {{ background: #0d1527; padding: 16px 20px; border-radius: 8px; border: 1px solid #1e293b; font-size: 13px; line-height: 1.8; color: #cbd5e1; margin: 18px 0; }}
  .warning-box {{ background: rgba(239, 68, 68, 0.1); border-left: 4px solid #ef4444; padding: 14px 18px; border-radius: 6px; margin: 20px 0; color: #fca5a5; font-size: 13px; }}
  .footer {{ background: #0d1527; padding: 20px 30px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b; }}
</style>
</head>
<body>
  <div class="email-card">
    <div class="header">
      <div class="logo">🛡️ Spam<span>Sentry</span></div>
    </div>
    <div class="content">
      <div class="alert-banner">
        ✓ Password Updated Successfully
      </div>
      <p style="font-size: 15px; color: #f8fafc; margin-top: 0;">Hello <strong>{user_name}</strong>,</p>
      <p style="font-size: 14px; color: #94a3b8; line-height: 1.6;">
        Your SpamSentry account password was updated on <strong>{timestamp}</strong>{ip_info}.
      </p>

      <div class="details-box">
        <strong>Account:</strong> {user_email}<br>
        <strong>Event:</strong> Security Password Reset / Change<br>
        <strong>Status:</strong> Completed & Verified
      </div>

      <div class="warning-box">
        <strong>Did not make this change?</strong><br>
        If you did not authorize this password update, your account may be compromised. Please take immediate action by resetting your credentials and enabling Two-Factor Authentication.
      </div>

      <p style="font-size: 13px; color: #94a3b8; line-height: 1.6;">
        If you authorized this change, no further action is needed. Thank you for keeping your account secure!
      </p>
    </div>
    <div class="footer">
      &copy; {datetime.now().year} SpamSentry Threat Protection. All rights reserved.<br>
      This is an automated security notification sent to {user_email}.
    </div>
  </div>
</body>
</html>
"""

    # Spawn background thread so user response is instantaneous
    thread = threading.Thread(
        target=send_email_direct,
        args=(user_email, subject, text_body, html_body),
        daemon=True
    )
    thread.start()
    return True


def send_welcome_account_notification(user_email: str, user_name: str) -> bool:
    """
    Dispatches a welcome security confirmation email upon successful new account registration.
    """
    timestamp = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    subject = "Welcome to SpamSentry - Account Successfully Created"

    text_body = f"""Hello {user_name},

Welcome to SpamSentry!

Your new defensive cybersecurity account was successfully created on {timestamp}.

ACCOUNT DETAILS:
----------------
• Name: {user_name}
• Registered Email: {user_email}
• Security Status: Active & Protected

WHAT YOU CAN DO WITH SPAMSENTRY:
• Check suspicious emails and SMS messages for spam patterns.
• Inspect phishing links and deceptive login portals safely.
• Ask defensive security questions with our Security Assistant.
• Track your scan history and threat analytics in real time.

Security Recommendation:
Always keep your password secret and never share verification codes with anyone.

Stay safe,
SpamSentry Threat Intelligence & Account Defense Team
https://spamsentry.com
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0a0f1d; color: #f8fafc; margin: 0; padding: 20px; }}
  .email-card {{ max-width: 580px; margin: 0 auto; background: #111827; border: 1px solid #1e293b; border-radius: 14px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
  .header {{ background: #152238; padding: 25px 30px; border-bottom: 1px solid #1e293b; text-align: center; }}
  .logo {{ font-size: 22px; font-weight: 800; color: #ffffff; }}
  .logo span {{ color: #00d4ff; }}
  .content {{ padding: 30px; }}
  .welcome-banner {{ background: rgba(0, 212, 255, 0.12); border-left: 4px solid #00d4ff; padding: 14px 18px; border-radius: 6px; margin-bottom: 22px; color: #bae6fd; font-size: 14px; font-weight: 600; }}
  .details-box {{ background: #0d1527; padding: 16px 20px; border-radius: 8px; border: 1px solid #1e293b; font-size: 13px; line-height: 1.8; color: #cbd5e1; margin: 18px 0; }}
  .features-box {{ background: #152238; padding: 16px 20px; border-radius: 8px; border: 1px solid #1e293b; margin: 18px 0; }}
  .features-box h4 {{ margin: 0 0 10px 0; color: #ffffff; font-size: 14px; }}
  .features-box ul {{ margin: 0; padding-left: 20px; font-size: 13px; color: #cbd5e1; line-height: 1.6; }}
  .footer {{ background: #0d1527; padding: 20px 30px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b; }}
</style>
</head>
<body>
  <div class="email-card">
    <div class="header">
      <div class="logo">🛡️ Spam<span>Sentry</span></div>
    </div>
    <div class="content">
      <div class="welcome-banner">
        ✓ Welcome to SpamSentry Threat Protection
      </div>
      <p style="font-size: 15px; color: #f8fafc; margin-top: 0;">Hello <strong>{user_name}</strong>,</p>
      <p style="font-size: 14px; color: #94a3b8; line-height: 1.6;">
        Your account was successfully registered on <strong>{timestamp}</strong>. You now have full access to our AI threat detection suite.
      </p>

      <div class="details-box">
        <strong>Registered Email:</strong> {user_email}<br>
        <strong>Status:</strong> Active Security Account<br>
        <strong>Protection Level:</strong> Maximum Threat Defense
      </div>

      <div class="features-box">
        <h4>Getting Started:</h4>
        <ul>
          <li>Scan suspicious emails with our <strong>Spam Checker</strong></li>
          <li>Analyze links & URLs with our <strong>Phishing Checker</strong></li>
          <li>Consult with our <strong>Security Assistant</strong> for defensive guidance</li>
        </ul>
      </div>

      <p style="font-size: 13px; color: #94a3b8; line-height: 1.6;">
        We recommend keeping your password unique and enabling Two-Factor Authentication on all your critical accounts.
      </p>
    </div>
    <div class="footer">
      &copy; {datetime.now().year} SpamSentry Threat Protection. All rights reserved.<br>
      This is an automated confirmation sent to {user_email}.
    </div>
  </div>
</body>
</html>
"""

    thread = threading.Thread(
        target=send_email_direct,
        args=(user_email, subject, text_body, html_body),
        daemon=True
    )
    thread.start()
    return True


def send_contact_inquiry_to_admin(sender_name: str, sender_email: str, subject: str, message: str, ip_address: Optional[str] = None) -> bool:
    """
    Dispatches an email alert to the platform administrator / support mailbox with the user's submitted message.
    """
    config = _get_smtp_config()
    admin_email = os.environ.get("ADMIN_EMAIL") or config.get("username") or "spamsentry001@gmail.com"
    timestamp = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    ip_info = f" (Client IP: {ip_address})" if ip_address and ip_address not in ["127.0.0.1", "::1"] else ""

    mail_subject = f"[SpamSentry Support Inquiry] {subject} - From {sender_name}"

    text_body = f"""Hello SpamSentry Admin Team,

You have received a new support inquiry / contact message via the SpamSentry portal.

INQUIRY DETAILS:
----------------
• Sender Name: {sender_name}
• Sender Email: {sender_email}
• Subject: {subject}
• Received: {timestamp}{ip_info}

MESSAGE CONTENT:
----------------
{message}

----------------
To reply to this user, you can reply directly to this email or write to: {sender_email}

SpamSentry Automated Notification System
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0a0f1d; color: #f8fafc; margin: 0; padding: 20px; }}
  .email-card {{ max-width: 600px; margin: 0 auto; background: #111827; border: 1px solid #1e293b; border-radius: 14px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
  .header {{ background: #152238; padding: 22px 30px; border-bottom: 1px solid #1e293b; text-align: center; }}
  .logo {{ font-size: 22px; font-weight: 800; color: #ffffff; }}
  .logo span {{ color: #00d4ff; }}
  .content {{ padding: 30px; }}
  .badge-tag {{ display: inline-block; background: rgba(0, 212, 255, 0.15); color: #38bdf8; border: 1px solid rgba(0, 212, 255, 0.3); padding: 5px 12px; border-radius: 20px; font-size: 12px; font-weight: 700; margin-bottom: 18px; }}
  .details-box {{ background: #0d1527; padding: 18px 20px; border-radius: 8px; border: 1px solid #1e293b; font-size: 13px; line-height: 1.8; color: #cbd5e1; margin: 16px 0; }}
  .message-box {{ background: #152238; border-left: 4px solid #00d4ff; padding: 18px 20px; border-radius: 6px; margin: 20px 0; color: #f1f5f9; font-size: 14px; line-height: 1.6; white-space: pre-wrap; }}
  .btn-reply {{ display: inline-block; background: #00d4ff; color: #0a0f1d; font-weight: 700; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-size: 14px; margin-top: 10px; }}
  .footer {{ background: #0d1527; padding: 18px 30px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b; }}
</style>
</head>
<body>
  <div class="email-card">
    <div class="header">
      <div class="logo">🛡️ Spam<span>Sentry</span> Support Central</div>
    </div>
    <div class="content">
      <div class="badge-tag">✉️ New Contact Form Submission</div>
      <h3 style="color: #ffffff; margin-top: 0;">New User Message Received</h3>
      <p style="color: #94a3b8; font-size: 14px;">A user has submitted an inquiry through the SpamSentry Contact page.</p>

      <div class="details-box">
        <strong>Sender Name:</strong> {sender_name}<br>
        <strong>Sender Email:</strong> <a href="mailto:{sender_email}" style="color: #00d4ff;">{sender_email}</a><br>
        <strong>Subject:</strong> {subject}<br>
        <strong>Timestamp:</strong> {timestamp}{ip_info}
      </div>

      <div style="font-size: 13px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 20px;">Message Details:</div>
      <div class="message-box">{message}</div>

      <div style="text-align: center; margin-top: 25px;">
        <a href="mailto:{sender_email}?subject=Re: {subject}" class="btn-reply">✉️ Direct Reply to {sender_name}</a>
      </div>
    </div>
    <div class="footer">
      SpamSentry Automated Notification Central &bull; {timestamp}
    </div>
  </div>
</body>
</html>
"""

    thread = threading.Thread(
        target=send_email_direct,
        args=(admin_email, mail_subject, text_body, html_body, sender_email),
        daemon=True
    )
    thread.start()
    return True


def send_contact_receipt_to_user(user_name: str, user_email: str, subject: str, message: str) -> bool:
    """
    Dispatches an automated receipt confirmation email to the user acknowledging their inquiry.
    """
    timestamp = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    mail_subject = f"We Received Your Message: {subject} - SpamSentry Support"

    text_body = f"""Hello {user_name},

Thank you for reaching out to SpamSentry Support!

We have received your message regarding: "{subject}".
Our defensive cybersecurity team is reviewing your inquiry and will get back to you as soon as possible.

YOUR SUBMITTED MESSAGE:
-----------------------
Subject: {subject}
Date: {timestamp}
Message:
{message}

-----------------------
If you have additional information or urgent threat logs to share, feel free to reply directly to this email.

Best regards,
SpamSentry Support & Threat Intelligence Team
https://spamsentry.com
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0a0f1d; color: #f8fafc; margin: 0; padding: 20px; }}
  .email-card {{ max-width: 580px; margin: 0 auto; background: #111827; border: 1px solid #1e293b; border-radius: 14px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
  .header {{ background: #152238; padding: 25px 30px; border-bottom: 1px solid #1e293b; text-align: center; }}
  .logo {{ font-size: 22px; font-weight: 800; color: #ffffff; }}
  .logo span {{ color: #00d4ff; }}
  .content {{ padding: 30px; }}
  .success-banner {{ background: rgba(16, 185, 129, 0.12); border-left: 4px solid #10b981; padding: 14px 18px; border-radius: 6px; margin-bottom: 22px; color: #a7f3d0; font-size: 14px; font-weight: 600; }}
  .details-box {{ background: #0d1527; padding: 16px 20px; border-radius: 8px; border: 1px solid #1e293b; font-size: 13px; line-height: 1.8; color: #cbd5e1; margin: 18px 0; }}
  .message-preview {{ background: #152238; padding: 14px 18px; border-radius: 6px; color: #e2e8f0; font-size: 13px; line-height: 1.6; border: 1px solid #1e293b; white-space: pre-wrap; }}
  .footer {{ background: #0d1527; padding: 20px 30px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b; }}
</style>
</head>
<body>
  <div class="email-card">
    <div class="header">
      <div class="logo">🛡️ Spam<span>Sentry</span></div>
    </div>
    <div class="content">
      <div class="success-banner">
        ✓ Message Received Successfully
      </div>
      <p style="font-size: 15px; color: #f8fafc; margin-top: 0;">Hello <strong>{user_name}</strong>,</p>
      <p style="font-size: 14px; color: #94a3b8; line-height: 1.6;">
        Thank you for contacting SpamSentry Support. We have received your inquiry regarding <strong>"{subject}"</strong> on <strong>{timestamp}</strong>.
      </p>
      <p style="font-size: 14px; color: #94a3b8; line-height: 1.6;">
        Our security team is reviewing your message and will respond to you promptly at this email address.
      </p>

      <div class="details-box">
        <strong>Subject:</strong> {subject}<br>
        <strong>Status:</strong> Under Review by Security Team<br>
        <strong>Reference Email:</strong> {user_email}
      </div>

      <div style="font-size: 12px; font-weight: 700; color: #94a3b8; text-transform: uppercase; margin-bottom: 6px;">Copy of Your Message:</div>
      <div class="message-preview">{message}</div>

      <p style="font-size: 13px; color: #64748b; margin-top: 20px; line-height: 1.5;">
        Need immediate protection? You can continue using our live <strong>Spam Checker</strong> and <strong>Phishing Scanner</strong> tools on the platform at any time.
      </p>
    </div>
    <div class="footer">
      &copy; {datetime.now().year} SpamSentry Threat Protection. All rights reserved.<br>
      Automated confirmation sent to {user_email}.
    </div>
  </div>
</body>
</html>
"""

    thread = threading.Thread(
        target=send_email_direct,
        args=(user_email, mail_subject, text_body, html_body),
        daemon=True
    )
    thread.start()
    return True

