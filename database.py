"""
SpamSentry - Database Module
Provides robust SQLite connection management, safe migrations, password hashing,
foreign-key enforcement, and cloud-sync immune storage in LocalAppData.
"""

import sqlite3
import json
import os
import shutil
import time
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = Path(__file__).resolve().parent

# Ensure resilient database storage location immune to OneDrive sync locks
def _resolve_database_path() -> Path:
    # 1. Try local app data first (immune to OneDrive sync locks on Windows)
    local_app_data = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if local_app_data:
        app_dir = Path(local_app_data) / "SpamSentry"
        try:
            app_dir.mkdir(parents=True, exist_ok=True)
            target_db = app_dir / "database.db"
            
            # If workspace already has a legacy database.db and local app data does not, copy it over
            workspace_db = BASE_DIR / "database.db"
            if workspace_db.exists() and not target_db.exists():
                try:
                    shutil.copy2(str(workspace_db), str(target_db))
                except Exception:
                    pass
            return target_db
        except Exception:
            pass

    # 2. Fallback to workspace directory
    return BASE_DIR / "database.db"


DB_PATH = _resolve_database_path()


def get_db_connection() -> sqlite3.Connection:
    """
    Establishes and returns a connection with Row factory, Foreign Keys,
    and extended busy timeout to prevent lockouts.
    """
    global DB_PATH
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    for attempt in range(3):
        try:
            conn = sqlite3.connect(
                str(DB_PATH.resolve()),
                timeout=60.0,
                check_same_thread=False
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 30000;")
            try:
                conn.execute("PRAGMA journal_mode = WAL;")
            except Exception:
                pass
            conn.execute("PRAGMA synchronous = NORMAL;")
            return conn
        except sqlite3.OperationalError:
            if attempt == 2:
                # Fallback to local temp db if primary path is locked
                fallback_path = Path(os.environ.get("TEMP", os.environ.get("TMP", str(BASE_DIR)))) / "spamsentry_db.db"
                conn = sqlite3.connect(str(fallback_path), timeout=60.0, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                return conn
            time.sleep(0.1)

    conn = sqlite3.connect(str(DB_PATH.resolve()), timeout=60.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initializes the database schema and performs non-destructive schema migrations
    preserving all existing users, records, and history data.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = OFF;")

        # 1. Create or migrate USERS table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        users_exists = cursor.fetchone()

        if not users_exists:
            cursor.execute("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fullname TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    mobile TEXT,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
        else:
            cursor.execute("PRAGMA table_info(users);")
            user_cols = {row["name"]: row for row in cursor.fetchall()}

            if "password_hash" not in user_cols or "password" in user_cols or "role" not in user_cols:
                cursor.execute("DROP TABLE IF EXISTS users_migrated;")
                cursor.execute("""
                    CREATE TABLE users_migrated (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        fullname TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        mobile TEXT,
                        password_hash TEXT NOT NULL,
                        role TEXT DEFAULT 'user',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)

                cursor.execute("SELECT * FROM users;")
                old_users = cursor.fetchall()
                for u in old_users:
                    u_dict = dict(u)
                    fullname = u_dict.get("fullname", "")
                    email = u_dict.get("email", "")
                    mobile = u_dict.get("mobile", "")
                    role = u_dict.get("role", "user")
                    created_at = u_dict.get("created_at")

                    raw_pwd = u_dict.get("password_hash") or u_dict.get("password", "")
                    if raw_pwd and (raw_pwd.startswith("scrypt:") or raw_pwd.startswith("pbkdf2:")):
                        pwd_hash = raw_pwd
                    elif raw_pwd:
                        pwd_hash = generate_password_hash(raw_pwd)
                    else:
                        pwd_hash = generate_password_hash("password123")

                    if created_at:
                        cursor.execute("""
                            INSERT INTO users_migrated (id, fullname, email, mobile, password_hash, role, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (u_dict["id"], fullname, email, mobile, pwd_hash, role, created_at))
                    else:
                        cursor.execute("""
                            INSERT INTO users_migrated (id, fullname, email, mobile, password_hash, role)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (u_dict["id"], fullname, email, mobile, pwd_hash, role))

                cursor.execute("DROP TABLE users;")
                cursor.execute("ALTER TABLE users_migrated RENAME TO users;")
                conn.commit()
                print("[OK] Users table successfully migrated to modern schema with password hashing.")

        # 2. Create or migrate HISTORY table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='history';")
        history_exists = cursor.fetchone()

        if not history_exists:
            cursor.execute("""
                CREATE TABLE history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    email_text TEXT NOT NULL,
                    sender_email TEXT,
                    prediction TEXT NOT NULL,
                    confidence REAL DEFAULT 0.0,
                    spam_score REAL DEFAULT 0.0,
                    phishing_score REAL DEFAULT 0.0,
                    risk_level TEXT DEFAULT 'LOW',
                    explanation TEXT,
                    urls_detected INTEGER DEFAULT 0,
                    suspicious_urls INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)
            conn.commit()
        else:
            cursor.execute("PRAGMA table_info(history);")
            hist_cols = {row["name"]: row for row in cursor.fetchall()}

            if "confidence" not in hist_cols or "result" in hist_cols or "date" in hist_cols:
                cursor.execute("DROP TABLE IF EXISTS history_migrated;")
                cursor.execute("""
                    CREATE TABLE history_migrated (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        email_text TEXT NOT NULL,
                        sender_email TEXT,
                        prediction TEXT NOT NULL,
                        confidence REAL DEFAULT 0.0,
                        spam_score REAL DEFAULT 0.0,
                        phishing_score REAL DEFAULT 0.0,
                        risk_level TEXT DEFAULT 'LOW',
                        explanation TEXT,
                        urls_detected INTEGER DEFAULT 0,
                        suspicious_urls INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                    );
                """)

                cursor.execute("SELECT * FROM history;")
                old_history = cursor.fetchall()
                for h in old_history:
                    h_dict = dict(h)
                    user_id = h_dict.get("user_id", 1)
                    email_text = h_dict.get("email_text", "")
                    sender_email = h_dict.get("sender_email", "")
                    prediction = h_dict.get("prediction") or h_dict.get("result", "Safe")
                    confidence = float(h_dict.get("confidence") or 0.85)
                    spam_score = float(h_dict.get("spam_score") or (0.85 if prediction.lower() == "spam" else 0.15))
                    phishing_score = float(h_dict.get("phishing_score") or (0.85 if prediction.lower() == "phishing" else 0.10))
                    risk_level = h_dict.get("risk_level") or ("HIGH" if prediction.lower() in ["spam", "phishing"] else "LOW")
                    explanation = h_dict.get("explanation") or json.dumps({"reasons": [f"Scanned message: {prediction}"]})
                    urls_detected = int(h_dict.get("urls_detected") or 0)
                    suspicious_urls = int(h_dict.get("suspicious_urls") or 0)
                    created_at = h_dict.get("created_at") or h_dict.get("date")

                    if created_at:
                        cursor.execute("""
                            INSERT INTO history_migrated (
                                id, user_id, email_text, sender_email, prediction, confidence,
                                spam_score, phishing_score, risk_level, explanation,
                                urls_detected, suspicious_urls, created_at
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            h_dict["id"], user_id, email_text, sender_email, prediction, confidence,
                            spam_score, phishing_score, risk_level, explanation,
                            urls_detected, suspicious_urls, created_at
                        ))
                    else:
                        cursor.execute("""
                            INSERT INTO history_migrated (
                                id, user_id, email_text, sender_email, prediction, confidence,
                                spam_score, phishing_score, risk_level, explanation,
                                urls_detected, suspicious_urls
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            h_dict["id"], user_id, email_text, sender_email, prediction, confidence,
                            spam_score, phishing_score, risk_level, explanation,
                            urls_detected, suspicious_urls
                        ))

                cursor.execute("DROP TABLE history;")
                cursor.execute("ALTER TABLE history_migrated RENAME TO history;")
                conn.commit()
                print("[OK] History table successfully migrated to modern schema with all columns.")

        # 3. Create CONTACTS table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()

        # 4. Seed default Admin Account if none exists
        admin_email = os.environ.get("ADMIN_EMAIL", "admin@spamsentry.com").lower().strip()
        admin_password = os.environ.get("ADMIN_PASSWORD", "Admin@1234")

        cursor.execute("SELECT id FROM users WHERE role='admin' OR email=?", (admin_email,))
        admin = cursor.fetchone()

        if not admin:
            admin_hash = generate_password_hash(admin_password)
            cursor.execute("""
                INSERT INTO users (fullname, email, mobile, password_hash, role)
                VALUES (?, ?, ?, ?, ?)
            """, ("System Administrator", admin_email, "1234567890", admin_hash, "admin"))
        # 5. Seed default user account if none exists
        default_user_email = "shettigarlikhith92@gmail.com"
        cursor.execute("SELECT id FROM users WHERE email=?", (default_user_email,))
        default_user = cursor.fetchone()
        if not default_user:
            user_hash = generate_password_hash("1234")
            cursor.execute("""
                INSERT INTO users (fullname, email, mobile, password_hash, role)
                VALUES (?, ?, ?, ?, ?)
            """, ("Likhith Shettigar", default_user_email, "9876543210", user_hash, "user"))
            conn.commit()
            print(f"[OK] Default user account seeded: {default_user_email} / 1234")

        print(f"[OK] Database initialized and active at: {DB_PATH}")
    finally:
        conn.close()


# ==============================================================================
# USER DATA ACCESS HELPERS
# ==============================================================================

def create_user(fullname: str, email: str, mobile: str, password: str, role: str = "user") -> Optional[int]:
    """Creates a new user with hashed password."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        pwd_hash = generate_password_hash(password)
        cursor.execute("""
            INSERT INTO users (fullname, email, mobile, password_hash, role)
            VALUES (?, ?, ?, ?, ?)
        """, (fullname.strip(), email.strip().lower(), mobile.strip() if mobile else "", pwd_hash, role))
        conn.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
    """Validates user email and password against stored password_hash."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(email)=?", (email.strip().lower(),))
        user = cursor.fetchone()
        if not user:
            return None

        stored_hash = user["password_hash"] if "password_hash" in user.keys() and user["password_hash"] else None
        if not stored_hash and "password" in user.keys():
            if user["password"] == password:
                return dict(user)
            return None

        if stored_hash and check_password_hash(stored_hash, password):
            return dict(user)

        return None
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Fetches user details by user ID."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, fullname, email, mobile, role, created_at FROM users WHERE id=?", (user_id,))
        user = cursor.fetchone()
        return dict(user) if user else None
    finally:
        conn.close()


def update_user_profile(user_id: int, fullname: str, mobile: str) -> bool:
    """Updates user's name and mobile number."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET fullname=?, mobile=? WHERE id=?", (fullname.strip(), mobile.strip(), user_id))
        conn.commit()
        return True
    finally:
        conn.close()


def change_user_password(user_id: int, current_password: str, new_password: str) -> Tuple[bool, str]:
    """Verifies current password with cryptographic authentication and updates to new hashed password."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE id=?", (user_id,))
        row = cursor.fetchone()
        
        if not row or not row["password_hash"]:
            return False, "Authentication error: User account not found."

        if not check_password_hash(row["password_hash"], current_password):
            return False, "Authentication error: Current password does not match our records."

        if current_password == new_password:
            return False, "Validation error: New password must be different from your current password."

        if len(new_password) < 6:
            return False, "Validation error: New password must be at least 6 characters long."

        new_hash = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user_id))
        conn.commit()
        return True, "Security password changed successfully."
    finally:
        conn.close()


# ==============================================================================
# SCAN HISTORY ACCESS HELPERS
# ==============================================================================

def save_scan_result(user_id: int, email_text: str, sender_email: Optional[str], ai_result: Dict[str, Any]) -> int:
    """Persists a complete AI scan result into the history table."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        explanation_json = json.dumps({
            "reasons": ai_result.get("reasons", []),
            "recommendation": ai_result.get("recommendation", ""),
            "summary": ai_result.get("summary", ""),
            "urls": ai_result.get("urls", [])
        })

        cursor.execute("""
            INSERT INTO history (
                user_id, email_text, sender_email, prediction, confidence,
                spam_score, phishing_score, risk_level, explanation,
                urls_detected, suspicious_urls
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            email_text,
            sender_email or "",
            ai_result.get("prediction", "LEGITIMATE"),
            ai_result.get("confidence", 0.0),
            ai_result.get("spam_score", 0.0),
            ai_result.get("phishing_score", 0.0),
            ai_result.get("risk_level", "LOW"),
            explanation_json,
            ai_result.get("urls_detected", 0),
            ai_result.get("suspicious_urls_count", 0)
        ))
        conn.commit()
        scan_id = cursor.lastrowid
        return scan_id if scan_id else 1
    finally:
        conn.close()


def get_user_history(user_id: int, filter_prediction: Optional[str] = None, search_query: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetches scan history belonging strictly to the requesting user."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        query = "SELECT * FROM history WHERE user_id = ?"
        params: List[Any] = [user_id]

        if filter_prediction and filter_prediction.lower() != "all":
            query += " AND LOWER(prediction) = ?"
            params.append(filter_prediction.lower())

        if search_query and search_query.strip():
            query += " AND (email_text LIKE ? OR sender_email LIKE ?)"
            params.append(f"%{search_query.strip()}%")
            params.append(f"%{search_query.strip()}%")

        query += " ORDER BY id DESC"

        cursor.execute(query, params)
        rows = cursor.fetchall()

        results = []
        for r in rows:
            item = dict(r)
            if item.get("explanation"):
                try:
                    item["details"] = json.loads(item["explanation"])
                except Exception:
                    item["details"] = {"reasons": [item["explanation"]]}
            else:
                item["details"] = {"reasons": []}
            results.append(item)
        return results
    finally:
        conn.close()


def get_scan_by_id(scan_id: int, user_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """
    Fetches a specific scan result. If user_id is provided, enforces ownership (prevents IDOR).
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        if user_id is not None:
            cursor.execute("SELECT * FROM history WHERE id=? AND user_id=?", (scan_id, user_id))
        else:
            cursor.execute("SELECT * FROM history WHERE id=?", (scan_id,))

        row = cursor.fetchone()
        if not row:
            return None

        item = dict(row)
        if item.get("explanation"):
            try:
                item["details"] = json.loads(item["explanation"])
            except Exception:
                item["details"] = {"reasons": [item["explanation"]]}
        else:
            item["details"] = {"reasons": [], "recommendation": "", "summary": "", "urls": []}
        return item
    finally:
        conn.close()


def delete_scan_by_id(scan_id: int, user_id: int) -> bool:
    """Deletes a specific scan record if owned by the user."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM history WHERE id=? AND user_id=?", (scan_id, user_id))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def get_user_dashboard_stats(user_id: int) -> Dict[str, Any]:
    """Calculates user statistics from SQLite database."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM history WHERE user_id=?", (user_id,))
        total_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM history WHERE user_id=? AND UPPER(prediction)='SPAM'", (user_id,))
        total_spam = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM history WHERE user_id=? AND UPPER(prediction)='PHISHING'", (user_id,))
        total_phishing = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM history WHERE user_id=? AND UPPER(prediction) IN ('SAFE', 'LEGITIMATE')", (user_id,))
        total_safe = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM history WHERE user_id=? AND UPPER(risk_level)='HIGH'", (user_id,))
        high_risk = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM history WHERE user_id=? AND UPPER(risk_level)='MEDIUM'", (user_id,))
        medium_risk = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM history WHERE user_id=? AND UPPER(risk_level)='LOW'", (user_id,))
        low_risk = cursor.fetchone()[0]

        cursor.execute("""
            SELECT id, email_text, sender_email, prediction, confidence, risk_level, created_at
            FROM history
            WHERE user_id=?
            ORDER BY id DESC
            LIMIT 6
        """, (user_id,))
        recent_scans = [dict(r) for r in cursor.fetchall()]

        return {
            "total_scans": total_scans,
            "total_spam": total_spam,
            "total_phishing": total_phishing,
            "total_safe": total_safe,
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk,
            "recent_scans": recent_scans
        }
    finally:
        conn.close()


# ==============================================================================
# ADMIN DATA ACCESS HELPERS
# ==============================================================================

def get_admin_dashboard_stats() -> Dict[str, Any]:
    """Calculates system-wide analytics for administrator view."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM users WHERE role != 'admin'")
        total_users = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM history")
        total_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM history WHERE UPPER(prediction)='SPAM'")
        total_spam = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM history WHERE UPPER(prediction)='PHISHING'")
        total_phishing = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM history WHERE UPPER(prediction) IN ('SAFE', 'LEGITIMATE')")
        total_safe = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM history WHERE UPPER(risk_level)='HIGH'")
        high_risk = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM contacts")
        total_inquiries = cursor.fetchone()[0]

        cursor.execute("""
            SELECT h.id, h.user_id, u.fullname, u.email as user_email, h.email_text,
                   h.prediction, h.risk_level, h.confidence, h.created_at
            FROM history h
            LEFT JOIN users u ON h.user_id = u.id
            ORDER BY h.id DESC
            LIMIT 8
        """)
        recent_activity = [dict(r) for r in cursor.fetchall()]

        return {
            "total_users": total_users,
            "total_scans": total_scans,
            "total_spam": total_spam,
            "total_phishing": total_phishing,
            "total_safe": total_safe,
            "high_risk": high_risk,
            "total_inquiries": total_inquiries,
            "recent_activity": recent_activity
        }
    finally:
        conn.close()


def get_all_users_with_stats() -> List[Dict[str, Any]]:
    """Returns all registered users with their individual scan metrics."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.id, u.fullname, u.email, u.mobile, u.role, u.created_at,
                   COUNT(h.id) as scan_count
            FROM users u
            LEFT JOIN history h ON u.id = h.user_id
            GROUP BY u.id
            ORDER BY u.id DESC
        """)
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()


def get_all_scan_history_for_admin(filter_prediction: Optional[str] = None, search_query: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetches all system scan history records with user metadata for administrator."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        query = """
            SELECT h.id, h.user_id, u.fullname, u.email as user_email, h.email_text,
                   h.sender_email, h.prediction, h.risk_level, h.confidence, h.created_at
            FROM history h
            LEFT JOIN users u ON h.user_id = u.id
            WHERE 1=1
        """
        params: List[Any] = []
        if filter_prediction and filter_prediction.lower() != "all":
            query += " AND LOWER(h.prediction) = ?"
            params.append(filter_prediction.lower())

        if search_query and search_query.strip():
            query += " AND (h.email_text LIKE ? OR h.sender_email LIKE ? OR u.fullname LIKE ? OR u.email LIKE ?)"
            term = f"%{search_query.strip()}%"
            params.extend([term, term, term, term])

        query += " ORDER BY h.id DESC"
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()


def clear_all_scan_history() -> bool:
    """Deletes all records from the history table (Admin action)."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM history;")
        conn.commit()
        return True
    finally:
        conn.close()


def delete_scan_by_admin(scan_id: int) -> bool:
    """Deletes a single scan record by ID regardless of owner (Admin action)."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM history WHERE id=?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def delete_user_by_admin(user_id: int) -> bool:
    """Deletes a user account and associated history records (via CASCADE)."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE id=?", (user_id,))
        row = cursor.fetchone()
        if not row or row["role"] == "admin":
            return False

        cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def save_contact_message(name: str, email: str, subject: str, message: str) -> int:
    """Saves a submitted contact inquiry to the contacts table and returns its ID."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO contacts (name, email, subject, message)
            VALUES (?, ?, ?, ?)
        """, (name.strip(), email.strip(), subject.strip(), message.strip()))
        conn.commit()
        return cursor.lastrowid or 1
    finally:
        conn.close()


def get_all_contact_messages(search_query: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves all user contact inquiries for administrator review."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        query = "SELECT * FROM contacts"
        params: List[Any] = []
        if search_query and search_query.strip():
            query += " WHERE name LIKE ? OR email LIKE ? OR subject LIKE ? OR message LIKE ?"
            term = f"%{search_query.strip()}%"
            params.extend([term, term, term, term])
        query += " ORDER BY id DESC"
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()


def get_contact_message_by_id(contact_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a specific contact inquiry by ID."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM contacts WHERE id=?", (contact_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def delete_contact_message_by_admin(contact_id: int) -> bool:
    """Deletes a specific contact message by ID."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM contacts WHERE id=?", (contact_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def clear_all_contact_messages() -> bool:
    """Deletes all contact messages (Admin action)."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM contacts;")
        conn.commit()
        return True
    finally:
        conn.close()


def get_contact_messages_count() -> int:
    """Returns the total number of contact inquiries in the database."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM contacts")
        return cursor.fetchone()[0]
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()