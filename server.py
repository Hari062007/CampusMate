"""
CampusMate Server
Implements secure, invitation-based classroom registration, RBAC,
persistent data storage, and REST/RPC endpoints.

DUAL-ENGINE ARCHITECTURE:
1. Supabase Cloud PostgreSQL & Auth Engine: Active when SUPABASE_URL and
   SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_KEY) are configured in the environment.
   Uses Supabase Auth and cloud PostgreSQL tables & RPC functions.
2. Local SQLite Fallback Engine: Active when Supabase credentials are not set.
   Stores data in campusmate.db for offline development and local automated tests.
"""

import os
import sys
import sqlite3
import secrets
import hashlib
import datetime
import re
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g

# Optional Supabase Python Client
try:
    from supabase import create_client, Client
    SUPABASE_SDK_AVAILABLE = True
except ImportError:
    SUPABASE_SDK_AVAILABLE = False
    Client = None

app = Flask(__name__, static_folder="public")
DB_PATH = os.path.join(os.path.dirname(__file__), "campusmate.db")

# ----------------------------------------------------------------------------
# ENVIRONMENT & ENGINE INITIALIZATION
# ----------------------------------------------------------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = (
    os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    or os.environ.get("SUPABASE_KEY", "").strip()
)
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "").strip()
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "campusmate-dev-secret-key-2026")
app.secret_key = FLASK_SECRET_KEY

supabase_admin: Client | None = None
HAS_SUPABASE = False

if SUPABASE_SDK_AVAILABLE and SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    try:
        supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
        HAS_SUPABASE = True
        print(f"[CampusMate] Supabase Cloud Engine Initialized: {SUPABASE_URL}")
    except Exception as e:
        print(f"[CampusMate] WARNING: Failed to initialize Supabase client: {e}. Falling back to SQLite.")
        HAS_SUPABASE = False
else:
    print("[CampusMate] Running in Local SQLite Engine mode (campusmate.db).")

def get_user_supabase_client(token: str) -> Client | None:
    """
    Returns a Supabase client configured with the user's JWT bearer token,
    ensuring PostgreSQL Row Level Security (RLS) evaluates auth.uid() = <user_id>.
    """
    if not HAS_SUPABASE or not SUPABASE_SDK_AVAILABLE:
        return None
    try:
        key = SUPABASE_ANON_KEY or SUPABASE_SERVICE_ROLE_KEY
        client = create_client(SUPABASE_URL, key)
        client.postgrest.auth(token)
        return client
    except Exception:
        return supabase_admin

# ----------------------------------------------------------------------------
# SQLITE DATABASE INITIALIZATION (LOCAL / FALLBACK MODE)
# ----------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = ON")

    # 1. Profiles Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS profiles (
        id TEXT PRIMARY KEY,
        full_name TEXT NOT NULL,
        college_email TEXT NOT NULL UNIQUE,
        roll_number TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        is_faculty BOOLEAN DEFAULT 0,
        email_verified BOOLEAN DEFAULT 1,
        created_at TEXT NOT NULL
    );
    """)

    # 2. Classrooms Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS classrooms (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT DEFAULT '',
        owner_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE RESTRICT,
        created_at TEXT NOT NULL
    );
    """)

    # 3. Classroom Members Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS classroom_members (
        id TEXT PRIMARY KEY,
        classroom_id TEXT NOT NULL REFERENCES classrooms(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK(role IN ('owner', 'member')),
        membership_status TEXT NOT NULL CHECK(membership_status IN ('approved', 'removed')),
        joined_at TEXT NOT NULL,
        UNIQUE(classroom_id, user_id)
    );
    """)

    # 4. Classroom Invitations Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS classroom_invitations (
        id TEXT PRIMARY KEY,
        classroom_id TEXT NOT NULL REFERENCES classrooms(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        created_by TEXT NOT NULL REFERENCES profiles(id),
        expires_at TEXT,
        revoked_at TEXT,
        created_at TEXT NOT NULL
    );
    """)

    # 5. Classroom Join Requests Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS classroom_join_requests (
        id TEXT PRIMARY KEY,
        classroom_id TEXT NOT NULL REFERENCES classrooms(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
        status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected', 'cancelled')),
        requested_at TEXT NOT NULL,
        reviewed_at TEXT,
        reviewed_by TEXT REFERENCES profiles(id),
        UNIQUE(classroom_id, user_id)
    );
    """)

    # 6. Classroom Posts Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS classroom_posts (
        id TEXT PRIMARY KEY,
        classroom_id TEXT NOT NULL REFERENCES classrooms(id) ON DELETE CASCADE,
        author_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        is_faculty_verified BOOLEAN DEFAULT 0,
        created_at TEXT NOT NULL
    );
    """)

    # 7. Assignments Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS assignments (
        id TEXT PRIMARY KEY,
        classroom_id TEXT NOT NULL REFERENCES classrooms(id) ON DELETE CASCADE,
        created_by TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        description TEXT DEFAULT '',
        subject TEXT NOT NULL,
        due_date TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    # 8. User Tasks Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_tasks (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
        assignment_id TEXT REFERENCES assignments(id) ON DELETE SET NULL,
        classroom_id TEXT NOT NULL REFERENCES classrooms(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        due_date TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'in_progress', 'completed')),
        reminder_at TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(user_id, assignment_id)
    );
    """)

    # 9. Notifications Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
        classroom_id TEXT REFERENCES classrooms(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT NOT NULL,
        is_read BOOLEAN DEFAULT 0,
        created_at TEXT NOT NULL
    );
    """)

    # 10. Sessions Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL
    );
    """)

    # 11. Notification Preferences Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS notification_preferences (
        user_id TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
        reminder_hours_before INTEGER DEFAULT 24,
        email_notifications_enabled BOOLEAN DEFAULT 1
    );
    """)

    conn.commit()
    conn.close()

init_db()

# ----------------------------------------------------------------------------
# SECURITY & AUTH UTILITIES
# ----------------------------------------------------------------------------
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return f"{salt}:{hashed.hex()}"

def verify_password(stored: str, provided: str) -> bool:
    try:
        salt, stored_hash = stored.split(":")
        calc_hash = hashlib.pbkdf2_hmac("sha256", provided.encode("utf-8"), salt.encode("utf-8"), 100000)
        return secrets.compare_digest(stored_hash, calc_hash.hex())
    except Exception:
        return False

def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif "token" in request.args:
            token = request.args.get("token")

        if not token:
            return jsonify({"error": "Unauthorized: Missing authentication token"}), 401

        if HAS_SUPABASE:
            try:
                user_res = supabase_admin.auth.get_user(token)
                if not user_res or not user_res.user:
                    return jsonify({"error": "Unauthorized: Invalid or expired session"}), 401
                user_id = str(user_res.user.id)
                prof_res = supabase_admin.table("profiles").select("*").eq("id", user_id).execute()
                if not prof_res.data:
                    # Fallback if profile row is not yet provisioned
                    meta = user_res.user.user_metadata or {}
                    profile = {
                        "id": user_id,
                        "full_name": meta.get("full_name") or user_res.user.email.split("@")[0],
                        "college_email": user_res.user.email,
                        "roll_number": meta.get("roll_number", "UNASSIGNED"),
                        "is_faculty": False,
                    }
                else:
                    profile = prof_res.data[0]

                g.current_user = profile
                g.token = token
                g.supabase_user_client = get_user_supabase_client(token)
                return f(*args, **kwargs)
            except Exception as e:
                return jsonify({"error": f"Unauthorized: {str(e)}"}), 401

        # SQLite Fallback Engine
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT user_id FROM sessions WHERE token = ?", (token,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Unauthorized: Invalid or expired session"}), 401

        cur.execute("SELECT id, full_name, college_email, roll_number, is_faculty FROM profiles WHERE id = ?", (row["user_id"],))
        user = cur.fetchone()
        if not user:
            return jsonify({"error": "User profile not found"}), 401

        g.current_user = dict(user)
        g.token = token
        return f(*args, **kwargs)
    return decorated

def is_approved_member(db, classroom_id: str, user_id: str) -> bool:
    if HAS_SUPABASE:
        try:
            res = supabase_admin.table("classroom_members").select("id").eq("classroom_id", classroom_id).eq("user_id", user_id).eq("membership_status", "approved").execute()
            return bool(res.data)
        except Exception:
            return False
    cur = db.cursor()
    cur.execute("""
        SELECT 1 FROM classroom_members
        WHERE classroom_id = ? AND user_id = ? AND membership_status = 'approved'
    """, (classroom_id, user_id))
    return cur.fetchone() is not None

def is_classroom_owner(db, classroom_id: str, user_id: str) -> bool:
    if HAS_SUPABASE:
        try:
            res = supabase_admin.table("classrooms").select("id").eq("id", classroom_id).eq("owner_id", user_id).execute()
            return bool(res.data)
        except Exception:
            return False
    cur = db.cursor()
    cur.execute("SELECT 1 FROM classrooms WHERE id = ? AND owner_id = ?", (classroom_id, user_id))
    return cur.fetchone() is not None

# ----------------------------------------------------------------------------
# HEALTH CHECK ROUTE (FOR RENDER HEALTH MONITORS)
# ----------------------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def health_check():
    engine_name = "supabase" if HAS_SUPABASE else "sqlite"
    return jsonify({
        "status": "healthy",
        "app": "CampusMate",
        "version": "2.0.0",
        "engine": engine_name,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }), 200

# ----------------------------------------------------------------------------
# AUTHENTICATION ROUTES
# ----------------------------------------------------------------------------
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    full_name = (data.get("full_name") or "").strip()
    college_email = (data.get("college_email") or "").strip().lower()
    roll_number = (data.get("roll_number") or "").strip()
    password = data.get("password") or ""

    if not full_name:
        return jsonify({"error": "Full Name is required."}), 400
    if not college_email or not EMAIL_REGEX.match(college_email):
        return jsonify({"error": "A valid college email address is required."}), 400
    if not roll_number:
        return jsonify({"error": "Roll Number is required."}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long."}), 400

    if HAS_SUPABASE:
        try:
            # Case-insensitive check on existing profiles
            exist_chk = supabase_admin.table("profiles").select("id").ilike("college_email", college_email).execute()
            if exist_chk.data:
                return jsonify({"error": "An account with this college email already exists. Please sign in."}), 400

            # Create user in Supabase Auth
            auth_res = supabase_admin.auth.admin.create_user({
                "email": college_email,
                "password": password,
                "email_confirm": True,
                "user_metadata": {
                    "full_name": full_name,
                    "roll_number": roll_number
                }
            })
            if not auth_res or not auth_res.user:
                return jsonify({"error": "Registration failed with Supabase Auth."}), 400

            user_id = str(auth_res.user.id)

            # Ensure profile exists (in case auth trigger is pending or not yet configured)
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            profile_data = {
                "id": user_id,
                "full_name": full_name,
                "college_email": college_email,
                "roll_number": roll_number,
                "is_faculty": False,
                "created_at": now_iso,
                "updated_at": now_iso
            }
            supabase_admin.table("profiles").upsert(profile_data).execute()

            # Default notification preferences
            supabase_admin.table("notification_preferences").upsert({
                "user_id": user_id,
                "reminder_hours_before": 24,
                "email_notifications_enabled": True
            }).execute()

            # Sign in to obtain session access token
            sign_in = supabase_admin.auth.sign_in_with_password({"email": college_email, "password": password})
            token = sign_in.session.access_token

            return jsonify({
                "token": token,
                "user": profile_data,
                "message": "Registration successful."
            }), 201
        except Exception as e:
            return jsonify({"error": f"Registration failed: {str(e)}"}), 400

    # SQLite Engine
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id FROM profiles WHERE lower(college_email) = ?", (college_email,))
    if cur.fetchone():
        return jsonify({"error": "An account with this college email already exists. Please sign in."}), 400

    user_id = secrets.token_hex(16)
    pwd_hash = hash_password(password)
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        cur.execute("""
            INSERT INTO profiles (id, full_name, college_email, roll_number, password_hash, is_faculty, email_verified, created_at)
            VALUES (?, ?, ?, ?, ?, 0, 1, ?)
        """, (user_id, full_name, college_email, roll_number, pwd_hash, now_str))

        cur.execute("""
            INSERT INTO notification_preferences (user_id, reminder_hours_before, email_notifications_enabled)
            VALUES (?, 24, 1)
        """, (user_id,))

        session_token = secrets.token_urlsafe(32)
        cur.execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", (session_token, user_id, now_str))
        db.commit()

        user_profile = {
            "id": user_id,
            "full_name": full_name,
            "college_email": college_email,
            "roll_number": roll_number,
            "is_faculty": False
        }

        return jsonify({
            "token": session_token,
            "user": user_profile,
            "message": "Registration successful."
        }), 201
    except Exception as e:
        db.rollback()
        return jsonify({"error": f"Database error during registration: {str(e)}"}), 500

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    college_email = (data.get("college_email") or "").strip().lower()
    password = data.get("password") or ""

    if not college_email or not password:
        return jsonify({"error": "College email and password are required."}), 400

    if HAS_SUPABASE:
        try:
            sign_in = supabase_admin.auth.sign_in_with_password({"email": college_email, "password": password})
            if not sign_in or not sign_in.user or not sign_in.session:
                return jsonify({"error": "Invalid email or password."}), 401

            user_id = str(sign_in.user.id)
            token = sign_in.session.access_token

            prof_res = supabase_admin.table("profiles").select("*").eq("id", user_id).execute()
            if prof_res.data:
                profile = prof_res.data[0]
            else:
                meta = sign_in.user.user_metadata or {}
                profile = {
                    "id": user_id,
                    "full_name": meta.get("full_name") or college_email.split("@")[0],
                    "college_email": college_email,
                    "roll_number": meta.get("roll_number", "UNASSIGNED"),
                    "is_faculty": False
                }

            return jsonify({
                "token": token,
                "user": profile,
                "message": "Login successful."
            }), 200
        except Exception as e:
            return jsonify({"error": "Invalid email or password."}), 401

    # SQLite Engine
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM profiles WHERE lower(college_email) = ?", (college_email,))
    user = cur.fetchone()
    if not user or not verify_password(user["password_hash"], password):
        return jsonify({"error": "Invalid email or password."}), 401

    session_token = secrets.token_urlsafe(32)
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cur.execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", (session_token, user["id"], now_str))
    db.commit()

    user_profile = {
        "id": user["id"],
        "full_name": user["full_name"],
        "college_email": user["college_email"],
        "roll_number": user["roll_number"],
        "is_faculty": bool(user["is_faculty"])
    }

    return jsonify({
        "token": session_token,
        "user": user_profile,
        "message": "Login successful."
    }), 200

@app.route("/api/auth/me", methods=["GET"])
@auth_required
def get_me():
    return jsonify({"user": g.current_user}), 200

@app.route("/api/auth/profile", methods=["PATCH"])
@auth_required
def update_profile():
    data = request.get_json(silent=True) or {}
    full_name = (data.get("full_name") or "").strip()
    roll_number = (data.get("roll_number") or "").strip()

    if not full_name and not roll_number:
        return jsonify({"error": "At least one field (full_name or roll_number) is required to update."}), 400

    user_id = g.current_user["id"]

    if HAS_SUPABASE:
        try:
            update_data = {}
            if full_name:
                update_data["full_name"] = full_name
            if roll_number:
                update_data["roll_number"] = roll_number
            update_data["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

            res = supabase_admin.table("profiles").update(update_data).eq("id", user_id).execute()
            updated_profile = res.data[0] if res.data else {**g.current_user, **update_data}
            return jsonify({"user": updated_profile, "message": "Profile updated successfully."}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to update profile: {str(e)}"}), 500

    # SQLite Engine
    db = get_db()
    cur = db.cursor()
    if full_name and roll_number:
        cur.execute("UPDATE profiles SET full_name = ?, roll_number = ? WHERE id = ?", (full_name, roll_number, user_id))
    elif full_name:
        cur.execute("UPDATE profiles SET full_name = ? WHERE id = ?", (full_name, user_id))
    elif roll_number:
        cur.execute("UPDATE profiles SET roll_number = ? WHERE id = ?", (roll_number, user_id))
    db.commit()

    cur.execute("SELECT id, full_name, college_email, roll_number, is_faculty FROM profiles WHERE id = ?", (user_id,))
    updated_user = dict(cur.fetchone())
    return jsonify({"user": updated_user, "message": "Profile updated successfully."}), 200

@app.route("/api/auth/logout", methods=["POST"])
@auth_required
def logout():
    if HAS_SUPABASE:
        try:
            supabase_admin.auth.admin.sign_out(g.token)
        except Exception:
            pass
        return jsonify({"success": True, "message": "Logged out successfully."}), 200

    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM sessions WHERE token = ?", (g.token,))
    db.commit()
    return jsonify({"success": True, "message": "Logged out successfully."}), 200

# ----------------------------------------------------------------------------
# CLASSROOM MANAGEMENT ROUTES
# ----------------------------------------------------------------------------
@app.route("/api/classrooms", methods=["GET"])
@auth_required
def list_classrooms():
    user_id = g.current_user["id"]

    if HAS_SUPABASE:
        try:
            # Classrooms owned or where approved member
            owned = supabase_admin.table("classrooms").select("*").eq("owner_id", user_id).execute().data or []
            memberships = supabase_admin.table("classroom_members").select("classroom_id, role").eq("user_id", user_id).eq("membership_status", "approved").execute().data or []

            member_cls_map = {m["classroom_id"]: m["role"] for m in memberships}
            all_cls_ids = list(set([c["id"] for c in owned] + list(member_cls_map.keys())))

            if not all_cls_ids:
                return jsonify({"classrooms": []}), 200

            all_cls = supabase_admin.table("classrooms").select("*").in_("id", all_cls_ids).execute().data or []
            classrooms_list = []
            for c in all_cls:
                c_id = c["id"]
                is_owner = c["owner_id"] == user_id
                user_role = "owner" if is_owner else member_cls_map.get(c_id, "member")

                # Count members
                m_count_res = supabase_admin.table("classroom_members").select("id", count="exact").eq("classroom_id", c_id).eq("membership_status", "approved").execute()
                member_count = m_count_res.count if m_count_res.count is not None else 1

                classrooms_list.append({
                    "id": c_id,
                    "name": c["name"],
                    "description": c.get("description", ""),
                    "owner_id": c["owner_id"],
                    "is_owner": is_owner,
                    "role": user_role,
                    "user_role": user_role,
                    "member_count": member_count,
                    "created_at": c.get("created_at")
                })

            return jsonify({"classrooms": classrooms_list}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to list classrooms: {str(e)}"}), 500

    # SQLite Engine
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT
            c.id, c.name, c.description, c.owner_id, c.created_at,
            cm.role AS user_role,
            (SELECT COUNT(*) FROM classroom_members WHERE classroom_id = c.id AND membership_status = 'approved') AS member_count
        FROM classrooms c
        JOIN classroom_members cm ON c.id = cm.classroom_id
        WHERE cm.user_id = ? AND cm.membership_status = 'approved'
        ORDER BY c.created_at DESC
    """, (user_id,))
    rows = cur.fetchall()
    classrooms_list = []
    for r in rows:
        classrooms_list.append({
            "id": r["id"],
            "name": r["name"],
            "description": r["description"],
            "owner_id": r["owner_id"],
            "is_owner": (r["owner_id"] == user_id),
            "role": r["user_role"],
            "user_role": r["user_role"],
            "member_count": r["member_count"],
            "created_at": r["created_at"]
        })
    return jsonify({"classrooms": classrooms_list}), 200

@app.route("/api/classrooms", methods=["POST"])
@auth_required
def create_classroom():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()

    if not name:
        return jsonify({"error": "Classroom Name is required."}), 400

    user_id = g.current_user["id"]

    if HAS_SUPABASE:
        try:
            # Call RPC create_classroom if available
            user_client = g.get("supabase_user_client") or supabase_admin
            rpc_res = user_client.rpc("create_classroom", {"p_name": name, "p_description": description}).execute()
            if rpc_res.data and rpc_res.data.get("success"):
                cls_data = rpc_res.data.get("classroom", {})
                return jsonify({
                    "classroom": cls_data,
                    "message": "Classroom created successfully."
                }), 201

            # Fallback table insert
            cls_id = secrets.token_hex(16)
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            supabase_admin.table("classrooms").insert({
                "id": cls_id,
                "name": name,
                "description": description,
                "owner_id": user_id,
                "created_at": now_iso
            }).execute()
            supabase_admin.table("classroom_members").insert({
                "classroom_id": cls_id,
                "user_id": user_id,
                "role": "owner",
                "membership_status": "approved"
            }).execute()
            return jsonify({
                "classroom": {"id": cls_id, "name": name, "description": description, "owner_id": user_id, "role": "owner"},
                "message": "Classroom created successfully."
            }), 201
        except Exception as e:
            return jsonify({"error": f"Failed to create classroom: {str(e)}"}), 500

    # SQLite Engine
    db = get_db()
    cur = db.cursor()
    cls_id = secrets.token_hex(16)
    cm_id = secrets.token_hex(16)
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        cur.execute("""
            INSERT INTO classrooms (id, name, description, owner_id, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (cls_id, name, description, user_id, now_str))

        cur.execute("""
            INSERT INTO classroom_members (id, classroom_id, user_id, role, membership_status, joined_at)
            VALUES (?, ?, ?, 'owner', 'approved', ?)
        """, (cm_id, cls_id, user_id, now_str))

        db.commit()

        return jsonify({
            "classroom": {
                "id": cls_id,
                "name": name,
                "description": description,
                "owner_id": user_id,
                "role": "owner"
            },
            "message": "Classroom created successfully."
        }), 201
    except Exception as e:
        db.rollback()
        return jsonify({"error": f"Failed to create classroom: {str(e)}"}), 500

@app.route("/api/classrooms/<classroom_id>", methods=["GET"])
@auth_required
def get_classroom_details(classroom_id: str):
    user_id = g.current_user["id"]

    if HAS_SUPABASE:
        try:
            cls_res = supabase_admin.table("classrooms").select("*").eq("id", classroom_id).execute()
            if not cls_res.data:
                return jsonify({"error": "Classroom not found."}), 404
            cls = cls_res.data[0]

            is_owner = (cls["owner_id"] == user_id)
            mem_res = supabase_admin.table("classroom_members").select("role").eq("classroom_id", classroom_id).eq("user_id", user_id).eq("membership_status", "approved").execute()
            if not is_owner and not mem_res.data:
                return jsonify({"error": "Forbidden: You are not an approved member of this classroom."}), 403

            user_role = "owner" if is_owner else mem_res.data[0]["role"]
            m_count = supabase_admin.table("classroom_members").select("id", count="exact").eq("classroom_id", classroom_id).eq("membership_status", "approved").execute().count or 1
            req_count = 0
            if is_owner:
                req_count = supabase_admin.table("classroom_join_requests").select("id", count="exact").eq("classroom_id", classroom_id).eq("status", "pending").execute().count or 0

            return jsonify({
                "classroom": {
                    "id": cls["id"],
                    "name": cls["name"],
                    "description": cls.get("description", ""),
                    "owner_id": cls["owner_id"],
                    "is_owner": is_owner,
                    "user_role": user_role,
                    "member_count": m_count,
                    "pending_requests_count": req_count,
                    "created_at": cls.get("created_at")
                }
            }), 200
        except Exception as e:
            return jsonify({"error": f"Failed to fetch classroom: {str(e)}"}), 500

    # SQLite Engine
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM classrooms WHERE id = ?", (classroom_id,))
    cls = cur.fetchone()
    if not cls:
        return jsonify({"error": "Classroom not found."}), 404

    is_owner = (cls["owner_id"] == user_id)
    cur.execute("SELECT role FROM classroom_members WHERE classroom_id = ? AND user_id = ? AND membership_status = 'approved'", (classroom_id, user_id))
    membership = cur.fetchone()

    if not is_owner and not membership:
        return jsonify({"error": "Forbidden: You are not an approved member of this classroom."}), 403

    user_role = "owner" if is_owner else membership["role"]
    cur.execute("SELECT COUNT(*) AS count FROM classroom_members WHERE classroom_id = ? AND membership_status = 'approved'", (classroom_id,))
    member_count = cur.fetchone()["count"]

    req_count = 0
    if is_owner:
        cur.execute("SELECT COUNT(*) AS count FROM classroom_join_requests WHERE classroom_id = ? AND status = 'pending'", (classroom_id,))
        req_count = cur.fetchone()["count"]

    return jsonify({
        "classroom": {
            "id": cls["id"],
            "name": cls["name"],
            "description": cls["description"],
            "owner_id": cls["owner_id"],
            "is_owner": is_owner,
            "user_role": user_role,
            "member_count": member_count,
            "pending_requests_count": req_count,
            "created_at": cls["created_at"]
        }
    }), 200

# ----------------------------------------------------------------------------
# INVITATION MANAGEMENT ROUTES (OWNER CONTROLS)
# ----------------------------------------------------------------------------
@app.route("/api/classrooms/<classroom_id>/invitation", methods=["POST"])
@auth_required
def create_invitation(classroom_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    if not is_classroom_owner(db, classroom_id, user_id):
        return jsonify({"error": "Forbidden: Only the classroom owner can generate invitation links."}), 403

    data = request.get_json(silent=True) or {}
    days = int(data.get("expires_in_days", 7))
    expires_at = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)).isoformat()
    raw_token = secrets.token_urlsafe(32)
    token_hashed = hash_token(raw_token)
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if HAS_SUPABASE:
        try:
            # Revoke existing active
            supabase_admin.table("classroom_invitations").update({"revoked_at": now_str}).eq("classroom_id", classroom_id).is_("revoked_at", "null").execute()
            # Insert new
            supabase_admin.table("classroom_invitations").insert({
                "classroom_id": classroom_id,
                "token_hash": token_hashed,
                "created_by": user_id,
                "expires_at": expires_at,
                "created_at": now_str
            }).execute()
            return jsonify({
                "token": raw_token,
                "raw_token": raw_token,
                "invitation_url": f"{request.host_url}?invite={raw_token}",
                "expires_at": expires_at,
                "message": "Invitation link generated successfully."
            }), 201
        except Exception as e:
            return jsonify({"error": f"Failed to generate invitation link: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    cur.execute("""
        UPDATE classroom_invitations
        SET revoked_at = ?
        WHERE classroom_id = ? AND revoked_at IS NULL
    """, (now_str, classroom_id))

    inv_id = secrets.token_hex(16)
    cur.execute("""
        INSERT INTO classroom_invitations (id, classroom_id, token_hash, created_by, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (inv_id, classroom_id, token_hashed, user_id, expires_at, now_str))
    db.commit()

    return jsonify({
        "token": raw_token,
        "raw_token": raw_token,
        "invitation_url": f"{request.host_url}?invite={raw_token}",
        "expires_at": expires_at,
        "message": "Invitation link generated successfully."
    }), 201

@app.route("/api/classrooms/<classroom_id>/invitation/revoke", methods=["POST"])
@auth_required
def revoke_invitation(classroom_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    if not is_classroom_owner(db, classroom_id, user_id):
        return jsonify({"error": "Forbidden: Only the classroom owner can revoke invitation links."}), 403

    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if HAS_SUPABASE:
        try:
            supabase_admin.table("classroom_invitations").update({"revoked_at": now_str}).eq("classroom_id", classroom_id).is_("revoked_at", "null").execute()
            return jsonify({"success": True, "message": "Invitation link revoked successfully."}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to revoke invitation link: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    cur.execute("""
        UPDATE classroom_invitations
        SET revoked_at = ?
        WHERE classroom_id = ? AND revoked_at IS NULL
    """, (now_str, classroom_id))
    db.commit()

    return jsonify({"success": True, "message": "Invitation link revoked successfully."}), 200

@app.route("/api/classrooms/<classroom_id>/invitation/active", methods=["GET"])
@auth_required
def get_active_invitation(classroom_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    if not is_classroom_owner(db, classroom_id, user_id):
        return jsonify({"error": "Forbidden: Only the classroom owner can view active invitations."}), 403

    if HAS_SUPABASE:
        try:
            invs = supabase_admin.table("classroom_invitations").select("*").eq("classroom_id", classroom_id).is_("revoked_at", "null").order("created_at", desc=True).limit(1).execute().data
            if not invs:
                return jsonify({"active_invitation": None}), 200
            inv = invs[0]
            is_expired = False
            if inv.get("expires_at"):
                exp = datetime.datetime.fromisoformat(inv["expires_at"].replace("Z", "+00:00"))
                is_expired = (exp < datetime.datetime.now(datetime.timezone.utc))
            return jsonify({
                "active_invitation": {
                    "id": inv["id"],
                    "expires_at": inv.get("expires_at"),
                    "is_expired": is_expired,
                    "created_at": inv.get("created_at")
                }
            }), 200
        except Exception as e:
            return jsonify({"error": f"Failed to fetch invitation: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    cur.execute("""
        SELECT id, expires_at, created_at
        FROM classroom_invitations
        WHERE classroom_id = ? AND revoked_at IS NULL
        ORDER BY created_at DESC
        LIMIT 1
    """, (classroom_id,))
    inv = cur.fetchone()
    if not inv:
        return jsonify({"active_invitation": None}), 200

    is_expired = False
    if inv["expires_at"]:
        exp = datetime.datetime.fromisoformat(inv["expires_at"])
        is_expired = (exp < datetime.datetime.now(datetime.timezone.utc))

    return jsonify({
        "active_invitation": {
            "id": inv["id"],
            "expires_at": inv["expires_at"],
            "is_expired": is_expired,
            "created_at": inv["created_at"]
        }
    }), 200

# ----------------------------------------------------------------------------
# INVITATION PREVIEW & JOINING WORKFLOW (ZERO-TRUST PREVIEW)
# ----------------------------------------------------------------------------
@app.route("/api/invitations/preview", methods=["GET"])
def preview_invitation():
    raw_token = (request.args.get("token") or "").strip()
    if not raw_token:
        return jsonify({"valid": False, "status": "invalid", "message": "Missing invitation token."}), 400

    token_hashed = hash_token(raw_token)

    if HAS_SUPABASE:
        try:
            # Query RPC get_invitation_preview if available
            rpc_res = supabase_admin.rpc("get_invitation_preview", {"p_token_hash": token_hashed}).execute()
            if rpc_res.data:
                return jsonify(rpc_res.data), 200

            # Fallback table query
            inv_res = supabase_admin.table("classroom_invitations").select("classroom_id, expires_at, revoked_at").eq("token_hash", token_hashed).execute()
            if not inv_res.data:
                return jsonify({"valid": False, "status": "not_found", "message": "Invitation link does not exist."}), 404
            inv = inv_res.data[0]
            if inv.get("revoked_at"):
                return jsonify({"valid": False, "status": "revoked", "message": "This invitation link has been revoked by the classroom owner."}), 410
            if inv.get("expires_at"):
                exp = datetime.datetime.fromisoformat(inv["expires_at"].replace("Z", "+00:00"))
                if exp < datetime.datetime.now(datetime.timezone.utc):
                    return jsonify({"valid": False, "status": "expired", "message": "This invitation link has expired."}), 410

            cls_res = supabase_admin.table("classrooms").select("id, name, description, owner_id").eq("id", inv["classroom_id"]).execute()
            cls = cls_res.data[0]
            owner_res = supabase_admin.table("profiles").select("full_name").eq("id", cls["owner_id"]).execute()
            owner_name = owner_res.data[0]["full_name"] if owner_res.data else "Classroom Owner"

            return jsonify({
                "valid": True,
                "status": "active",
                "classroom_id": cls["id"],
                "classroom_name": cls["name"],
                "classroom_description": cls.get("description", ""),
                "owner_name": owner_name
            }), 200
        except Exception as e:
            return jsonify({"error": f"Failed to preview invitation: {str(e)}"}), 500

    # SQLite Engine
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT
            ci.id, ci.classroom_id, ci.expires_at, ci.revoked_at,
            c.name AS classroom_name, c.description AS classroom_description,
            p.full_name AS owner_name
        FROM classroom_invitations ci
        JOIN classrooms c ON c.id = ci.classroom_id
        JOIN profiles p ON p.id = c.owner_id
        WHERE ci.token_hash = ?
    """, (token_hashed,))
    row = cur.fetchone()

    if not row:
        return jsonify({"valid": False, "status": "not_found", "message": "Invitation link does not exist."}), 404
    if row["revoked_at"] is not None:
        return jsonify({"valid": False, "status": "revoked", "message": "This invitation link has been revoked by the classroom owner."}), 410
    if row["expires_at"] is not None:
        exp = datetime.datetime.fromisoformat(row["expires_at"])
        if exp < datetime.datetime.now(datetime.timezone.utc):
            return jsonify({"valid": False, "status": "expired", "message": "This invitation link has expired."}), 410

    return jsonify({
        "valid": True,
        "status": "active",
        "classroom_id": row["classroom_id"],
        "classroom_name": row["classroom_name"],
        "classroom_description": row["classroom_description"],
        "owner_name": row["owner_name"]
    }), 200

@app.route("/api/invitations/request-join", methods=["POST"])
@auth_required
def request_to_join():
    data = request.get_json(silent=True) or {}
    raw_token = (data.get("token") or "").strip()
    user_id = g.current_user["id"]

    if not raw_token:
        return jsonify({"error": "Missing invitation token."}), 400

    token_hashed = hash_token(raw_token)

    if HAS_SUPABASE:
        try:
            user_client = g.get("supabase_user_client") or supabase_admin
            rpc_res = user_client.rpc("request_to_join", {"p_token_hash": token_hashed}).execute()
            if rpc_res.data:
                return jsonify(rpc_res.data), 200

            # Fallback
            inv_res = supabase_admin.table("classroom_invitations").select("classroom_id, expires_at, revoked_at").eq("token_hash", token_hashed).execute()
            if not inv_res.data:
                return jsonify({"error": "Invalid or expired invitation link."}), 404
            inv = inv_res.data[0]
            cls_id = inv["classroom_id"]

            if is_approved_member(None, cls_id, user_id):
                return jsonify({"status": "approved", "message": "You are already an approved member of this classroom."}), 200

            # Insert or reset request
            req_data = {
                "classroom_id": cls_id,
                "user_id": user_id,
                "status": "pending",
                "requested_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            supabase_admin.table("classroom_join_requests").upsert(req_data, on_conflict="classroom_id, user_id").execute()

            # Notify owner
            cls_info = supabase_admin.table("classrooms").select("name, owner_id").eq("id", cls_id).execute().data[0]
            supabase_admin.table("notifications").insert({
                "user_id": cls_info["owner_id"],
                "classroom_id": cls_id,
                "title": "New Join Request",
                "message": f"{g.current_user['full_name']} requested to join {cls_info['name']}.",
                "type": "join_request"
            }).execute()

            return jsonify({
                "status": "pending",
                "classroom_id": cls_id,
                "message": "Join request submitted successfully. Waiting for classroom owner approval."
            }), 201
        except Exception as e:
            return jsonify({"error": f"Failed to submit join request: {str(e)}"}), 500

    # SQLite Engine
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT ci.classroom_id, ci.expires_at, ci.revoked_at, c.owner_id, c.name AS classroom_name
        FROM classroom_invitations ci
        JOIN classrooms c ON c.id = ci.classroom_id
        WHERE ci.token_hash = ?
    """, (token_hashed,))
    inv = cur.fetchone()

    if not inv:
        return jsonify({"error": "Invalid invitation link."}), 404
    if inv["revoked_at"] is not None:
        return jsonify({"error": "This invitation link has been revoked."}), 410
    if inv["expires_at"] is not None:
        exp = datetime.datetime.fromisoformat(inv["expires_at"])
        if exp < datetime.datetime.now(datetime.timezone.utc):
            return jsonify({"error": "This invitation link has expired."}), 410

    cls_id = inv["classroom_id"]
    if is_approved_member(db, cls_id, user_id):
        return jsonify({"status": "approved", "message": "You are already an approved member of this classroom."}), 200

    cur.execute("SELECT id, status FROM classroom_join_requests WHERE classroom_id = ? AND user_id = ?", (cls_id, user_id))
    existing_req = cur.fetchone()
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if existing_req:
        if existing_req["status"] == "pending":
            return jsonify({"status": "pending", "message": "Your request is already pending approval."}), 200
        elif existing_req["status"] == "approved":
            return jsonify({"status": "approved", "message": "Your request has already been approved."}), 200
        else:
            cur.execute("""
                UPDATE classroom_join_requests
                SET status = 'pending', requested_at = ?, reviewed_at = NULL, reviewed_by = NULL
                WHERE id = ?
            """, (now_str, existing_req["id"]))
    else:
        req_id = secrets.token_hex(16)
        cur.execute("""
            INSERT INTO classroom_join_requests (id, classroom_id, user_id, status, requested_at)
            VALUES (?, ?, ?, 'pending', ?)
        """, (req_id, cls_id, user_id, now_str))

    notif_id = secrets.token_hex(16)
    cur.execute("""
        INSERT INTO notifications (id, user_id, classroom_id, title, message, type, created_at)
        VALUES (?, ?, ?, 'New Join Request', ?, 'join_request', ?)
    """, (notif_id, inv["owner_id"], cls_id, f"{g.current_user['full_name']} requested to join {inv['classroom_name']}.", now_str))

    db.commit()

    return jsonify({
        "status": "pending",
        "classroom_id": cls_id,
        "message": "Your request has been sent to the classroom owner for approval."
    }), 200

# ----------------------------------------------------------------------------
# OWNER APPROVAL DASHBOARD ROUTES
# ----------------------------------------------------------------------------
@app.route("/api/classrooms/<classroom_id>/requests", methods=["GET"])
@auth_required
def get_classroom_requests(classroom_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    if not is_classroom_owner(db, classroom_id, user_id):
        return jsonify({"error": "Forbidden: Only the classroom owner can view join requests."}), 403

    if HAS_SUPABASE:
        try:
            reqs = supabase_admin.table("classroom_join_requests").select("id, user_id, status, requested_at").eq("classroom_id", classroom_id).eq("status", "pending").order("requested_at", desc=True).execute().data or []
            requests_list = []
            for r in reqs:
                prof = supabase_admin.table("profiles").select("full_name, college_email, roll_number").eq("id", r["user_id"]).execute().data
                prof_data = prof[0] if prof else {}
                requests_list.append({
                    "id": r["id"],
                    "user_id": r["user_id"],
                    "status": r["status"],
                    "requested_at": r["requested_at"],
                    "full_name": prof_data.get("full_name", "Student"),
                    "college_email": prof_data.get("college_email", ""),
                    "roll_number": prof_data.get("roll_number", "")
                })
            return jsonify({"requests": requests_list}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to fetch requests: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    cur.execute("""
        SELECT
            r.id, r.user_id, r.status, r.requested_at,
            p.full_name, p.college_email, p.roll_number
        FROM classroom_join_requests r
        JOIN profiles p ON p.id = r.user_id
        WHERE r.classroom_id = ? AND r.status = 'pending'
        ORDER BY r.requested_at DESC
    """, (classroom_id,))
    rows = cur.fetchall()
    return jsonify({"requests": [dict(r) for r in rows]}), 200

@app.route("/api/classrooms/<classroom_id>/requests/<request_id>/approve", methods=["POST"])
@auth_required
def approve_request(classroom_id: str, request_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    if not is_classroom_owner(db, classroom_id, user_id):
        return jsonify({"error": "Forbidden: Only the classroom owner can approve join requests."}), 403

    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if HAS_SUPABASE:
        try:
            user_client = g.get("supabase_user_client") or supabase_admin
            rpc_res = user_client.rpc("approve_join_request", {"p_request_id": request_id}).execute()
            if rpc_res.data and rpc_res.data.get("success"):
                return jsonify(rpc_res.data), 200

            # Fallback table update
            req_res = supabase_admin.table("classroom_join_requests").select("user_id, classroom_id").eq("id", request_id).execute()
            if not req_res.data:
                return jsonify({"error": "Join request not found."}), 404
            req = req_res.data[0]
            student_id = req["user_id"]

            supabase_admin.table("classroom_join_requests").update({"status": "approved", "reviewed_at": now_str, "reviewed_by": user_id}).eq("id", request_id).execute()
            supabase_admin.table("classroom_members").upsert({"classroom_id": classroom_id, "user_id": student_id, "role": "member", "membership_status": "approved", "joined_at": now_str}, on_conflict="classroom_id, user_id").execute()

            # Backfill active upcoming assignments into student's tasks
            upcoming_assigns = supabase_admin.table("assignments").select("id, title, due_date").eq("classroom_id", classroom_id).gt("due_date", now_str).execute().data or []
            for a in upcoming_assigns:
                supabase_admin.table("user_tasks").upsert({
                    "user_id": student_id,
                    "assignment_id": a["id"],
                    "classroom_id": classroom_id,
                    "title": a["title"],
                    "due_date": a["due_date"],
                    "status": "pending",
                    "created_at": now_str
                }, on_conflict="user_id, assignment_id").execute()

            # Notification
            cls_name = supabase_admin.table("classrooms").select("name").eq("id", classroom_id).execute().data[0]["name"]
            supabase_admin.table("notifications").insert({
                "user_id": student_id,
                "classroom_id": classroom_id,
                "title": "Join Request Approved!",
                "message": f"Your request to join {cls_name} has been approved. Welcome to the class!",
                "type": "request_approved",
                "created_at": now_str
            }).execute()

            return jsonify({"success": True, "status": "approved", "message": "Join request approved successfully."}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to approve request: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    cur.execute("SELECT user_id, classroom_id FROM classroom_join_requests WHERE id = ?", (request_id,))
    req = cur.fetchone()
    if not req or req["classroom_id"] != classroom_id:
        return jsonify({"error": "Join request not found."}), 404

    student_id = req["user_id"]
    cur.execute("""
        UPDATE classroom_join_requests
        SET status = 'approved', reviewed_at = ?, reviewed_by = ?
        WHERE id = ?
    """, (now_str, user_id, request_id))

    cur.execute("SELECT id FROM classroom_members WHERE classroom_id = ? AND user_id = ?", (classroom_id, student_id))
    mem = cur.fetchone()
    if mem:
        cur.execute("UPDATE classroom_members SET membership_status = 'approved', joined_at = ? WHERE id = ?", (now_str, mem["id"]))
    else:
        cm_id = secrets.token_hex(16)
        cur.execute("""
            INSERT INTO classroom_members (id, classroom_id, user_id, role, membership_status, joined_at)
            VALUES (?, ?, ?, 'member', 'approved', ?)
        """, (cm_id, classroom_id, student_id, now_str))

    # Synchronize upcoming assignments into student's personal tasks
    cur.execute("SELECT id, title, due_date FROM assignments WHERE classroom_id = ? AND due_date > ?", (classroom_id, now_str))
    assignments = cur.fetchall()
    for a in assignments:
        cur.execute("SELECT 1 FROM user_tasks WHERE user_id = ? AND assignment_id = ?", (student_id, a["id"]))
        if not cur.fetchone():
            task_id = secrets.token_hex(16)
            cur.execute("""
                INSERT INTO user_tasks (id, user_id, assignment_id, classroom_id, title, due_date, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
            """, (task_id, student_id, a["id"], classroom_id, a["title"], a["due_date"], now_str))

    cur.execute("SELECT name FROM classrooms WHERE id = ?", (classroom_id,))
    cls_name = cur.fetchone()["name"]
    notif_id = secrets.token_hex(16)
    cur.execute("""
        INSERT INTO notifications (id, user_id, classroom_id, title, message, type, created_at)
        VALUES (?, ?, ?, 'Join Request Approved!', ?, 'request_approved', ?)
    """, (notif_id, student_id, classroom_id, f"Your request to join {cls_name} has been approved. Welcome to the class!", now_str))

    db.commit()

    return jsonify({"success": True, "status": "approved", "message": "Join request approved successfully."}), 200

@app.route("/api/classrooms/<classroom_id>/requests/<request_id>/reject", methods=["POST"])
@auth_required
def reject_request(classroom_id: str, request_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    if not is_classroom_owner(db, classroom_id, user_id):
        return jsonify({"error": "Forbidden: Only the classroom owner can reject join requests."}), 403

    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if HAS_SUPABASE:
        try:
            user_client = g.get("supabase_user_client") or supabase_admin
            rpc_res = user_client.rpc("reject_join_request", {"p_request_id": request_id}).execute()
            if rpc_res.data:
                return jsonify(rpc_res.data), 200

            req_res = supabase_admin.table("classroom_join_requests").select("user_id").eq("id", request_id).execute()
            if not req_res.data:
                return jsonify({"error": "Join request not found."}), 404
            student_id = req_res.data[0]["user_id"]

            supabase_admin.table("classroom_join_requests").update({"status": "rejected", "reviewed_at": now_str, "reviewed_by": user_id}).eq("id", request_id).execute()
            cls_name = supabase_admin.table("classrooms").select("name").eq("id", classroom_id).execute().data[0]["name"]
            supabase_admin.table("notifications").insert({
                "user_id": student_id,
                "classroom_id": classroom_id,
                "title": "Join Request Declined",
                "message": f"Your request to join {cls_name} was declined by the classroom owner.",
                "type": "request_rejected",
                "created_at": now_str
            }).execute()

            return jsonify({"success": True, "status": "rejected", "message": "Join request rejected."}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to reject request: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    cur.execute("SELECT user_id, classroom_id FROM classroom_join_requests WHERE id = ?", (request_id,))
    req = cur.fetchone()
    if not req or req["classroom_id"] != classroom_id:
        return jsonify({"error": "Join request not found."}), 404

    cur.execute("""
        UPDATE classroom_join_requests
        SET status = 'rejected', reviewed_at = ?, reviewed_by = ?
        WHERE id = ?
    """, (now_str, user_id, request_id))

    cur.execute("SELECT name FROM classrooms WHERE id = ?", (classroom_id,))
    cls_name = cur.fetchone()["name"]
    notif_id = secrets.token_hex(16)
    cur.execute("""
        INSERT INTO notifications (id, user_id, classroom_id, title, message, type, created_at)
        VALUES (?, ?, ?, 'Join Request Declined', ?, 'request_rejected', ?)
    """, (notif_id, req["user_id"], classroom_id, f"Your request to join {cls_name} was declined by the classroom owner.", now_str))

    db.commit()

    return jsonify({"success": True, "status": "rejected", "message": "Join request rejected."}), 200

@app.route("/api/classrooms/<classroom_id>/members", methods=["GET"])
@auth_required
def get_classroom_members(classroom_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    if not is_approved_member(db, classroom_id, user_id) and not is_classroom_owner(db, classroom_id, user_id):
        return jsonify({"error": "Forbidden: You are not an approved member of this classroom."}), 403

    if HAS_SUPABASE:
        try:
            mems = supabase_admin.table("classroom_members").select("user_id, role, joined_at").eq("classroom_id", classroom_id).eq("membership_status", "approved").order("joined_at", desc=False).execute().data or []
            members_list = []
            for m in mems:
                prof = supabase_admin.table("profiles").select("full_name, college_email, roll_number, is_faculty").eq("id", m["user_id"]).execute().data
                prof_data = prof[0] if prof else {}
                members_list.append({
                    "user_id": m["user_id"],
                    "role": m["role"],
                    "joined_at": m["joined_at"],
                    "full_name": prof_data.get("full_name", "Student"),
                    "college_email": prof_data.get("college_email", ""),
                    "roll_number": prof_data.get("roll_number", ""),
                    "is_faculty": bool(prof_data.get("is_faculty"))
                })
            return jsonify({"members": members_list}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to fetch members: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    cur.execute("""
        SELECT
            cm.user_id, cm.role, cm.joined_at,
            p.full_name, p.college_email, p.roll_number, p.is_faculty
        FROM classroom_members cm
        JOIN profiles p ON p.id = cm.user_id
        WHERE cm.classroom_id = ? AND cm.membership_status = 'approved'
        ORDER BY cm.joined_at ASC
    """, (classroom_id,))
    rows = cur.fetchall()
    members_list = []
    for r in rows:
        members_list.append({
            "user_id": r["user_id"],
            "role": r["role"],
            "joined_at": r["joined_at"],
            "full_name": r["full_name"],
            "college_email": r["college_email"],
            "roll_number": r["roll_number"],
            "is_faculty": bool(r["is_faculty"])
        })
    return jsonify({"members": members_list}), 200

@app.route("/api/classrooms/<classroom_id>/members/<member_user_id>", methods=["DELETE"])
@auth_required
def remove_member(classroom_id: str, member_user_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    if not is_classroom_owner(db, classroom_id, user_id):
        return jsonify({"error": "Forbidden: Only the classroom owner can remove members."}), 403

    if member_user_id == user_id:
        return jsonify({"error": "Classroom owner cannot be removed. Transfer ownership first."}), 400

    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if HAS_SUPABASE:
        try:
            user_client = g.get("supabase_user_client") or supabase_admin
            rpc_res = user_client.rpc("remove_classroom_member", {"p_classroom_id": classroom_id, "p_member_user_id": member_user_id}).execute()
            if rpc_res.data:
                return jsonify(rpc_res.data), 200

            # Fallback
            supabase_admin.table("classroom_members").delete().eq("classroom_id", classroom_id).eq("user_id", member_user_id).execute()
            supabase_admin.table("classroom_join_requests").delete().eq("classroom_id", classroom_id).eq("user_id", member_user_id).execute()
            supabase_admin.table("user_tasks").delete().eq("classroom_id", classroom_id).eq("user_id", member_user_id).execute()
            cls_name = supabase_admin.table("classrooms").select("name").eq("id", classroom_id).execute().data[0]["name"]
            supabase_admin.table("notifications").insert({
                "user_id": member_user_id,
                "classroom_id": classroom_id,
                "title": "Classroom Membership Removed",
                "message": f"You were removed from {cls_name} by the classroom owner.",
                "type": "member_removed",
                "created_at": now_str
            }).execute()
            return jsonify({"success": True, "message": "Member removed successfully."}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to remove member: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    cur.execute("DELETE FROM classroom_members WHERE classroom_id = ? AND user_id = ?", (classroom_id, member_user_id))
    cur.execute("DELETE FROM classroom_join_requests WHERE classroom_id = ? AND user_id = ?", (classroom_id, member_user_id))
    cur.execute("DELETE FROM user_tasks WHERE classroom_id = ? AND user_id = ?", (classroom_id, member_user_id))

    cur.execute("SELECT name FROM classrooms WHERE id = ?", (classroom_id,))
    cls_name = cur.fetchone()["name"]
    notif_id = secrets.token_hex(16)
    cur.execute("""
        INSERT INTO notifications (id, user_id, classroom_id, title, message, type, created_at)
        VALUES (?, ?, ?, 'Classroom Membership Removed', ?, 'member_removed', ?)
    """, (notif_id, member_user_id, classroom_id, f"You were removed from {cls_name} by the classroom owner.", now_str))

    db.commit()

    return jsonify({"success": True, "message": "Member removed successfully."}), 200

@app.route("/api/classrooms/<classroom_id>/transfer-ownership", methods=["POST"])
@auth_required
def transfer_classroom_ownership(classroom_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    if not is_classroom_owner(db, classroom_id, user_id):
        return jsonify({"error": "Forbidden: Only the current classroom owner can transfer ownership."}), 403

    data = request.get_json(silent=True) or {}
    new_owner_id = (data.get("new_owner_id") or "").strip()

    if not new_owner_id:
        return jsonify({"error": "Missing new_owner_id."}), 400
    if new_owner_id == user_id:
        return jsonify({"error": "You are already the classroom owner."}), 400

    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if HAS_SUPABASE:
        try:
            user_client = g.get("supabase_user_client") or supabase_admin
            rpc_res = user_client.rpc("transfer_classroom_ownership", {"p_classroom_id": classroom_id, "p_new_owner_id": new_owner_id}).execute()
            if rpc_res.data:
                return jsonify(rpc_res.data), 200

            # Fallback
            supabase_admin.table("classrooms").update({"owner_id": new_owner_id, "updated_at": now_str}).eq("id", classroom_id).execute()
            supabase_admin.table("classroom_members").update({"role": "member"}).eq("classroom_id", classroom_id).eq("user_id", user_id).execute()
            supabase_admin.table("classroom_members").update({"role": "owner"}).eq("classroom_id", classroom_id).eq("user_id", new_owner_id).execute()
            supabase_admin.table("notifications").insert({
                "user_id": new_owner_id,
                "classroom_id": classroom_id,
                "title": "Classroom Ownership Transferred",
                "message": "You are now the designated owner of this classroom.",
                "type": "announcement",
                "created_at": now_str
            }).execute()
            return jsonify({"success": True, "message": "Ownership transferred successfully."}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to transfer ownership: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    cur.execute("SELECT 1 FROM classroom_members WHERE classroom_id = ? AND user_id = ? AND membership_status = 'approved'", (classroom_id, new_owner_id))
    if not cur.fetchone():
        return jsonify({"error": "New owner must already be an approved member of this classroom."}), 400

    cur.execute("UPDATE classrooms SET owner_id = ? WHERE id = ?", (new_owner_id, classroom_id))
    cur.execute("UPDATE classroom_members SET role = 'member' WHERE classroom_id = ? AND user_id = ?", (classroom_id, user_id))
    cur.execute("UPDATE classroom_members SET role = 'owner' WHERE classroom_id = ? AND user_id = ?", (classroom_id, new_owner_id))

    notif_id = secrets.token_hex(16)
    cur.execute("""
        INSERT INTO notifications (id, user_id, classroom_id, title, message, type, created_at)
        VALUES (?, ?, ?, 'Classroom Ownership Transferred', 'You are now the designated owner of this classroom.', 'announcement', ?)
    """, (notif_id, new_owner_id, classroom_id, now_str))

    db.commit()

    return jsonify({"success": True, "message": "Ownership transferred successfully."}), 200

# ----------------------------------------------------------------------------
# CLASSROOM POSTS & TIMELINE ROUTES
# ----------------------------------------------------------------------------
@app.route("/api/classrooms/<classroom_id>/posts", methods=["GET"])
@auth_required
def get_posts(classroom_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    if not is_approved_member(db, classroom_id, user_id) and not is_classroom_owner(db, classroom_id, user_id):
        return jsonify({"error": "Forbidden: You are not an approved member of this classroom."}), 403

    if HAS_SUPABASE:
        try:
            posts = supabase_admin.table("classroom_posts").select("*").eq("classroom_id", classroom_id).order("created_at", desc=True).execute().data or []
            posts_list = []
            for p in posts:
                author_res = supabase_admin.table("profiles").select("full_name, is_faculty").eq("id", p["author_id"]).execute().data
                author = author_res[0] if author_res else {}
                posts_list.append({
                    "id": p["id"],
                    "title": p["title"],
                    "content": p["content"],
                    "author_id": p["author_id"],
                    "author_name": author.get("full_name", "Student"),
                    "is_faculty_verified": bool(p.get("is_faculty_verified")),
                    "created_at": p.get("created_at")
                })
            return jsonify({"posts": posts_list}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to fetch posts: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    cur.execute("""
        SELECT
            cp.id, cp.title, cp.content, cp.author_id, cp.is_faculty_verified, cp.created_at,
            p.full_name AS author_name, p.is_faculty
        FROM classroom_posts cp
        JOIN profiles p ON p.id = cp.author_id
        WHERE cp.classroom_id = ?
        ORDER BY cp.created_at DESC
    """, (classroom_id,))
    rows = cur.fetchall()
    posts_list = []
    for r in rows:
        posts_list.append({
            "id": r["id"],
            "title": r["title"],
            "content": r["content"],
            "author_id": r["author_id"],
            "author_name": r["author_name"],
            "is_faculty_verified": bool(r["is_faculty_verified"]),
            "created_at": r["created_at"]
        })
    return jsonify({"posts": posts_list}), 200

@app.route("/api/classrooms/<classroom_id>/posts", methods=["POST"])
@auth_required
def create_post(classroom_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    if not is_approved_member(db, classroom_id, user_id) and not is_classroom_owner(db, classroom_id, user_id):
        return jsonify({"error": "Forbidden: You are not an approved member of this classroom."}), 403

    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    content = (data.get("content") or "").strip()

    if not title or not content:
        return jsonify({"error": "Title and Content are required."}), 400

    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    is_faculty = bool(g.current_user.get("is_faculty", False))

    if HAS_SUPABASE:
        try:
            post_id = secrets.token_hex(16)
            supabase_admin.table("classroom_posts").insert({
                "id": post_id,
                "classroom_id": classroom_id,
                "author_id": user_id,
                "title": title,
                "content": content,
                "is_faculty_verified": is_faculty,
                "created_at": now_str
            }).execute()
            return jsonify({
                "post": {
                    "id": post_id,
                    "title": title,
                    "content": content,
                    "author_id": user_id,
                    "author_name": g.current_user["full_name"],
                    "is_faculty_verified": is_faculty,
                    "created_at": now_str
                },
                "message": "Post created successfully."
            }), 201
        except Exception as e:
            return jsonify({"error": f"Failed to create post: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    post_id = secrets.token_hex(16)
    cur.execute("""
        INSERT INTO classroom_posts (id, classroom_id, author_id, title, content, is_faculty_verified, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (post_id, classroom_id, user_id, title, content, 1 if is_faculty else 0, now_str))
    db.commit()

    return jsonify({
        "post": {
            "id": post_id,
            "title": title,
            "content": content,
            "author_id": user_id,
            "author_name": g.current_user["full_name"],
            "is_faculty_verified": is_faculty,
            "created_at": now_str
        },
        "message": "Post created successfully."
    }), 201

# ----------------------------------------------------------------------------
# ASSIGNMENTS & AUTOMATIC TASK DISTRIBUTION ROUTES
# ----------------------------------------------------------------------------
@app.route("/api/classrooms/<classroom_id>/assignments", methods=["GET"])
@auth_required
def get_assignments(classroom_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    if not is_approved_member(db, classroom_id, user_id) and not is_classroom_owner(db, classroom_id, user_id):
        return jsonify({"error": "Forbidden: You are not an approved member of this classroom."}), 403

    if HAS_SUPABASE:
        try:
            assigns = supabase_admin.table("assignments").select("*").eq("classroom_id", classroom_id).order("due_date", desc=False).execute().data or []
            assign_list = []
            for a in assigns:
                author_res = supabase_admin.table("profiles").select("full_name").eq("id", a["created_by"]).execute().data
                creator_name = author_res[0]["full_name"] if author_res else "Classmate"
                assign_list.append({
                    "id": a["id"],
                    "classroom_id": a["classroom_id"],
                    "title": a["title"],
                    "description": a.get("description", ""),
                    "subject": a["subject"],
                    "due_date": a["due_date"],
                    "created_by": a["created_by"],
                    "creator_name": creator_name,
                    "created_at": a.get("created_at")
                })
            return jsonify({"assignments": assign_list}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to fetch assignments: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    cur.execute("""
        SELECT
            a.id, a.classroom_id, a.title, a.description, a.subject, a.due_date, a.created_by, a.created_at,
            p.full_name AS creator_name
        FROM assignments a
        JOIN profiles p ON p.id = a.created_by
        WHERE a.classroom_id = ?
        ORDER BY a.due_date ASC
    """, (classroom_id,))
    rows = cur.fetchall()
    return jsonify({"assignments": [dict(r) for r in rows]}), 200

@app.route("/api/classrooms/<classroom_id>/assignments", methods=["POST"])
@auth_required
def create_assignment(classroom_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    if not is_approved_member(db, classroom_id, user_id) and not is_classroom_owner(db, classroom_id, user_id):
        return jsonify({"error": "Forbidden: You are not an approved member of this classroom."}), 403

    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    description = (data.get("description") or "").strip()
    subject = (data.get("subject") or "").strip()
    due_date = (data.get("due_date") or "").strip()

    if not title or not subject or not due_date:
        return jsonify({"error": "Title, Subject, and Due Date are required."}), 400

    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if HAS_SUPABASE:
        try:
            assign_id = secrets.token_hex(16)
            supabase_admin.table("assignments").insert({
                "id": assign_id,
                "classroom_id": classroom_id,
                "created_by": user_id,
                "title": title,
                "description": description,
                "subject": subject,
                "due_date": due_date,
                "created_at": now_str
            }).execute()

            # Trigger trg_new_assignment_distribution handles fan-out in Postgres.
            # Defense-in-depth: if database triggers are not present, fan out here:
            mems = supabase_admin.table("classroom_members").select("user_id").eq("classroom_id", classroom_id).eq("membership_status", "approved").execute().data or []
            cls_name = supabase_admin.table("classrooms").select("name").eq("id", classroom_id).execute().data[0]["name"]

            for m in mems:
                mem_id = m["user_id"]
                # Task
                supabase_admin.table("user_tasks").upsert({
                    "user_id": mem_id,
                    "assignment_id": assign_id,
                    "classroom_id": classroom_id,
                    "title": title,
                    "due_date": due_date,
                    "status": "pending",
                    "created_at": now_str
                }, on_conflict="user_id, assignment_id").execute()
                # Notification (skip author)
                if mem_id != user_id:
                    supabase_admin.table("notifications").insert({
                        "user_id": mem_id,
                        "classroom_id": classroom_id,
                        "title": f"New Assignment: {title}",
                        "message": f"Subject: {subject} | Due: {due_date} in {cls_name}",
                        "type": "assignment_shared",
                        "created_at": now_str
                    }).execute()

            return jsonify({
                "assignment": {
                    "id": assign_id,
                    "title": title,
                    "description": description,
                    "subject": subject,
                    "due_date": due_date,
                    "created_by": user_id
                },
                "message": "Assignment created and synchronized to all classmates' tasks."
            }), 201
        except Exception as e:
            return jsonify({"error": f"Failed to create assignment: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    assign_id = secrets.token_hex(16)
    cur.execute("""
        INSERT INTO assignments (id, classroom_id, created_by, title, description, subject, due_date, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (assign_id, classroom_id, user_id, title, description, subject, due_date, now_str))

    # Fan out individual tasks to all approved members
    cur.execute("SELECT user_id FROM classroom_members WHERE classroom_id = ? AND membership_status = 'approved'", (classroom_id,))
    members = cur.fetchall()

    cur.execute("SELECT name FROM classrooms WHERE id = ?", (classroom_id,))
    cls_name = cur.fetchone()["name"]

    for m in members:
        mem_id = m["user_id"]
        task_id = secrets.token_hex(16)
        cur.execute("""
            INSERT INTO user_tasks (id, user_id, assignment_id, classroom_id, title, due_date, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
        """, (task_id, mem_id, assign_id, classroom_id, title, due_date, now_str))

        if mem_id != user_id:
            notif_id = secrets.token_hex(16)
            cur.execute("""
                INSERT INTO notifications (id, user_id, classroom_id, title, message, type, created_at)
                VALUES (?, ?, ?, ?, ?, 'assignment_shared', ?)
            """, (notif_id, mem_id, classroom_id, f"New Assignment: {title}", f"Subject: {subject} | Due: {due_date} in {cls_name}", now_str))

    db.commit()

    return jsonify({
        "assignment": {
            "id": assign_id,
            "title": title,
            "description": description,
            "subject": subject,
            "due_date": due_date,
            "created_by": user_id
        },
        "message": "Assignment created and synchronized to all classmates' tasks."
    }), 201

@app.route("/api/classrooms/<classroom_id>/assignments/<assignment_id>", methods=["PATCH"])
@auth_required
def update_assignment(classroom_id: str, assignment_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    data = request.get_json(silent=True) or {}
    new_title = (data.get("title") or "").strip()
    new_due_date = (data.get("due_date") or "").strip()
    new_desc = (data.get("description") or "").strip()

    if not new_title and not new_due_date and not new_desc:
        return jsonify({"error": "No update fields provided."}), 400

    if HAS_SUPABASE:
        try:
            assign_res = supabase_admin.table("assignments").select("created_by, classroom_id").eq("id", assignment_id).execute()
            if not assign_res.data:
                return jsonify({"error": "Assignment not found."}), 404
            assign = assign_res.data[0]
            is_owner = is_classroom_owner(None, classroom_id, user_id)
            if assign["created_by"] != user_id and not is_owner:
                return jsonify({"error": "Forbidden: Only assignment creator or classroom owner can edit assignments."}), 403

            upd = {}
            if new_title:
                upd["title"] = new_title
            if new_due_date:
                upd["due_date"] = new_due_date
            if new_desc:
                upd["description"] = new_desc

            supabase_admin.table("assignments").update(upd).eq("id", assignment_id).execute()
            # Sync user tasks
            task_upd = {}
            if new_title:
                task_upd["title"] = new_title
            if new_due_date:
                task_upd["due_date"] = new_due_date
            if task_upd:
                supabase_admin.table("user_tasks").update(task_upd).eq("assignment_id", assignment_id).execute()

            return jsonify({"success": True, "message": "Assignment and tasks updated successfully."}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to update assignment: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    cur.execute("SELECT created_by, classroom_id FROM assignments WHERE id = ?", (assignment_id,))
    assign = cur.fetchone()
    if not assign or assign["classroom_id"] != classroom_id:
        return jsonify({"error": "Assignment not found."}), 404

    is_owner = is_classroom_owner(db, classroom_id, user_id)
    if assign["created_by"] != user_id and not is_owner:
        return jsonify({"error": "Forbidden: Only assignment creator or classroom owner can edit assignments."}), 403

    if new_title and new_due_date:
        cur.execute("UPDATE assignments SET title = ?, due_date = ?, description = ? WHERE id = ?", (new_title, new_due_date, new_desc, assignment_id))
        cur.execute("UPDATE user_tasks SET title = ?, due_date = ? WHERE assignment_id = ?", (new_title, new_due_date, assignment_id))
    elif new_title:
        cur.execute("UPDATE assignments SET title = ? WHERE id = ?", (new_title, assignment_id))
        cur.execute("UPDATE user_tasks SET title = ? WHERE assignment_id = ?", (new_title, assignment_id))
    elif new_due_date:
        cur.execute("UPDATE assignments SET due_date = ? WHERE id = ?", (new_due_date, assignment_id))
        cur.execute("UPDATE user_tasks SET due_date = ? WHERE assignment_id = ?", (new_due_date, assignment_id))

    db.commit()
    return jsonify({"success": True, "message": "Assignment and tasks updated successfully."}), 200

@app.route("/api/classrooms/<classroom_id>/assignments/<assignment_id>", methods=["DELETE"])
@auth_required
def delete_assignment(classroom_id: str, assignment_id: str):
    db = get_db()
    user_id = g.current_user["id"]

    if HAS_SUPABASE:
        try:
            assign_res = supabase_admin.table("assignments").select("created_by").eq("id", assignment_id).execute()
            if not assign_res.data:
                return jsonify({"error": "Assignment not found."}), 404
            assign = assign_res.data[0]
            is_owner = is_classroom_owner(None, classroom_id, user_id)
            if assign["created_by"] != user_id and not is_owner:
                return jsonify({"error": "Forbidden: Only assignment creator or classroom owner can delete assignments."}), 403

            supabase_admin.table("assignments").delete().eq("id", assignment_id).execute()
            supabase_admin.table("user_tasks").delete().eq("assignment_id", assignment_id).execute()
            return jsonify({"success": True, "message": "Assignment deleted successfully."}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to delete assignment: {str(e)}"}), 500

    # SQLite Engine
    cur = db.cursor()
    cur.execute("SELECT created_by, classroom_id FROM assignments WHERE id = ?", (assignment_id,))
    assign = cur.fetchone()
    if not assign or assign["classroom_id"] != classroom_id:
        return jsonify({"error": "Assignment not found."}), 404

    is_owner = is_classroom_owner(db, classroom_id, user_id)
    if assign["created_by"] != user_id and not is_owner:
        return jsonify({"error": "Forbidden: Only assignment creator or classroom owner can delete assignments."}), 403

    cur.execute("DELETE FROM assignments WHERE id = ?", (assignment_id,))
    cur.execute("DELETE FROM user_tasks WHERE assignment_id = ?", (assignment_id,))
    db.commit()
    return jsonify({"success": True, "message": "Assignment deleted successfully."}), 200

# ----------------------------------------------------------------------------
# USER TASKS & DEADLINE TRACKING ROUTES
# ----------------------------------------------------------------------------
@app.route("/api/tasks", methods=["GET"])
@auth_required
def get_user_tasks():
    user_id = g.current_user["id"]

    if HAS_SUPABASE:
        try:
            tasks = supabase_admin.table("user_tasks").select("*").eq("user_id", user_id).order("due_date", desc=False).execute().data or []
            tasks_list = []
            for t in tasks:
                cls_name = "Classroom Task"
                if t.get("classroom_id"):
                    c_res = supabase_admin.table("classrooms").select("name").eq("id", t["classroom_id"]).execute().data
                    if c_res:
                        cls_name = c_res[0]["name"]
                tasks_list.append({
                    "id": t["id"],
                    "assignment_id": t.get("assignment_id"),
                    "classroom_id": t.get("classroom_id"),
                    "classroom_name": cls_name,
                    "title": t["title"],
                    "due_date": t["due_date"],
                    "status": t["status"],
                    "created_at": t.get("created_at")
                })
            return jsonify({"tasks": tasks_list}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to fetch tasks: {str(e)}"}), 500

    # SQLite Engine
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT
            ut.id, ut.assignment_id, ut.classroom_id, ut.title, ut.due_date, ut.status, ut.created_at,
            c.name AS classroom_name
        FROM user_tasks ut
        LEFT JOIN classrooms c ON c.id = ut.classroom_id
        WHERE ut.user_id = ?
        ORDER BY ut.due_date ASC
    """, (user_id,))
    rows = cur.fetchall()
    return jsonify({"tasks": [dict(r) for r in rows]}), 200

@app.route("/api/tasks/<task_id>", methods=["PATCH"])
@auth_required
def update_task_status(task_id: str):
    user_id = g.current_user["id"]
    data = request.get_json(silent=True) or {}
    status = (data.get("status") or "").strip()

    if status not in ("pending", "in_progress", "completed"):
        return jsonify({"error": "Invalid status. Must be pending, in_progress, or completed."}), 400

    if HAS_SUPABASE:
        try:
            res = supabase_admin.table("user_tasks").update({"status": status}).eq("id", task_id).eq("user_id", user_id).execute()
            if not res.data:
                return jsonify({"error": "Task not found."}), 404
            return jsonify({"task": res.data[0], "message": "Task status updated."}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to update task: {str(e)}"}), 500

    # SQLite Engine
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id FROM user_tasks WHERE id = ? AND user_id = ?", (task_id, user_id))
    if not cur.fetchone():
        return jsonify({"error": "Task not found."}), 404

    cur.execute("UPDATE user_tasks SET status = ? WHERE id = ? AND user_id = ?", (status, task_id, user_id))
    db.commit()

    return jsonify({"task": {"id": task_id, "status": status}, "message": "Task status updated."}), 200

# ----------------------------------------------------------------------------
# IN-APP NOTIFICATIONS ROUTES
# ----------------------------------------------------------------------------
@app.route("/api/notifications", methods=["GET"])
@auth_required
def get_notifications():
    user_id = g.current_user["id"]

    if HAS_SUPABASE:
        try:
            notifs = supabase_admin.table("notifications").select("*").eq("user_id", user_id).order("created_at", desc=True).limit(50).execute().data or []
            return jsonify({"notifications": notifs}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to fetch notifications: {str(e)}"}), 500

    # SQLite Engine
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT id, classroom_id, title, message, type, is_read, created_at
        FROM notifications
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 50
    """, (user_id,))
    rows = cur.fetchall()
    notifs = []
    for r in rows:
        notifs.append({
            "id": r["id"],
            "classroom_id": r["classroom_id"],
            "title": r["title"],
            "message": r["message"],
            "type": r["type"],
            "is_read": bool(r["is_read"]),
            "created_at": r["created_at"]
        })
    return jsonify({"notifications": notifs}), 200

@app.route("/api/notifications/<notif_id>/read", methods=["POST"])
@auth_required
def mark_notification_read(notif_id: str):
    user_id = g.current_user["id"]

    if HAS_SUPABASE:
        try:
            supabase_admin.table("notifications").update({"is_read": True}).eq("id", notif_id).eq("user_id", user_id).execute()
            return jsonify({"success": True}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to mark notification read: {str(e)}"}), 500

    # SQLite Engine
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?", (notif_id, user_id))
    db.commit()
    return jsonify({"success": True}), 200

# ----------------------------------------------------------------------------
# FRONTEND STATIC FILES & SPA ROUTING
# ----------------------------------------------------------------------------
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    public_dir = os.path.join(os.path.dirname(__file__), "public")
    if path != "" and os.path.exists(os.path.join(public_dir, path)):
        return send_from_directory(public_dir, path)
    return send_from_directory(public_dir, "index.html")

# ----------------------------------------------------------------------------
# APPLICATION ENTRY POINT
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
