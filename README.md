# CampusMate — College Classroom & Academic Coordination Platform

CampusMate is an invitation-based college classroom coordination web app built for students and classmates to manage academic coursework, deadlines, lab records, assignments, and announcements with privacy, single-owner governance, and automatic task synchronization.

---

## 1. Core Architecture & Highlights

- **Single-Owner Classroom Governance:** Every classroom has exactly one designated owner (creator) who controls membership, issues cryptographically secure invitation links, approves/rejects join requests, and removes members.
- **Strict 3-Field Student Profile:** Students register with only `Full Name`, `College Email Address`, and `Roll Number`. No unnecessary personal data (phone, DOB, address, gender) is ever requested.
- **Zero-Trust Cryptographic Invitations:** Invitation tokens are stored as SHA-256 hashes (`token_hash`). Opening an invitation URL never grants automatic access; visitors only see a sanitized preview (classroom name and owner name). Applicants must request to join and await owner approval.
- **Automatic Assignment Fan-Out & Task Sync:** When an assignment is created or updated by any approved member or the owner, individual task entries are automatically synchronized into every classmate's personal `user_tasks` list with real-time in-app notifications.
- **Dual-Engine Backend:**
  - **Local Development / Offline Mode:** Runs entirely on local SQLite (`campusmate.db`) with zero setup or external keys required.
  - **Production Online Mode:** Seamlessly connects to **Supabase Cloud PostgreSQL** and **Supabase Auth** when configured in environment variables.
- **Mobile-First PWA:** Installable on Android, iOS, Windows, and macOS as a standalone Progressive Web App with offline caching support.

---

## 2. Project Files Map

```
CampusMate/
├── server.py                     # Flask dual-engine backend (Supabase Cloud + SQLite fallback)
├── requirements.txt             # Python production dependencies (Flask, gunicorn, supabase, etc.)
├── Procfile                     # Render/Heroku process start command
├── render.yaml                  # Render Infrastructure-as-Code blueprint specification
├── .gitignore                   # Git exclusion rules (protects campusmate.db, secrets, .env)
├── .env.example                 # Environment variables configuration template
├── supabase_schema.sql          # Step 1: Baseline Supabase PostgreSQL tables & RLS policies
├── supabase_migration_patch.sql # Step 2: Security DEFINER hardening, faculty safeguards, triggers
├── test_scenarios.py            # Automated security suite (Scenarios A through I)
├── test_extended.py             # Extended test suite (Health, sync, delete, transfer, profile)
├── test_supabase_adapter.py     # Mocked Supabase adapter unit verification
├── campusmate.db                # Local SQLite database
└── public/                      # Static web assets & SPA frontend
    ├── index.html               # 10 Application screens, modals, Tailwind & Lucide icons
    ├── app.js                   # Client SPA router, session handling, notifications & tasks
    ├── styles.css               # Responsive design & custom scrollbars
    ├── manifest.json            # PWA web manifest
    ├── sw.js                    # PWA Service Worker (caching shell + dynamic API bypass)
    └── icon.svg                 # Scalable CampusMate app icon
```

---

## 3. Running Locally (Quick Start)

### Step 1: Install Dependencies
Open PowerShell or your terminal in the project directory:
```powershell
pip install -r requirements.txt
```

### Step 2: Start the Local Server
```powershell
python server.py
```
You will see:
```
[CampusMate] Running in Local SQLite Engine mode (campusmate.db).
 * Running on http://127.0.0.1:5000
```

### Step 3: Open in Your Web Browser
Navigate to `http://localhost:5000` to test the application.

---

## 4. Running the Automated Tests

All tests run locally without needing external keys:

```powershell
# 1. Run Core Security Scenarios A through I:
python test_scenarios.py

# 2. Run Extended Features (Health, Task Sync, Ownership Transfer):
python test_extended.py

# 3. Run Supabase Cloud Adapter Unit Verification:
python test_supabase_adapter.py

# 4. Run All Test Suites Together:
python -m unittest discover -p "test_*.py"
```

---

## 5. Online Cloud Deployment Guide (Beginner Step-by-Step)

To make CampusMate accessible online for your classmates, you will use **Supabase** (free cloud database & authentication) and **Render** (free web hosting).

### Part A: Set Up Supabase Database

1. **Create an Account:** Go to [supabase.com](https://supabase.com) and click **"Start your project"** (Sign in with GitHub).
2. **Create New Project:** Click **"New Project"**, give it a name (e.g. `CampusMate`), and set a strong database password. Choose the region closest to you.
3. **Execute SQL Script 1 (Baseline Schema):**
   - In your Supabase Dashboard left menu, click **"SQL Editor"**.
   - Click **"New query"**.
   - Open [`supabase_schema.sql`](supabase_schema.sql), copy all its contents, paste them into the SQL Editor, and click **"Run"**.
   - Verify: 10 tables are created with Row Level Security enabled.
4. **Execute SQL Script 2 (Security Patch & Triggers):**
   - Click **"New query"** again.
   - Open [`supabase_migration_patch.sql`](supabase_migration_patch.sql), copy all its contents, paste them into the SQL Editor, and click **"Run"**.
   - Verify: Triggers on `auth.users`, `assignments`, and `profiles` are provisioned.
5. **Get Your API Credentials:**
   - In Supabase Dashboard, click **Project Settings** (gear icon at the bottom left) -> **API**.
   - Copy **Project URL** (e.g., `https://xyzabcdef.supabase.co`).
   - Copy **service_role (secret)** key (under *Project API keys*).

---

### Part B: Deploy Backend to Render

1. **Push Code to GitHub:**
   - Create a new repository on [github.com](https://github.com) named `CampusMate`.
   - In your local project directory, initialize Git, commit, and push:
     ```powershell
     git init
     git add .
     git commit -m "Deploy CampusMate"
     git branch -M main
     git remote add origin https://github.com/<your-username>/CampusMate.git
     git push -u origin main
     ```
2. **Create Web Service on Render:**
   - Go to [render.com](https://render.com) and sign in with GitHub.
   - Click **"New +"** (top right) -> **"Web Service"**.
   - Connect your `CampusMate` GitHub repository.
3. **Configure Settings:**
   - **Name:** `campusmate`
   - **Region:** Choose Oregon or closest to your Supabase region.
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn server:app --bind 0.0.0.0:$PORT`
   - **Instance Type:** `Free`
4. **Add Environment Variables (under "Environment Variables" section):**
   - `SUPABASE_URL` = your Supabase Project URL (`https://xyzabcdef.supabase.co`)
   - `SUPABASE_SERVICE_ROLE_KEY` = your Supabase `service_role` secret key
   - `FLASK_SECRET_KEY` = any random 32-character string
5. **Deploy:**
   - Click **"Create Web Service"**.
   - Render will build your app and deploy it online at `https://campusmate-xxxx.onrender.com`.

---

## 6. How to Test Online with Your Classmates

1. **Student A (Classroom Owner):**
   - Opens the live Render URL in Chrome/Edge/Safari.
   - Registers with:
     - Name: `Alice Johnson`
     - Email: `alice@college.edu`
     - Roll: `CS-101`
   - Clicks **"Create Classroom"** -> enters `Operating Systems`.
   - Clicks **"Invite Classmates"** -> clicks **"Copy Link"** (e.g. `https://campusmate-xxxx.onrender.com/?invite=xyz...`).
2. **Student B (Applicant):**
   - Opens the copied invitation link in an incognito window or separate phone/browser.
   - Sees the **Limited Preview** (displays only *"Operating Systems | Owner: Alice Johnson"* without any assignments or member lists).
   - Registers with:
     - Name: `Bob Smith`
     - Email: `bob@college.edu`
     - Roll: `CS-102`
   - Clicks **"Request to Join"**.
   - Screen displays: *"Your request has been sent. Waiting for owner approval."*
3. **Student A (Approval):**
   - Returns to Owner Dashboard -> clicks **"Join Requests"** tab.
   - Sees Bob Smith's request with name, email, and roll number.
   - Clicks **"Approve"**.
4. **Instant Synchronization:**
   - Student B's screen automatically grants classroom access upon refresh.
   - Student A posts an assignment (*"Lab 1: CPU Scheduling"*).
   - Student B receives an instant in-app notification and the assignment is automatically added to Bob's **"My Tasks"** checklist!

---

## 7. Installing on Mobile (PWA)

CampusMate includes a full Progressive Web App manifest and offline service worker:
- **On Android (Chrome):** Tap the 3 dots menu -> tap **"Install App"** or **"Add to Home Screen"**.
- **On iPhone (Safari):** Tap the Share button (square with arrow) -> tap **"Add to Home Screen"**.
- CampusMate will run as a native full-screen application with its custom app icon!
#   C a m p u s M a t e  
 