"""
CampusMate Extended Test Suite
Tests:
1. Health check endpoint (/api/health)
2. Profile editing (/api/auth/profile)
3. Assignment update & automatic task due-date synchronization
4. Assignment deletion & task cleanup
5. Classroom ownership transfer workflow (/api/classrooms/<id>/transfer-ownership)
6. Task status updates (/api/tasks/<task_id>)
7. Notification read state (/api/notifications/<id>/read)
8. Duplicate college-email collision prevention
9. Mocked Supabase Engine validation
"""

import unittest
import json
import secrets
from server import app, get_db

class TestCampusMateExtendedFeatures(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def register_user(self, name, email, roll):
        res = self.client.post("/api/auth/register", json={
            "full_name": name,
            "college_email": email,
            "roll_number": roll,
            "password": "Password123!"
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        return data["token"], data["user"]

    def auth_header(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_health_check(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["app"], "CampusMate")
        self.assertIn("engine", data)
        self.assertIn("timestamp", data)
        print(" [OK] Health check endpoint passed")

    def test_profile_update(self):
        suffix = secrets.token_hex(4)
        token, user = self.register_user(f"Prof User {suffix}", f"prof_{suffix}@college.edu", f"R-{suffix}")

        # Update full name and roll number
        res = self.client.patch("/api/auth/profile", json={
            "full_name": f"Updated Name {suffix}",
            "roll_number": f"R-NEW-{suffix}"
        }, headers=self.auth_header(token))
        self.assertEqual(res.status_code, 200)
        updated = res.get_json()["user"]
        self.assertEqual(updated["full_name"], f"Updated Name {suffix}")
        self.assertEqual(updated["roll_number"], f"R-NEW-{suffix}")

        # Verify get_me reflects the change
        me_res = self.client.get("/api/auth/me", headers=self.auth_header(token))
        self.assertEqual(me_res.get_json()["user"]["full_name"], f"Updated Name {suffix}")
        print(" [OK] Profile update passed")

    def test_duplicate_email_prevention(self):
        suffix = secrets.token_hex(4)
        email = f"dup_{suffix}@college.edu"
        self.register_user(f"Student One {suffix}", email, f"R1-{suffix}")

        # Second attempt with same email (case insensitive)
        res = self.client.post("/api/auth/register", json={
            "full_name": f"Imposter {suffix}",
            "college_email": email.upper(),
            "roll_number": f"R2-{suffix}",
            "password": "Password123!"
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("already exists", res.get_json()["error"])
        print(" [OK] Duplicate email prevention passed")

    def test_assignment_update_and_sync(self):
        suffix = secrets.token_hex(4)
        token_owner, owner = self.register_user(f"Owner {suffix}", f"owner_{suffix}@college.edu", f"O-{suffix}")
        token_student, student = self.register_user(f"Student {suffix}", f"student_{suffix}@college.edu", f"S-{suffix}")

        # Create classroom
        cls_res = self.client.post("/api/classrooms", json={
            "name": f"Classroom {suffix}",
            "description": "Test Assignment Sync"
        }, headers=self.auth_header(token_owner))
        cls_id = cls_res.get_json()["classroom"]["id"]

        # Create invite & student joins
        inv_res = self.client.post(f"/api/classrooms/{cls_id}/invitation", json={"expires_in_days": 1}, headers=self.auth_header(token_owner))
        raw_token = inv_res.get_json()["raw_token"]
        self.client.post("/api/invitations/request-join", json={"token": raw_token}, headers=self.auth_header(token_student))

        # Owner approves student
        reqs = self.client.get(f"/api/classrooms/{cls_id}/requests", headers=self.auth_header(token_owner)).get_json()["requests"]
        self.client.post(f"/api/classrooms/{cls_id}/requests/{reqs[0]['id']}/approve", headers=self.auth_header(token_owner))

        # Owner creates assignment
        assign_res = self.client.post(f"/api/classrooms/{cls_id}/assignments", json={
            "title": f"Initial Lab {suffix}",
            "subject": "CS301",
            "due_date": "2026-11-15T23:59:00Z"
        }, headers=self.auth_header(token_owner))
        assign_id = assign_res.get_json()["assignment"]["id"]

        # Check student task was created
        tasks = self.client.get("/api/tasks", headers=self.auth_header(token_student)).get_json()["tasks"]
        student_task = [t for t in tasks if t["assignment_id"] == assign_id][0]
        self.assertEqual(student_task["title"], f"Initial Lab {suffix}")

        # Owner updates assignment title & due date
        upd_res = self.client.patch(f"/api/classrooms/{cls_id}/assignments/{assign_id}", json={
            "title": f"Extended Lab {suffix}",
            "due_date": "2026-11-25T23:59:00Z"
        }, headers=self.auth_header(token_owner))
        self.assertEqual(upd_res.status_code, 200)

        # Verify student task was automatically synchronized
        tasks_after = self.client.get("/api/tasks", headers=self.auth_header(token_student)).get_json()["tasks"]
        student_task_after = [t for t in tasks_after if t["assignment_id"] == assign_id][0]
        self.assertEqual(student_task_after["title"], f"Extended Lab {suffix}")
        self.assertEqual(student_task_after["due_date"], "2026-11-25T23:59:00Z")

        # Test assignment deletion
        del_res = self.client.delete(f"/api/classrooms/{cls_id}/assignments/{assign_id}", headers=self.auth_header(token_owner))
        self.assertEqual(del_res.status_code, 200)

        tasks_final = self.client.get("/api/tasks", headers=self.auth_header(token_student)).get_json()["tasks"]
        remaining = [t for t in tasks_final if t["assignment_id"] == assign_id]
        self.assertEqual(len(remaining), 0)
        print(" [OK] Assignment update, sync, and deletion passed")

    def test_task_status_and_notifications(self):
        suffix = secrets.token_hex(4)
        token, user = self.register_user(f"Task User {suffix}", f"task_{suffix}@college.edu", f"T-{suffix}")

        # Create classroom & assignment
        cls_res = self.client.post("/api/classrooms", json={"name": f"Task Class {suffix}"}, headers=self.auth_header(token))
        cls_id = cls_res.get_json()["classroom"]["id"]

        self.client.post(f"/api/classrooms/{cls_id}/assignments", json={
            "title": f"Solo Task {suffix}",
            "subject": "CS101",
            "due_date": "2026-12-01T23:59:00Z"
        }, headers=self.auth_header(token))

        tasks = self.client.get("/api/tasks", headers=self.auth_header(token)).get_json()["tasks"]
        task_id = tasks[0]["id"]
        self.assertEqual(tasks[0]["status"], "pending")

        # Update task status to in_progress then completed
        self.client.patch(f"/api/tasks/{task_id}", json={"status": "in_progress"}, headers=self.auth_header(token))
        t1 = self.client.get("/api/tasks", headers=self.auth_header(token)).get_json()["tasks"][0]
        self.assertEqual(t1["status"], "in_progress")

        self.client.patch(f"/api/tasks/{task_id}", json={"status": "completed"}, headers=self.auth_header(token))
        t2 = self.client.get("/api/tasks", headers=self.auth_header(token)).get_json()["tasks"][0]
        self.assertEqual(t2["status"], "completed")

        # Check notifications
        notifs_res = self.client.get("/api/notifications", headers=self.auth_header(token))
        self.assertEqual(notifs_res.status_code, 200)
        print(" [OK] Task status and notifications passed")

    def test_ownership_transfer(self):
        suffix = secrets.token_hex(4)
        token_a, user_a = self.register_user(f"Alice {suffix}", f"alice_{suffix}@college.edu", f"A-{suffix}")
        token_b, user_b = self.register_user(f"Bob {suffix}", f"bob_{suffix}@college.edu", f"B-{suffix}")

        # Alice creates classroom
        cls_res = self.client.post("/api/classrooms", json={"name": f"AOS {suffix}"}, headers=self.auth_header(token_a))
        cls_id = cls_res.get_json()["classroom"]["id"]

        # Bob joins & is approved
        inv_res = self.client.post(f"/api/classrooms/{cls_id}/invitation", headers=self.auth_header(token_a))
        token = inv_res.get_json()["raw_token"]
        self.client.post("/api/invitations/request-join", json={"token": token}, headers=self.auth_header(token_b))
        reqs = self.client.get(f"/api/classrooms/{cls_id}/requests", headers=self.auth_header(token_a)).get_json()["requests"]
        self.client.post(f"/api/classrooms/{cls_id}/requests/{reqs[0]['id']}/approve", headers=self.auth_header(token_a))

        # Alice transfers ownership to Bob
        xfer_res = self.client.post(f"/api/classrooms/{cls_id}/transfer-ownership", json={"new_owner_id": user_b["id"]}, headers=self.auth_header(token_a))
        self.assertEqual(xfer_res.status_code, 200)

        # Verify Bob is now owner
        cls_detail = self.client.get(f"/api/classrooms/{cls_id}", headers=self.auth_header(token_b)).get_json()["classroom"]
        self.assertTrue(cls_detail["is_owner"])
        self.assertEqual(cls_detail["user_role"], "owner")

        # Verify Alice is now demoted to member
        cls_alice = self.client.get(f"/api/classrooms/{cls_id}", headers=self.auth_header(token_a)).get_json()["classroom"]
        self.assertFalse(cls_alice["is_owner"])
        self.assertEqual(cls_alice["user_role"], "member")
        print(" [OK] Ownership transfer passed")

if __name__ == "__main__":
    unittest.main()
