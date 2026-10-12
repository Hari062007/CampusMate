"""
CampusMate Automated Security & Workflow Verification Suite
Implements and verifies Scenarios A through I as specified in the requirements.
"""

import unittest
import json
import os
import tempfile
from server import app, init_db, DB_PATH

class TestCampusMateSecurityScenarios(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Ensure fresh database state
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        init_db()

    def setUp(self):
        self.client = app.test_client()

    def register_user(self, full_name, email, roll_number, password="Password123!"):
        res = self.client.post("/api/auth/register", json={
            "full_name": full_name,
            "college_email": email,
            "roll_number": roll_number,
            "password": password
        })
        self.assertEqual(res.status_code, 201, f"Registration failed: {res.data.decode()}")
        data = res.get_json()
        return data["token"], data["user"]

    def auth_header(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_complete_scenarios_a_through_i(self):
        print("\n=======================================================")
        print("RUNNING CAMPUSMATE SECURITY & ACCESS CONTROL VERIFICATION")
        print("=======================================================")

        # ---------------------------------------------------------------------
        # SCENARIO A: Student A creates a classroom and generates an invitation link
        # ---------------------------------------------------------------------
        print("\n[Scenario A] Registering Student A, creating classroom and generating invitation...")
        token_a, student_a = self.register_user("Alice Johnson", "alice@college.edu", "CS-2026-001")
        
        # 1. Create Classroom
        cls_res = self.client.post("/api/classrooms", json={
            "name": "Advanced Operating Systems",
            "description": "Fall 2026 CS Core Classroom"
        }, headers=self.auth_header(token_a))
        self.assertEqual(cls_res.status_code, 201)
        classroom_id = cls_res.get_json()["classroom"]["id"]
        print(f" -> Classroom created: {classroom_id} by Owner: {student_a['full_name']}")

        # Verify owner has classroom in list with role 'owner'
        list_res = self.client.get("/api/classrooms", headers=self.auth_header(token_a))
        self.assertEqual(list_res.status_code, 200)
        classrooms = list_res.get_json()["classrooms"]
        self.assertEqual(len(classrooms), 1)
        self.assertEqual(classrooms[0]["role"], "owner")

        # 2. Add an assignment and a classroom post
        post_res = self.client.post(f"/api/classrooms/{classroom_id}/posts", json={
            "title": "Welcome to AOS",
            "content": "Syllabus and first lecture notes are now posted."
        }, headers=self.auth_header(token_a))
        self.assertEqual(post_res.status_code, 201)

        assign_res = self.client.post(f"/api/classrooms/{classroom_id}/assignments", json={
            "title": "Kernel Memory Allocator",
            "subject": "CS401",
            "description": "Implement buddy allocator in C",
            "due_date": "2026-11-01T23:59:59Z"
        }, headers=self.auth_header(token_a))
        self.assertEqual(assign_res.status_code, 201)

        # 3. Student A generates invitation link
        inv_res = self.client.post(f"/api/classrooms/{classroom_id}/invitation", json={
            "expires_in_days": 7
        }, headers=self.auth_header(token_a))
        self.assertEqual(inv_res.status_code, 201)
        inv_data = inv_res.get_json()
        raw_token = inv_data["raw_token"]
        self.assertTrue(len(raw_token) > 20)
        print(f" -> Secure invitation token generated: {raw_token[:10]}...")

        # ---------------------------------------------------------------------
        # SCENARIO B: Student B opens the link and requests access
        # ---------------------------------------------------------------------
        print("\n[Scenario B] Student B opens invitation preview and submits join request...")
        token_b, student_b = self.register_user("Bob Smith", "bob@college.edu", "CS-2026-042")

        # Preview invitation (Must NOT expose member list or private posts!)
        prev_res = self.client.get(f"/api/invitations/preview?token={raw_token}", headers=self.auth_header(token_b))
        self.assertEqual(prev_res.status_code, 200)
        prev_data = prev_res.get_json()
        self.assertEqual(prev_data["classroom_name"], "Advanced Operating Systems")
        self.assertEqual(prev_data["owner_name"], "Alice Johnson")
        self.assertNotIn("posts", prev_data)
        self.assertNotIn("members", prev_data)
        self.assertNotIn("assignments", prev_data)
        print(f" -> Preview validated: Limited metadata only (Classroom: {prev_data['classroom_name']})")

        # Submit join request
        req_res = self.client.post("/api/invitations/request-join", json={
            "token": raw_token
        }, headers=self.auth_header(token_b))
        self.assertEqual(req_res.status_code, 200)
        self.assertEqual(req_res.get_json()["status"], "pending")
        self.assertIn("Your request has been sent", req_res.get_json()["message"])
        print(f" -> Student B request status: PENDING")

        # ---------------------------------------------------------------------
        # SCENARIO C: Student B cannot view classroom content before approval
        # ---------------------------------------------------------------------
        print("\n[Scenario C] Verifying Student B is BLOCKED from private classroom content...")
        posts_b = self.client.get(f"/api/classrooms/{classroom_id}/posts", headers=self.auth_header(token_b))
        self.assertEqual(posts_b.status_code, 403, "Student B should receive 403 Forbidden on posts")

        assigns_b = self.client.get(f"/api/classrooms/{classroom_id}/assignments", headers=self.auth_header(token_b))
        self.assertEqual(assigns_b.status_code, 403, "Student B should receive 403 Forbidden on assignments")

        members_b = self.client.get(f"/api/classrooms/{classroom_id}/members", headers=self.auth_header(token_b))
        self.assertEqual(members_b.status_code, 403, "Student B should receive 403 Forbidden on member list")
        print(" -> Access correctly DENIED (403 Forbidden) for unapproved Student B")

        # ---------------------------------------------------------------------
        # SCENARIO D: Student A approves Student B. Student B gains access
        # ---------------------------------------------------------------------
        print("\n[Scenario D] Student A approves Student B and verifies access granted...")
        # Check owner received join request
        requests_res = self.client.get(f"/api/classrooms/{classroom_id}/requests", headers=self.auth_header(token_a))
        self.assertEqual(requests_res.status_code, 200)
        req_list = requests_res.get_json()["requests"]
        self.assertEqual(len(req_list), 1)
        req_b_id = req_list[0]["id"]
        self.assertEqual(req_list[0]["full_name"], "Bob Smith")
        self.assertEqual(req_list[0]["roll_number"], "CS-2026-042")

        # Approve request
        appr_res = self.client.post(f"/api/classrooms/{classroom_id}/requests/{req_b_id}/approve", headers=self.auth_header(token_a))
        self.assertEqual(appr_res.status_code, 200)
        self.assertEqual(appr_res.get_json()["status"], "approved")

        # Verify Student B now has access
        posts_b_after = self.client.get(f"/api/classrooms/{classroom_id}/posts", headers=self.auth_header(token_b))
        self.assertEqual(posts_b_after.status_code, 200)
        self.assertEqual(len(posts_b_after.get_json()["posts"]), 1)

        assigns_b_after = self.client.get(f"/api/classrooms/{classroom_id}/assignments", headers=self.auth_header(token_b))
        self.assertEqual(assigns_b_after.status_code, 200)
        self.assertEqual(len(assigns_b_after.get_json()["assignments"]), 1)

        # Verify assignment was automatically synced into Student B's personal tasks
        tasks_b = self.client.get("/api/tasks", headers=self.auth_header(token_b))
        self.assertEqual(tasks_b.status_code, 200)
        self.assertEqual(len(tasks_b.get_json()["tasks"]), 1)
        self.assertEqual(tasks_b.get_json()["tasks"][0]["title"], "Kernel Memory Allocator")
        print(" -> Student B APPROVED: Classroom content and synchronized tasks now accessible")

        # ---------------------------------------------------------------------
        # SCENARIO E: Student C opens the same link and requests access. Remains blocked until separately approved
        # ---------------------------------------------------------------------
        print("\n[Scenario E] Student C requests access using same link. Verifying Student C remains blocked...")
        token_c, student_c = self.register_user("Charlie Brown", "charlie@college.edu", "CS-2026-088")
        req_c_res = self.client.post("/api/invitations/request-join", json={"token": raw_token}, headers=self.auth_header(token_c))
        self.assertEqual(req_c_res.status_code, 200)
        self.assertEqual(req_c_res.get_json()["status"], "pending")

        # Check Student C is blocked from posts
        posts_c = self.client.get(f"/api/classrooms/{classroom_id}/posts", headers=self.auth_header(token_c))
        self.assertEqual(posts_c.status_code, 403, "Student C must remain blocked until approved")
        print(" -> Student C remains BLOCKED pending separate approval")

        # ---------------------------------------------------------------------
        # SCENARIO F: Student B attempts to approve their own request or another request
        # ---------------------------------------------------------------------
        print("\n[Scenario F] Student B attempts unauthorized request approval. Verifying rejection...")
        # Get pending request for Charlie
        requests_res_all = self.client.get(f"/api/classrooms/{classroom_id}/requests", headers=self.auth_header(token_a))
        req_c_id = [r["id"] for r in requests_res_all.get_json()["requests"] if r["user_id"] == student_c["id"]][0]

        # Student B attempts to approve Charlie
        tamper_res = self.client.post(f"/api/classrooms/{classroom_id}/requests/{req_c_id}/approve", headers=self.auth_header(token_b))
        self.assertEqual(tamper_res.status_code, 403, "Backend must reject non-owner approval attempt")

        # Student B attempts to view requests dashboard
        dash_tamper = self.client.get(f"/api/classrooms/{classroom_id}/requests", headers=self.auth_header(token_b))
        self.assertEqual(dash_tamper.status_code, 403, "Backend must deny non-owner access to requests list")
        print(" -> Self-approval / privilege escalation attempt REJECTED (403 Forbidden)")

        # ---------------------------------------------------------------------
        # SCENARIO G: Student A revokes invitation link. New applicants blocked, existing members retain access
        # ---------------------------------------------------------------------
        print("\n[Scenario G] Student A revokes invitation link. Verifying new applicants blocked & members retained...")
        revoke_res = self.client.post(f"/api/classrooms/{classroom_id}/invitation/revoke", headers=self.auth_header(token_a))
        self.assertEqual(revoke_res.status_code, 200)

        # Student D tries to use the revoked invitation
        token_d, student_d = self.register_user("Diana Prince", "diana@college.edu", "CS-2026-099")
        prev_d = self.client.get(f"/api/invitations/preview?token={raw_token}", headers=self.auth_header(token_d))
        self.assertEqual(prev_d.status_code, 410, "Revoked invitation should return 410 Gone")

        req_d = self.client.post("/api/invitations/request-join", json={"token": raw_token}, headers=self.auth_header(token_d))
        self.assertEqual(req_d.status_code, 410, "Join request on revoked link must be rejected")

        # Verify existing approved member (Student B) STILL has access
        posts_b_still = self.client.get(f"/api/classrooms/{classroom_id}/posts", headers=self.auth_header(token_b))
        self.assertEqual(posts_b_still.status_code, 200, "Approved member retains access after link revocation")
        print(" -> Revoked link blocked for new applicants; existing approved member B retained access")

        # ---------------------------------------------------------------------
        # SCENARIO H: Student A removes Student B. Student B loses access immediately
        # ---------------------------------------------------------------------
        print("\n[Scenario H] Student A removes Student B. Verifying immediate access loss...")
        del_res = self.client.delete(f"/api/classrooms/{classroom_id}/members/{student_b['id']}", headers=self.auth_header(token_a))
        self.assertEqual(del_res.status_code, 200)

        # Student B tries to access posts and assignments
        posts_b_removed = self.client.get(f"/api/classrooms/{classroom_id}/posts", headers=self.auth_header(token_b))
        self.assertEqual(posts_b_removed.status_code, 403, "Removed member must lose access to posts")

        assign_b_removed = self.client.get(f"/api/classrooms/{classroom_id}/assignments", headers=self.auth_header(token_b))
        self.assertEqual(assign_b_removed.status_code, 403, "Removed member must lose access to assignments")
        print(" -> Student B successfully REMOVED; immediate access loss verified")

        # ---------------------------------------------------------------------
        # SCENARIO I: Direct unauthenticated / unapproved access denied
        # ---------------------------------------------------------------------
        print("\n[Scenario I] Verifying direct access without approval or authentication is denied...")
        unauth_posts = self.client.get(f"/api/classrooms/{classroom_id}/posts")
        self.assertEqual(unauth_posts.status_code, 401, "Unauthenticated access must return 401")

        unauth_reqs = self.client.get(f"/api/classrooms/{classroom_id}/requests")
        self.assertEqual(unauth_reqs.status_code, 401, "Unauthenticated request must return 401")
        print(" -> Direct unauthenticated / unauthorized requests strictly DENIED")

        print("\n=======================================================")
        print("ALL SCENARIOS A THROUGH I PASSED SUCCESSFULLY!")
        print("=======================================================\n")

if __name__ == "__main__":
    unittest.main()
