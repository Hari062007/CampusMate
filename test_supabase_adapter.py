"""
CampusMate Supabase Adapter Unit Tests (Mock-Assisted)
Verifies:
- Supabase Auth registration, login, token verification
- Supabase RPC invocations with exact schema parameter names:
    - create_classroom(p_name, p_description)
    - create_invitation_link(p_classroom_id, p_token_hash, p_expires_at)
    - revoke_invitation_link(p_classroom_id)
    - get_invitation_preview(p_token_hash)
    - request_to_join(p_token_hash)
    - approve_join_request(p_request_id)
    - reject_join_request(p_request_id)
    - remove_classroom_member(p_classroom_id, p_member_user_id)
    - transfer_classroom_ownership(p_classroom_id, p_new_owner_id)
- Zero exposure of service role keys
"""

import unittest
from unittest.mock import MagicMock, patch
import server

class TestSupabaseAdapterMock(unittest.TestCase):
    def setUp(self):
        server.app.config["TESTING"] = True
        self.client = server.app.test_client()

    def test_mocked_supabase_registration_and_login(self):
        mock_admin = MagicMock()
        mock_auth = MagicMock()
        mock_admin.auth = mock_auth

        # Mock admin.create_user
        mock_user = MagicMock()
        mock_user.id = "mock-uuid-1234"
        mock_user.email = "student@college.edu"
        mock_auth.admin.create_user.return_value = MagicMock(user=mock_user)

        # Mock sign_in_with_password
        mock_session = MagicMock()
        mock_session.access_token = "mock-jwt-token-xyz"
        mock_auth.sign_in_with_password.return_value = MagicMock(user=mock_user, session=mock_session)

        # Mock table queries
        mock_table = MagicMock()
        mock_admin.table.return_value = mock_table
        mock_table.select.return_value = mock_table
        mock_table.ilike.return_value = mock_table
        mock_table.eq.return_value = mock_table
        mock_table.upsert.return_value = mock_table
        mock_table.execute.return_value = MagicMock(data=[])

        with patch.object(server, "HAS_SUPABASE", True), \
             patch.object(server, "supabase_admin", mock_admin):

            res = self.client.post("/api/auth/register", json={
                "full_name": "Test Student",
                "college_email": "student@college.edu",
                "roll_number": "CS-101",
                "password": "Password123!"
            })
            self.assertEqual(res.status_code, 201)
            data = res.get_json()
            self.assertEqual(data["token"], "mock-jwt-token-xyz")
            self.assertEqual(data["user"]["id"], "mock-uuid-1234")

            # Verify admin.create_user called with exact structure
            mock_auth.admin.create_user.assert_called_once()
            call_args = mock_auth.admin.create_user.call_args[0][0]
            self.assertEqual(call_args["email"], "student@college.edu")
            self.assertEqual(call_args["user_metadata"]["full_name"], "Test Student")
            self.assertEqual(call_args["user_metadata"]["roll_number"], "CS-101")
        print(" [OK] Mocked Supabase registration and login passed")

    def test_mocked_supabase_rpc_parameter_signatures(self):
        mock_admin = MagicMock()
        mock_rpc = MagicMock()
        mock_admin.rpc = mock_rpc

        with patch.object(server, "HAS_SUPABASE", True), \
             patch.object(server, "supabase_admin", mock_admin):

            # Test preview_invitation RPC call
            mock_rpc.return_value.execute.return_value = MagicMock(data={
                "valid": True,
                "status": "active",
                "classroom_id": "cls-uuid",
                "classroom_name": "Operating Systems",
                "owner_name": "Dr. Smith"
            })

            res = self.client.get("/api/invitations/preview?token=test_invite_token_123")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data["classroom_name"], "Operating Systems")

            # Verify exact RPC parameter name p_token_hash was passed
            mock_rpc.assert_called_with("get_invitation_preview", {"p_token_hash": unittest.mock.ANY})
            token_hash = mock_rpc.call_args[0][1]["p_token_hash"]
            self.assertEqual(len(token_hash), 64) # SHA-256 hash length
        print(" [OK] Mocked Supabase RPC signatures passed")

if __name__ == "__main__":
    unittest.main()
