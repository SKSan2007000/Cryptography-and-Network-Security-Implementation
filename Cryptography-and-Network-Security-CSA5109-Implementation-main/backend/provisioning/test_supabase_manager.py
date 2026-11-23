import os
import unittest
from backend.provisioning.supabase_manager import SupabaseManager, generate_secure_db_password


class TestSupabaseManagerAuth(unittest.TestCase):
    def test_strip_trailing_and_leading_whitespace(self):
        token_with_whitespace = "  sbp_fc1234567890abcdef   \n\t "
        manager = SupabaseManager(token=token_with_whitespace)
        self.assertEqual(manager.token, "sbp_fc1234567890abcdef")
        self.assertEqual(
            manager.headers["Authorization"],
            "Bearer sbp_fc1234567890abcdef",
        )
        self.assertFalse(manager.headers["Authorization"].endswith(" "))
        self.assertFalse(manager.headers["Authorization"].startswith("Bearer  "))

    def test_strip_quotes_around_token(self):
        token_with_quotes = '"sbp_fc999888777"'
        manager = SupabaseManager(token=token_with_quotes)
        self.assertEqual(manager.token, "sbp_fc999888777")
        self.assertEqual(manager.headers["Authorization"], "Bearer sbp_fc999888777")

    def test_bearer_prefix_deduplication(self):
        token_with_bearer = "Bearer sbp_fc444333222  "
        manager = SupabaseManager(token=token_with_bearer)
        self.assertEqual(manager.token, "sbp_fc444333222")
        self.assertEqual(manager.headers["Authorization"], "Bearer sbp_fc444333222")

    def test_empty_token_raises_error(self):
        with self.assertRaises(ValueError):
            SupabaseManager(token="   ")

    def test_password_generation_satisfies_rules(self):
        pwd = generate_secure_db_password(24)
        self.assertEqual(len(pwd), 24)
        self.assertTrue(any(c.isupper() for c in pwd))
        self.assertTrue(any(c.islower() for c in pwd))
        self.assertTrue(any(c.isdigit() for c in pwd))


if __name__ == "__main__":
    unittest.main()
