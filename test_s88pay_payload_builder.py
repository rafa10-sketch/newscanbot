import sys
import unittest
from base64 import b64decode
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from tools.s88pay_build_readonly_payload import build_payload, encrypt_token
import hashlib


def decrypt_token(token: str, api_key: str, secret_key: str) -> str:
    key = hashlib.sha256(api_key.encode("utf-8")).digest()[:32]
    iv = hashlib.sha256(secret_key.encode("utf-8")).hexdigest()[:16].encode("utf-8")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(b64decode(unquote(token))) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-8")


class S88PayPayloadBuilderTests(unittest.TestCase):
    def test_encrypt_token_round_trip(self):
        payload = "merchant_code=SKU123&currency_code=INR"
        token = encrypt_token(payload, "api-key", "secret-key")
        self.assertEqual(decrypt_token(token, "api-key", "secret-key"), payload)

    def test_build_payload_contains_encrypted_keys(self):
        endpoints = build_payload("SKU123", "INR", "TX001", "api-key", "secret-key")
        self.assertEqual(len(endpoints), 3)
        self.assertEqual(endpoints[0]["method"], "GET")
        self.assertNotIn("body", endpoints[0])
        self.assertIn("?key=", endpoints[0]["path"])
        self.assertEqual(
            decrypt_token(endpoints[0]["path"].split("?key=", 1)[1], "api-key", "secret-key"),
            "merchant_code=SKU123",
        )
        self.assertEqual(endpoints[2]["method"], "POST")
        self.assertIn("/transactions/status", endpoints[2]["path"])

    def test_build_payload_can_skip_transaction_status(self):
        endpoints = build_payload("SKU123", "INR", None, "api-key", "secret-key")
        self.assertEqual(len(endpoints), 2)
        self.assertEqual(endpoints[0]["method"], "GET")
        self.assertIn("/api/v1/balance/SKU123?key=", endpoints[0]["path"])
        self.assertEqual(endpoints[1]["method"], "POST")
        self.assertEqual(endpoints[1]["path"], "/api/v2/channel/SKU123")
        self.assertTrue(all("/transactions/status" not in item["path"] for item in endpoints))

    def test_build_payload_can_include_negative_controls(self):
        endpoints = build_payload(
            "SKU123",
            "INR",
            None,
            "api-key",
            "secret-key",
            include_negative_controls=True,
        )
        names = [endpoint["name"] for endpoint in endpoints]
        self.assertEqual(len(endpoints), 8)
        self.assertIn("Balance invalid key negative control", names)
        self.assertIn("Channel invalid key negative control", names)
        self.assertIn("Balance with channel key swap negative control", names)
        self.assertIn("Channel with balance key swap negative control", names)
        self.assertEqual(endpoints[2]["path"], "/api/v1/balance/SKU123")
        self.assertEqual(endpoints[5]["body"], {})

    def test_build_payload_can_include_wrong_merchant_boundary_controls(self):
        endpoints = build_payload(
            "SKU123",
            "INR",
            "TX001",
            "api-key",
            "secret-key",
            scope_merchant_code="SKU999",
        )

        names = [endpoint["name"] for endpoint in endpoints]
        self.assertEqual(len(endpoints), 6)
        self.assertIn("Balance wrong merchant negative control", names)
        self.assertIn("Channel wrong merchant negative control", names)
        self.assertIn("Transaction status wrong merchant negative control", names)

        boundary_balance = endpoints[3]
        self.assertEqual(boundary_balance["path"].split("?key=", 1)[0], "/api/v1/balance/SKU999")
        self.assertEqual(
            decrypt_token(boundary_balance["path"].split("?key=", 1)[1], "api-key", "secret-key"),
            "merchant_code=SKU123",
        )


if __name__ == "__main__":
    unittest.main()
