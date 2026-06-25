#!/usr/bin/env python3
"""
Build S88PAY read-only API scan payloads for the ScanBot dashboard.

Credentials are read from environment variables so API keys are not saved
into repository files:

  S88PAY_API_KEY
  S88PAY_SECRET_KEY

The generated JSON can be pasted into the dashboard API endpoints textarea.
If --transaction-code is omitted, only balance and channel read-only endpoints
are generated.

Use --scope-merchant-code only with another merchant that you are authorized to
test. It generates read-only boundary checks where keys for --merchant-code are
sent to the second merchant's paths and should be rejected.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


def encrypt_token(payload: str, api_key: str, secret_key: str) -> str:
    key = hashlib.sha256(api_key.encode("utf-8")).digest()[:32]
    iv = hashlib.sha256(secret_key.encode("utf-8")).hexdigest()[:16].encode("utf-8")

    padder = PKCS7(128).padder()
    padded = padder.update(payload.encode("utf-8")) + padder.finalize()

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return quote(base64.b64encode(ciphertext).decode("ascii"), safe="")


def build_payload(
    merchant_code: str,
    currency_code: str,
    transaction_code: str | None,
    api_key: str,
    secret_key: str,
    include_negative_controls: bool = False,
    scope_merchant_code: str | None = None,
) -> list[dict]:
    balance_key = encrypt_token(
        f"merchant_code={merchant_code}",
        api_key,
        secret_key,
    )
    channel_key = encrypt_token(
        f"merchant_code={merchant_code}&currency_code={currency_code}",
        api_key,
        secret_key,
    )

    endpoints = [
        {
            "method": "GET",
            "path": f"/api/v1/balance/{merchant_code}?key={balance_key}",
            "name": "Balance encrypted read-only check",
        },
        {
            "method": "POST",
            "path": f"/api/v2/channel/{merchant_code}",
            "name": "Active channels encrypted read-only check",
            "body": {"key": channel_key},
        },
    ]

    if include_negative_controls:
        endpoints.extend(
            [
                {
                    "method": "GET",
                    "path": f"/api/v1/balance/{merchant_code}",
                    "name": "Balance missing key negative control",
                },
                {
                    "method": "GET",
                    "path": f"/api/v1/balance/{merchant_code}?key=scanbot_invalid_key",
                    "name": "Balance invalid key negative control",
                },
                {
                    "method": "GET",
                    "path": f"/api/v1/balance/{merchant_code}?key={channel_key}",
                    "name": "Balance with channel key swap negative control",
                },
                {
                    "method": "POST",
                    "path": f"/api/v2/channel/{merchant_code}",
                    "name": "Channel missing key negative control",
                    "body": {},
                },
                {
                    "method": "POST",
                    "path": f"/api/v2/channel/{merchant_code}",
                    "name": "Channel invalid key negative control",
                    "body": {"key": "scanbot_invalid_key"},
                },
                {
                    "method": "POST",
                    "path": f"/api/v2/channel/{merchant_code}",
                    "name": "Channel with balance key swap negative control",
                    "body": {"key": balance_key},
                },
            ]
        )

    if transaction_code:
        status_key = encrypt_token(
            f"merchant_api_key={api_key}&transaction_code={transaction_code}",
            api_key,
            secret_key,
        )
        endpoints.append(
            {
                "method": "POST",
                "path": f"/api/v1/{merchant_code}/transactions/status",
                "name": "Transaction status encrypted read-only check",
                "body": {"key": status_key},
            }
        )

    if scope_merchant_code and scope_merchant_code != merchant_code:
        endpoints.extend(
            [
                {
                    "method": "GET",
                    "path": f"/api/v1/balance/{scope_merchant_code}?key={balance_key}",
                    "name": "Balance wrong merchant negative control",
                },
                {
                    "method": "POST",
                    "path": f"/api/v2/channel/{scope_merchant_code}",
                    "name": "Channel wrong merchant negative control",
                    "body": {"key": channel_key},
                },
            ]
        )
        if transaction_code:
            endpoints.append(
                {
                    "method": "POST",
                    "path": f"/api/v1/{scope_merchant_code}/transactions/status",
                    "name": "Transaction status wrong merchant negative control",
                    "body": {"key": status_key},
                }
            )

    return endpoints


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate encrypted S88PAY read-only endpoint JSON for ScanBot."
    )
    parser.add_argument("--merchant-code", default="SKU20251119085710")
    parser.add_argument("--currency-code", default="INR")
    parser.add_argument(
        "--transaction-code",
        default="",
        help="Existing transaction code to query with the status endpoint. Omit to generate only balance and channel endpoints.",
    )
    parser.add_argument(
        "--include-negative-controls",
        action="store_true",
        help="Also generate missing-key, invalid-key, and key-swap read-only negative controls.",
    )
    parser.add_argument(
        "--scope-merchant-code",
        default="",
        help=(
            "Optional second authorized merchant code for read-only boundary checks. "
            "Keys are generated for --merchant-code and sent to this merchant's paths; "
            "the API should reject them."
        ),
    )
    args = parser.parse_args()

    api_key = os.getenv("S88PAY_API_KEY", "").strip()
    secret_key = os.getenv("S88PAY_SECRET_KEY", "").strip()
    if not api_key or not secret_key:
        print(
            "Set S88PAY_API_KEY and S88PAY_SECRET_KEY before running this helper.",
            file=sys.stderr,
        )
        return 2

    payload = build_payload(
        merchant_code=args.merchant_code.strip(),
        currency_code=args.currency_code.strip().upper(),
        transaction_code=args.transaction_code.strip() or None,
        api_key=api_key,
        secret_key=secret_key,
        include_negative_controls=args.include_negative_controls,
        scope_merchant_code=args.scope_merchant_code.strip() or None,
    )
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
