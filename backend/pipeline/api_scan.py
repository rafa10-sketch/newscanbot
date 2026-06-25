"""
PentestBot v2 - API Scan Stage
Lightweight authenticated API checks for application-layer review.
"""

from __future__ import annotations

import json
import hashlib
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

from pipeline.base_stage import BaseStage


class APIScanStage(BaseStage):
    """Run non-destructive API checks against supplied or common endpoints."""

    NAME = "APIScan"
    SAFE_MUTATION_METHODS = {"GET", "HEAD", "OPTIONS"}
    API_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    DEFAULT_ENDPOINTS = [
        {"method": "GET", "path": "/api"},
        {"method": "GET", "path": "/api/health"},
        {"method": "GET", "path": "/health"},
        {"method": "GET", "path": "/openapi.json"},
        {"method": "GET", "path": "/swagger.json"},
        {"method": "GET", "path": "/docs"},
    ]
    SENSITIVE_PATTERNS = (
        re.compile(r"\b(api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password)\b", re.I),
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    )
    ERROR_PATTERNS = (
        re.compile(r"traceback \(most recent call last\)", re.I),
        re.compile(r"\b(stack trace|sql syntax|database error|exception)\b", re.I),
        re.compile(r"\b(debug|development) mode\b", re.I),
    )
    SENSITIVE_PARAM_NAMES = {
        "amount",
        "balance",
        "callback_url",
        "channel",
        "currency",
        "invoice_id",
        "merchant",
        "merchant_id",
        "order",
        "order_id",
        "payment_id",
        "reference",
        "reference_id",
        "refund_id",
        "settlement_id",
        "status",
        "transaction_id",
        "trx_id",
        "user_id",
    }
    HIGH_RISK_PATH_KEYWORDS = (
        "balance",
        "callback",
        "disbursement",
        "export",
        "invoice",
        "merchant",
        "notification",
        "order",
        "payment",
        "payout",
        "refund",
        "report",
        "reversal",
        "settlement",
        "submit-depositor",
        "submit-refno",
        "submit-utr",
        "transaction",
        "transfer",
        "utr",
        "void",
        "webhook",
        "withdraw",
    )
    SIGNATURE_HEADER_HINTS = ("signature", "sign", "hmac", "timestamp", "nonce")
    FINANCIAL_RESPONSE_FIELDS = {
        "available_balance",
        "balance",
        "currency_code",
        "currency_name",
        "frozen_balance",
    }
    NEGATIVE_CONTROL_HINTS = (
        "negative control",
        "invalid key",
        "missing key",
        "key swap",
        "with balance key",
        "with channel key",
        "wrong merchant",
        "merchant-scope",
        "wrong key",
        "wrong-purpose",
    )
    KEY_SWAP_HINTS = (
        "key swap",
        "with balance key",
        "with channel key",
        "wrong-purpose",
    )

    async def run(self) -> None:
        self.clear_stage_error()
        endpoints = self._parse_endpoints(self.ctx.get("api_endpoints"))
        if not endpoints:
            endpoints = self.DEFAULT_ENDPOINTS
            self.ctx.setdefault("limitations", []).append(
                "API scan used default discovery endpoints because no endpoint list was supplied."
            )

        has_auth_context = bool(str(self.ctx.get("custom_headers") or "").strip() or str(self.ctx.get("custom_cookies") or "").strip())
        headers = self._parse_headers(self.ctx.get("custom_headers"))
        if self.ctx.get("custom_cookies"):
            headers["Cookie"] = str(self.ctx["custom_cookies"]).strip()

        findings: list[dict] = []
        observations: list[dict] = []
        validation_queue: list[dict] = []

        self.log.info(f"[APIScan] Testing {len(endpoints)} API endpoint(s)")
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0) as client:
            for endpoint in endpoints[:100]:
                method = str(endpoint.get("method", "GET")).upper()
                endpoint_name = str(endpoint.get("name") or "")
                url = self._build_url(str(endpoint.get("path") or endpoint.get("url") or "/"))
                body = endpoint.get("body")
                safe_to_mutate = method in self.SAFE_MUTATION_METHODS

                authed = await self._request(client, method, url, headers, body)
                observations.append(self._observation(method, url, authed, "authenticated", endpoint_name))
                self._inspect_response(findings, method, url, authed)
                self._inspect_negative_control_acceptance(findings, endpoint_name, method, url, authed)
                self._queue_endpoint_review(validation_queue, endpoint, method, url, authed)

                if safe_to_mutate:
                    cors_headers = dict(headers)
                    cors_headers["Origin"] = "https://scanbot.invalid"
                    cors = await self._request(client, method, url, cors_headers, body)
                    observations.append(self._observation(method, url, cors, "cors-probe", endpoint_name))
                    self._inspect_response(findings, method, url, cors, "cors-probe")
                    self._inspect_cors_origin(findings, method, url, cors)

                if has_auth_context:
                    anon = await self._request(client, method, url, {}, None)
                    observations.append(self._observation(method, url, anon, "anonymous", endpoint_name))
                    self._inspect_response(findings, method, url, anon, "anonymous")
                    self._inspect_authz(findings, method, url, authed, anon)
                    self._inspect_auth_context_anomaly(findings, method, url, authed, anon)

                    invalid_headers = self._invalid_auth_headers(headers)
                    invalid = await self._request(client, method, url, invalid_headers, None if method in {"GET", "HEAD"} else body)
                    observations.append(self._observation(method, url, invalid, "invalid-auth", endpoint_name))
                    self._inspect_response(findings, method, url, invalid, "invalid-auth")
                    self._inspect_invalid_auth(findings, method, url, authed, invalid)

                    if safe_to_mutate:
                        await self._inspect_parameter_tampering(client, findings, method, url, headers, authed)
                        await self._inspect_signature_bypass(client, findings, method, url, headers, authed)

                if not safe_to_mutate:
                    self._queue_manual_validation(
                        validation_queue,
                        "state-changing-api",
                        "State-changing API workflow needs Burp validation",
                        method,
                        url,
                        "The endpoint uses a state-changing HTTP method, so ScanBot avoided automatic parameter mutation.",
                        [
                            "Replay the exact request and confirm idempotency behavior.",
                            "Tamper amount/status/merchant/order fields if present.",
                            "Confirm authorization boundaries with a lower-privilege or different merchant account.",
                            "Verify signature and timestamp enforcement before and after body changes.",
                        ],
                        {"status": authed.get("status", 0)},
                    )

        self.ctx["api_observations"] = observations
        self.ctx["api_findings"] = findings
        self.ctx["api_findings_count"] = len(findings)
        self.ctx["api_validation_queue"] = validation_queue
        self.ctx.setdefault("raw_outputs", []).append({
            "tool_name": "api-scan",
            "stage_name": self.NAME,
            "status": "success",
            "stdout": json.dumps({
                "observations": observations,
                "findings": findings,
                "validation_queue": validation_queue,
            }, indent=2),
            "stderr": "",
            "duration": 0.0,
        })
        self.log.info(
            f"[APIScan] Completed with {len(findings)} finding(s) and "
            f"{len(validation_queue)} manual validation item(s)"
        )

    def _parse_endpoints(self, raw: Any) -> list[dict]:
        if not raw:
            return []
        if isinstance(raw, list):
            return [self._normalize_endpoint(item) for item in raw if self._normalize_endpoint(item)]

        text = str(raw).strip()
        if not text:
            return []

        if text.startswith("[") or text.startswith("{"):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict) and isinstance(parsed.get("paths"), dict):
                    return self._parse_openapi_endpoints(parsed)
                items = parsed if isinstance(parsed, list) else parsed.get("endpoints", [])
                return [self._normalize_endpoint(item) for item in items if self._normalize_endpoint(item)]
            except Exception as exc:
                self.add_tool_error(f"Invalid API endpoint JSON: {exc}")
                return []

        endpoints = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2 and parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                endpoints.append({"method": parts[0].upper(), "path": parts[1].strip()})
            else:
                endpoints.append({"method": "GET", "path": line})
        return endpoints

    def _parse_openapi_endpoints(self, spec: dict) -> list[dict]:
        endpoints: list[dict] = []
        for path, methods in (spec.get("paths") or {}).items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                normalized_method = str(method).upper()
                if normalized_method not in self.API_METHODS:
                    continue
                item: dict[str, Any] = {
                    "method": normalized_method,
                    "path": str(path),
                }
                if isinstance(operation, dict):
                    item["operation_id"] = operation.get("operationId", "")
                    item["summary"] = operation.get("summary", "")
                    item["body"] = self._example_body_from_operation(operation)
                endpoints.append(item)
        return [endpoint for endpoint in endpoints if endpoint.get("path")]

    def _example_body_from_operation(self, operation: dict) -> Any:
        content = ((operation.get("requestBody") or {}).get("content") or {})
        for media in ("application/json", "application/x-www-form-urlencoded", "multipart/form-data"):
            schema = content.get(media) or {}
            if "example" in schema:
                return schema.get("example")
            examples = schema.get("examples")
            if isinstance(examples, dict) and examples:
                first = next(iter(examples.values()))
                if isinstance(first, dict):
                    return first.get("value")
        return None

    def _normalize_endpoint(self, item: Any) -> dict:
        if isinstance(item, str):
            return {"method": "GET", "path": item}
        if not isinstance(item, dict):
            return {}
        path = item.get("path") or item.get("url")
        if not path:
            return {}
        return {
            "method": str(item.get("method", "GET")).upper(),
            "path": str(path),
            "body": item.get("body"),
            "name": item.get("name") or item.get("summary") or item.get("operation_id") or "",
            "requires_auth": item.get("requires_auth"),
            "requires_signature": item.get("requires_signature"),
        }

    def _parse_headers(self, raw: Any) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "PentestBot-APIScan/1.0",
        }
        for line in str(raw or "").splitlines():
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            if name.strip() and value.strip():
                headers[name.strip()] = value.strip()
        return headers

    def _build_url(self, path: str) -> str:
        parsed = urlparse(path)
        if parsed.scheme in {"http", "https"}:
            allowed_hosts = {self.target, str(self.ctx.get("active_origin_ip") or "")}
            if parsed.hostname in allowed_hosts:
                return path
            self.ctx.setdefault("limitations", []).append(
                f"API endpoint URL host '{parsed.hostname}' was outside the scan target and was normalized to the target host."
            )
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
        base = f"https://{self.target}"
        return urljoin(base.rstrip("/") + "/", path.lstrip("/"))

    async def _request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Any,
    ) -> dict:
        try:
            kwargs: dict[str, Any] = {"headers": headers}
            if body is not None and method != "HEAD":
                kwargs["json" if isinstance(body, (dict, list)) else "content"] = body
            response = await client.request(method, url, **kwargs)
            text = response.text[:20000]
            return {
                "ok": True,
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": text,
                "body_hash": hashlib.sha1(text.encode(errors="ignore")).hexdigest(),
                "length": len(response.content),
                "final_url": str(response.url),
            }
        except Exception as exc:
            return {"ok": False, "status": 0, "headers": {}, "body": str(exc), "body_hash": "", "length": 0}

    def _observation(self, method: str, url: str, result: dict, auth_context: str, endpoint_name: str = "") -> dict:
        return {
            "method": method,
            "url": url,
            "name": endpoint_name,
            "auth_context": auth_context,
            "status": result.get("status", 0),
            "length": result.get("length", 0),
            "body_hash": result.get("body_hash", ""),
            "body_excerpt": self._body_excerpt(result),
            "ok": result.get("ok", False),
        }

    def _inspect_response(
        self,
        findings: list[dict],
        method: str,
        url: str,
        result: dict,
        auth_context: str = "authenticated",
    ) -> None:
        status = int(result.get("status", 0) or 0)
        body = str(result.get("body", ""))
        headers = {str(k).lower(): str(v) for k, v in result.get("headers", {}).items()}

        if status >= 500:
            findings.append(self._finding(
                "api-server-error",
                "API endpoint returns server error",
                "medium",
                url,
                f"{method} {url} returned HTTP {status} in {auth_context} context. Server errors can expose unstable code paths and should be reviewed.",
                {"status": status, "auth_context": auth_context, "body_excerpt": self._body_excerpt(result)},
            ))

        if any(pattern.search(body) for pattern in self.ERROR_PATTERNS):
            findings.append(self._finding(
                "api-verbose-error",
                "Verbose API error disclosure",
                "medium",
                url,
                f"The API response in {auth_context} context appears to expose stack traces, database errors, or debug details.",
                {"status": status, "auth_context": auth_context, "body_excerpt": self._body_excerpt(result)},
            ))

        if status < 400 and any(pattern.search(body) for pattern in self.SENSITIVE_PATTERNS):
            findings.append(self._finding(
                "api-sensitive-data",
                "Possible sensitive data exposure in API response",
                "high",
                url,
                f"The API response in {auth_context} context contains patterns that look like tokens, secrets, passwords, emails, or payment card data.",
                {"status": status, "auth_context": auth_context},
            ))

        allow_origin = headers.get("access-control-allow-origin", "")
        allow_creds = headers.get("access-control-allow-credentials", "")
        if allow_origin == "*" and allow_creds.lower() == "true":
            findings.append(self._finding(
                "api-cors-wildcard-credentials",
                "Permissive CORS with credentials",
                "high",
                url,
                "The API allows wildcard origins while also allowing credentials, which can expose authenticated API responses cross-origin.",
                {"access_control_allow_origin": allow_origin, "auth_context": auth_context},
            ))

    def _inspect_cors_origin(self, findings: list[dict], method: str, url: str, result: dict) -> None:
        headers = {str(k).lower(): str(v) for k, v in result.get("headers", {}).items()}
        allow_origin = headers.get("access-control-allow-origin", "")
        allow_creds = headers.get("access-control-allow-credentials", "")
        if allow_origin != "https://scanbot.invalid":
            return

        severity = "high" if allow_creds.lower() == "true" else "medium"
        findings.append(self._finding(
            "api-cors-origin-reflection",
            "API reflects untrusted CORS origin",
            severity,
            url,
            f"{method} {url} reflected a synthetic Origin header. Validate whether browser clients can read sensitive API responses cross-origin.",
            {
                "access_control_allow_origin": allow_origin,
                "access_control_allow_credentials": allow_creds,
            },
        ))

    def _inspect_authz(self, findings: list[dict], method: str, url: str, authed: dict, anon: dict) -> None:
        authed_status = int(authed.get("status", 0) or 0)
        anon_status = int(anon.get("status", 0) or 0)
        if 200 <= authed_status < 300 and 200 <= anon_status < 300:
            authed_len = max(int(authed.get("length", 0) or 0), 1)
            anon_len = int(anon.get("length", 0) or 0)
            similarity = min(anon_len, authed_len) / max(anon_len, authed_len, 1)
            severity = "medium" if similarity > 0.7 else "low"
            findings.append(self._finding(
                "api-public-authenticated-resource",
                "Authenticated API endpoint also accessible anonymously",
                severity,
                url,
                f"{method} {url} returned success both with and without authentication. Validate whether this endpoint is intended to be public.",
                {"authenticated_status": authed_status, "anonymous_status": anon_status},
            ))

    def _inspect_auth_context_anomaly(
        self,
        findings: list[dict],
        method: str,
        url: str,
        authed: dict,
        anon: dict,
    ) -> None:
        authed_status = int(authed.get("status", 0) or 0)
        anon_status = int(anon.get("status", 0) or 0)
        if not (200 <= anon_status < 300 and authed_status in {401, 403}):
            return

        severity = "medium" if self._is_high_risk_url(url) else "low"
        findings.append(self._finding(
            "api-auth-context-inversion",
            "API returns success anonymously but rejects provided auth context",
            severity,
            url,
            (
                f"{method} {url} returned HTTP {anon_status} anonymously but HTTP {authed_status} "
                "when the configured authentication header was sent. Validate whether the supplied auth header is wrong, "
                "or whether the endpoint unintentionally processes unauthenticated requests."
            ),
            {
                "authenticated_status": authed_status,
                "anonymous_status": anon_status,
                "anonymous_body_excerpt": self._body_excerpt(anon),
            },
        ))

    def _inspect_invalid_auth(self, findings: list[dict], method: str, url: str, authed: dict, invalid: dict) -> None:
        authed_status = int(authed.get("status", 0) or 0)
        invalid_status = int(invalid.get("status", 0) or 0)
        if not (200 <= authed_status < 300 and 200 <= invalid_status < 300):
            return

        similarity = self._response_similarity(authed, invalid)
        if similarity < 0.55:
            return

        severity = "high" if self._is_high_risk_url(url) else "medium"
        findings.append(self._finding(
            "api-invalid-auth-accepted",
            "API endpoint may accept invalid authentication",
            severity,
            url,
            f"{method} {url} returned a successful and similar response when authentication material was replaced with invalid values.",
            {
                "authenticated_status": authed_status,
                "invalid_auth_status": invalid_status,
                "response_similarity": round(similarity, 3),
            },
        ))

    def _inspect_negative_control_acceptance(
        self,
        findings: list[dict],
        endpoint_name: str,
        method: str,
        url: str,
        result: dict,
    ) -> None:
        if not self._looks_like_negative_control(endpoint_name):
            return

        status = int(result.get("status", 0) or 0)
        if not (200 <= status < 300):
            return

        json_fields = self._json_object_fields(result)
        has_financial_fields = bool(json_fields & self.FINANCIAL_RESPONSE_FIELDS)
        is_key_swap = self._looks_like_key_swap(endpoint_name)

        title = "API negative control returned a successful response"
        if is_key_swap:
            title = "API endpoint accepted a key intended for another endpoint"

        severity = "medium"
        if has_financial_fields and self._is_high_risk_url(url):
            severity = "high" if not is_key_swap else "medium"

        findings.append(self._finding(
            "api-negative-control-accepted",
            title,
            severity,
            url,
            (
                f"{method} {url} returned HTTP {status} for the negative-control test "
                f"'{endpoint_name}'. Negative controls are expected to fail; a successful "
                "response indicates the endpoint may accept missing, invalid, swapped, or "
                "wrong-purpose authentication material."
            ),
            {
                "endpoint_name": endpoint_name,
                "status": status,
                "json_fields": sorted(json_fields),
                "has_financial_fields": has_financial_fields,
                "is_key_swap": is_key_swap,
                "body_excerpt": self._body_excerpt(result),
            },
        ))

    def _looks_like_negative_control(self, endpoint_name: str) -> bool:
        lowered_name = str(endpoint_name or "").lower()
        return any(hint in lowered_name for hint in self.NEGATIVE_CONTROL_HINTS)

    def _looks_like_key_swap(self, endpoint_name: str) -> bool:
        lowered_name = str(endpoint_name or "").lower()
        return any(hint in lowered_name for hint in self.KEY_SWAP_HINTS)

    async def _inspect_parameter_tampering(
        self,
        client: httpx.AsyncClient,
        findings: list[dict],
        method: str,
        url: str,
        headers: dict[str, str],
        original: dict,
    ) -> None:
        if not (200 <= int(original.get("status", 0) or 0) < 300):
            return
        for mutation in self._build_tampered_urls(url):
            result = await self._request(client, method, mutation["url"], headers, None)
            status = int(result.get("status", 0) or 0)
            if not (200 <= status < 300):
                continue

            severity = "high" if mutation["risk"] == "high" or self._is_high_risk_url(url) else "medium"
            findings.append(self._finding(
                "api-idor-candidate",
                "Possible API authorization gap from parameter tampering",
                severity,
                mutation["url"],
                (
                    f"Changing {mutation['label']} in an authenticated {method} request still returned "
                    "a successful response. Manual validation is required to confirm object ownership and tenant scope."
                ),
                {
                    "original_url": url,
                    "tampered_url": mutation["url"],
                    "status": status,
                    "mutation": mutation,
                    "response_similarity": round(self._response_similarity(original, result), 3),
                },
            ))

    async def _inspect_signature_bypass(
        self,
        client: httpx.AsyncClient,
        findings: list[dict],
        method: str,
        url: str,
        headers: dict[str, str],
        original: dict,
    ) -> None:
        signature_headers = self._signature_header_names(headers)
        if not signature_headers or not (200 <= int(original.get("status", 0) or 0) < 300):
            return

        variants = {
            "missing-signature": {
                name: value
                for name, value in headers.items()
                if name not in signature_headers
            },
            "invalid-signature": {
                name: ("scanbot-invalid-signature" if name in signature_headers else value)
                for name, value in headers.items()
            },
        }
        for variant, variant_headers in variants.items():
            result = await self._request(client, method, url, variant_headers, None)
            status = int(result.get("status", 0) or 0)
            if not (200 <= status < 300):
                continue
            similarity = self._response_similarity(original, result)
            if similarity < 0.55:
                continue
            findings.append(self._finding(
                "api-signature-bypass-candidate",
                "API request signature may not be enforced",
                "high" if self._is_high_risk_url(url) else "medium",
                url,
                f"{method} {url} returned a successful and similar response with {variant.replace('-', ' ')}.",
                {
                    "variant": variant,
                    "signature_headers": signature_headers,
                    "status": status,
                    "response_similarity": round(similarity, 3),
                },
            ))

    def _invalid_auth_headers(self, headers: dict[str, str]) -> dict[str, str]:
        invalid = dict(headers)
        changed = False
        for name in list(invalid.keys()):
            lowered = name.lower()
            if lowered == "authorization":
                value = invalid[name]
                invalid[name] = "Bearer scanbot-invalid-token" if value.lower().startswith("bearer ") else "scanbot-invalid-auth"
                changed = True
            elif lowered == "cookie":
                invalid[name] = self._invalid_cookie_header(invalid[name])
                changed = True
            elif any(token in lowered for token in ("api-key", "apikey", "access-token", "auth-token", "token")):
                invalid[name] = "scanbot-invalid-token"
                changed = True

        if not changed:
            invalid["Authorization"] = "Bearer scanbot-invalid-token"
        return invalid

    def _invalid_cookie_header(self, cookie_header: str) -> str:
        cookies = []
        for cookie in cookie_header.split(";"):
            if "=" not in cookie:
                continue
            name, _ = cookie.split("=", 1)
            if name.strip():
                cookies.append(f"{name.strip()}=scanbot_invalid")
        return "; ".join(cookies) or "scanbot_invalid=1"

    def _signature_header_names(self, headers: dict[str, str]) -> list[str]:
        return [
            name
            for name in headers
            if any(hint in name.lower() for hint in self.SIGNATURE_HEADER_HINTS)
            and name.lower() not in {"authorization"}
        ]

    def _build_tampered_urls(self, url: str) -> list[dict]:
        mutations: list[dict] = []

        match = re.search(r"(?<![A-Za-z0-9])(\d{1,10})(?!\d)", url)
        if match:
            current = int(match.group(1))
            mutations.append({
                "url": url[:match.start()] + str(current + 1) + url[match.end():],
                "label": "numeric path/query identifier",
                "risk": "high",
            })

        uuid_match = re.search(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
            url,
            flags=re.I,
        )
        if uuid_match:
            value = uuid_match.group(0)
            replacement = value[:-1] + ("0" if value[-1].lower() != "0" else "1")
            mutations.append({
                "url": url[:uuid_match.start()] + replacement + url[uuid_match.end():],
                "label": "UUID identifier",
                "risk": "high",
            })

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        for index, (name, value) in enumerate(query_pairs):
            normalized = name.lower()
            if normalized not in self.SENSITIVE_PARAM_NAMES and not normalized.endswith("_id"):
                continue
            tampered_pairs = list(query_pairs)
            tampered_pairs[index] = (name, self._tampered_value(name, value))
            tampered_url = urlunparse(parsed._replace(query=urlencode(tampered_pairs, doseq=True)))
            mutations.append({
                "url": tampered_url,
                "label": f"query parameter '{name}'",
                "risk": "high" if normalized.endswith("_id") or "merchant" in normalized else "medium",
            })

        deduped: list[dict] = []
        seen: set[str] = set()
        for mutation in mutations:
            if mutation["url"] == url or mutation["url"] in seen:
                continue
            seen.add(mutation["url"])
            deduped.append(mutation)
        return deduped[:5]

    def _tampered_value(self, name: str, value: str) -> str:
        lowered = name.lower()
        if re.fullmatch(r"\d+", value or ""):
            return str(int(value) + 1)
        if "amount" in lowered or "balance" in lowered:
            return "1"
        if "status" in lowered:
            return "SUCCESS" if value.upper() != "SUCCESS" else "FAILED"
        if "callback" in lowered or "url" in lowered:
            return "https://scanbot.invalid/callback"
        if value:
            return f"{value}_scanbot"
        return "scanbot"

    def _queue_endpoint_review(self, queue: list[dict], endpoint: dict, method: str, url: str, result: dict) -> None:
        if not self._is_high_risk_url(url) and not self._is_high_risk_text(str(endpoint.get("name", ""))):
            return

        checks = [
            "Validate tenant or merchant scoping with another account.",
            "Check whether sensitive identifiers can be swapped without authorization failure.",
        ]
        if any(token in url.lower() for token in ("callback", "webhook", "notification")):
            checks.extend([
                "Replay a previous callback and verify timestamp or nonce rejection.",
                "Change callback amount/status/order_id and confirm signature validation fails.",
            ])
        if any(token in url.lower() for token in ("payment", "transaction", "order", "invoice", "refund", "settlement")):
            checks.extend([
                "Replay the payment or transaction request and verify idempotency.",
                "Tamper amount/status/channel/currency after signature generation.",
            ])
        self._queue_manual_validation(
            queue,
            "high-risk-api-workflow",
            "High-risk API workflow queued for Burp validation",
            method,
            url,
            "The endpoint name/path matches payment, merchant, settlement, callback, report, or transaction workflow keywords.",
            checks,
            {"status": result.get("status", 0), "endpoint_name": endpoint.get("name", "")},
        )

    def _queue_manual_validation(
        self,
        queue: list[dict],
        kind: str,
        title: str,
        method: str,
        url: str,
        reason: str,
        suggested_checks: list[str],
        evidence: dict,
    ) -> None:
        key = f"{kind}|{method}|{url}"
        if any(item.get("key") == key for item in queue):
            return
        queue.append({
            "key": key,
            "kind": kind,
            "title": title,
            "method": method,
            "url": url,
            "reason": reason,
            "suggested_checks": suggested_checks,
            "evidence": evidence,
        })

    def _is_high_risk_url(self, url: str) -> bool:
        return self._is_high_risk_text(urlparse(url).path)

    def _is_high_risk_text(self, text: str) -> bool:
        lowered = text.lower()
        return any(keyword in lowered for keyword in self.HIGH_RISK_PATH_KEYWORDS)

    @staticmethod
    def _response_similarity(left: dict, right: dict) -> float:
        left_len = max(int(left.get("length", 0) or 0), 1)
        right_len = max(int(right.get("length", 0) or 0), 1)
        length_similarity = min(left_len, right_len) / max(left_len, right_len, 1)
        if left.get("body_hash") and left.get("body_hash") == right.get("body_hash"):
            return 1.0
        return length_similarity

    @staticmethod
    def _body_excerpt(result: dict, limit: int = 500) -> str:
        text = str(result.get("body", "") or "")
        compact = re.sub(r"\s+", " ", text).strip()
        return compact[:limit]

    @staticmethod
    def _json_object_fields(result: dict) -> set[str]:
        try:
            parsed = json.loads(str(result.get("body", "") or ""))
        except Exception:
            return set()
        if not isinstance(parsed, dict):
            return set()
        return {str(key) for key in parsed.keys()}

    def _finding(
        self,
        kind: str,
        title: str,
        severity: str,
        affected: str,
        description: str,
        extra: dict,
    ) -> dict:
        return {
            "id": f"{kind}-{hashlib.sha1(f'{kind}|{affected}'.encode()).hexdigest()[:10]}",
            "title": title,
            "severity": severity,
            "affected": [affected],
            "description": description,
            "source": "api-scan",
            "extra": {"kind": kind, **extra},
        }
