#!/usr/bin/env python3
"""
Generate a Versori JWT and optionally call a Versori API endpoint.

This script is designed to be CI/CD friendly:
- secrets come from environment variables or a private key file
- the JWT is signed with your organisation PKCS #8 private key
- the API path/method can be supplied later without changing the code

Required configuration:
- VERSORI_SIGNING_KEY_ID
- VERSORI_EXTERNAL_USER_ID
- one of:
  - VERSORI_PRIVATE_KEY
  - VERSORI_PRIVATE_KEY_FILE

Optional configuration:
- VERSORI_ORG_ID
- VERSORI_API_BASE_URL           (default: https://platform.versori.com)
- VERSORI_API_PATH               (for example: /api/v2/o/{org_id}/users/{external_user_id})
- VERSORI_API_METHOD             (default: GET)
- VERSORI_API_BODY               (JSON string for POST/PUT/PATCH requests)
- VERSORI_TOKEN_LIFETIME_SECONDS (default: 3600)

Examples:
  python deploy.py --dry-run
  python deploy.py --api-path "/api/v2/o/{org_id}/users/{external_user_id}"
  python deploy.py --api-path "/api/v2/o/{org_id}/users/{external_user_id}" --method GET
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

try:
    import jwt
except ImportError as exc:
    raise SystemExit(
        "PyJWT is required. Install it with: pip install PyJWT[crypto]"
    ) from exc


DEFAULT_BASE_URL = "https://platform.versori.com"
#DEFAULT_BASE_URL = "http://localhost:8901"


def read_private_key() -> str:
    """Load the PKCS #8 PEM private key from env or file."""
    inline_key = os.getenv("VERSORI_PRIVATE_KEY")
    if inline_key:
        return inline_key

    key_file = os.getenv("VERSORI_PRIVATE_KEY_FILE")
    if key_file:
        with open(key_file, "r", encoding="utf-8") as handle:
            return handle.read()

    raise ValueError(
        "Set VERSORI_PRIVATE_KEY or VERSORI_PRIVATE_KEY_FILE with your PKCS #8 PEM key."
    )


def read_required_value(cli_value: str | None, env_name: str) -> str:
    value = cli_value or os.getenv(env_name)
    if not value:
        raise ValueError(f"Missing required value: {env_name}")
    return value


def sign_versori_jwt(
    private_key: str,
    signing_key_id: str,
    external_user_id: str,
    lifetime_seconds: int = 3600,
) -> str:
    """
    Create a JWT for a Versori end user.

    Versori expects:
    - iss = https://versori.com/sk/<signingKeyId>
    - sub = <external user id>
    - iat = current unix time
    - exp = iat + short lifetime
    """
    issued_at = int(time.time())
    payload = {
        "iss": f"https://versori.com/sk/{signing_key_id}",
        "sub": external_user_id,
        "iat": issued_at,
        "exp": issued_at + lifetime_seconds,
    }

    token = jwt.encode(payload, private_key, algorithm="RS256")
    return token if isinstance(token, str) else token.decode("utf-8")


def render_api_path(template: str, org_id: str | None, external_user_id: str) -> str:
    replacements = {
        "org_id": org_id or "",
        "external_user_id": external_user_id,
    }

    try:
        return template.format(**replacements)
    except KeyError as exc:
        raise ValueError(
            f"Unknown placeholder in VERSORI_API_PATH or --api-path: {exc}"
        ) from exc


def build_url(base_url: str, api_path: str) -> str:
    if api_path.startswith("http://") or api_path.startswith("https://"):
        return api_path

    normalized_base = base_url.rstrip("/") + "/"
    normalized_path = api_path.lstrip("/")
    return urllib.parse.urljoin(normalized_base, normalized_path)


def parse_json_body(body_text: str | None) -> bytes | None:
    if not body_text:
        return None

    parsed = json.loads(body_text)
    return json.dumps(parsed).encode("utf-8")


def call_versori_api(
    method: str,
    url: str,
    token: str,
    body: bytes | None = None,
) -> tuple[int, str]:
    headers = {
        "Authorization": f"JWT {token}",
        "Accept": "application/json",
    }

    if body is not None:
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url=url,
        data=body,
        headers=headers,
        method=method.upper(),
    )

    try:
        with urllib.request.urlopen(request) as response:
            response_body = response.read().decode("utf-8")
            return response.status, response_body
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        return exc.code, error_body


def build_curl_command(
    method: str,
    url: str,
    token: str,
    body: bytes | None = None,
) -> str:
    """Build a PowerShell-friendly curl command for the API request."""

    def quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    command_parts = [
        "curl",
        "-X",
        quote(method.upper()),
        quote(url),
        "-H",
        quote("Accept: application/json"),
        "-H",
        quote(f"Authorization: JWT {token}"),
    ]

    if body is not None:
        body_text = body.decode("utf-8")
        command_parts.extend(
            [
                "-H",
                quote("Content-Type: application/json"),
                "--data",
                quote(body_text),
            ]
        )

    return " ".join(command_parts)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a Versori JWT and optionally call a Versori API."
    )
    parser.add_argument(
        "--signing-key-id",
        help="Versori signing key id. Falls back to VERSORI_SIGNING_KEY_ID.",
    )
    parser.add_argument(
        "--external-user-id",
        help="External user id to place in the JWT sub claim. Falls back to VERSORI_EXTERNAL_USER_ID.",
    )
    parser.add_argument(
        "--org-id",
        help="Versori organisation id. Falls back to VERSORI_ORG_ID.",
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("VERSORI_API_BASE_URL", DEFAULT_BASE_URL),
        help="Versori base URL. Defaults to VERSORI_API_BASE_URL or the platform URL.",
    )
    parser.add_argument(
        "--api-path",
        help=(
            "API path or full URL. Supports {org_id} and {external_user_id} placeholders. "
            "Falls back to VERSORI_API_PATH."
        ),
    )
    parser.add_argument(
        "--method",
        default=os.getenv("VERSORI_API_METHOD", "GET"),
        help="HTTP method to use for the API call. Defaults to GET.",
    )
    parser.add_argument(
        "--body",
        help="JSON request body. Falls back to VERSORI_API_BODY.",
    )
    parser.add_argument(
        "--lifetime-seconds",
        type=int,
        default=int(os.getenv("VERSORI_TOKEN_LIFETIME_SECONDS", "3600")),
        help="JWT lifetime in seconds. Defaults to 3600.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate the token and print request details without calling the API.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        private_key = read_private_key()
        signing_key_id = read_required_value(
            args.signing_key_id, "VERSORI_SIGNING_KEY_ID"
        )
        external_user_id = read_required_value(
            args.external_user_id, "VERSORI_EXTERNAL_USER_ID"
        )
        org_id = args.org_id or os.getenv("VERSORI_ORG_ID")
        api_path = args.api_path or os.getenv("VERSORI_API_PATH")
        body_text = args.body or os.getenv("VERSORI_API_BODY")

        token = sign_versori_jwt(
            private_key=private_key,
            signing_key_id=signing_key_id,
            external_user_id=external_user_id,
            lifetime_seconds=args.lifetime_seconds,
        )

        print("Versori JWT generated successfully.")
        print(f"issuer: https://versori.com/sk/{signing_key_id}")
        print(f"subject: {external_user_id}")
        print(f"token_lifetime_seconds: {args.lifetime_seconds}")
        print(f"jwt_token: {token}")

        if not api_path:
            print(
                "No API path configured yet. Set VERSORI_API_PATH or pass --api-path when the endpoint is decided."
            )
            return 0

        resolved_path = render_api_path(api_path, org_id, external_user_id)
        url = build_url(args.base_url, resolved_path)
        body = parse_json_body(body_text)
        curl_command = build_curl_command(
            method=args.method,
            url=url,
            token=token,
            body=body,
        )

        print(f"method: {args.method.upper()}")
        print(f"url: {url}")
        print(f"curl: {curl_command}")

        if args.dry_run:
            print("Dry run enabled. Skipping API call.")
            return 0

        status_code, response_text = call_versori_api(
            method=args.method,
            url=url,
            token=token,
            body=body,
        )

        print(f"status_code: {status_code}")
        print("response:")
        print(response_text)
        return 0 if 200 <= status_code < 300 else 1

    except json.JSONDecodeError as exc:
        print(f"Invalid JSON body: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
