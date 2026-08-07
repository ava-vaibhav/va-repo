#!/usr/bin/env python3
"""
Generate a Versori JWT and call pre-deployment Versori API endpoints.

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
- DEPLOY_BRANCH / GITHUB_REF_NAME (branch being deployed)
- VERSORI_ORG_ID
- PROJECT_ID / VERSORI_PROJECT_ID
- ENVIRONMENT_ID / VERSORI_ENVIRONMENT_ID
- VERSORI_API_BASE_URL           (default: https://platform.versori.com)
- VERSORI_API_PATH               (for example: /api/v2/o/{org_id}/users/{external_user_id})
- VERSORI_API_METHOD             (default: GET)
- VERSORI_API_BODY               (JSON string for POST/PUT/PATCH requests)
- CCS_CONFIG_API_BASE_URL        (default: hosted CCS config API base URL)
- CCS_CONFIG_API_URL             (optional full endpoint override)
- APP_ID / CCS_APP_ID
- APP_VERSION / CCS_APP_VERSION
- SCHEMA_TYPE / CCS_SCHEMA_TYPE
- LAYOUT_TYPE / CCS_LAYOUT_TYPE
- CONFIG_NAME / CCS_CONFIG_NAME
- CONFIG_SCHEMA / CCS_CONFIG_SCHEMA (JSON string)
- CONFIG_LAYOUT / CCS_CONFIG_LAYOUT (JSON string)
- VERSORI_TOKEN_LIFETIME_SECONDS (default: 3600)

Examples:
  python deploy.py --branch cicd-test --dry-run
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
DEFAULT_CCS_CONFIG_API_BASE_URL = (
    "https://tmc2tfdf-71d90861-staging.gcp-eu4-1-staging.versori.run"
)
CCS_CONFIG_API_PATH = "/ccs-upsert-application-config"


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


def read_first_env(*env_names: str) -> str | None:
    for env_name in env_names:
        value = os.getenv(env_name)
        if value:
            return value
    return None


def read_branch(cli_value: str | None) -> str:
    value = (
        cli_value
        or os.getenv("DEPLOY_BRANCH")
        or os.getenv("GITHUB_REF_NAME")
        or os.getenv("GITHUB_HEAD_REF")
    )
    if not value:
        raise ValueError(
            "Missing branch. Pass --branch or set DEPLOY_BRANCH / GITHUB_REF_NAME."
        )
    return value


def mask_token(token: str) -> str:
    if len(token) <= 12:
        return "***"
    return f"{token[:8]}...{token[-4:]}"


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


def build_url_with_query(url: str, query_params: dict[str, str]) -> str:
    parsed = urllib.parse.urlsplit(url)
    existing_query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = urllib.parse.urlencode(existing_query + list(query_params.items()))
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment)
    )


def parse_json_body(body_text: str | None) -> bytes | None:
    if not body_text:
        return None

    parsed = json.loads(body_text)
    return json.dumps(parsed).encode("utf-8")


def parse_json_env_value(value_text: str, value_name: str) -> Any:
    try:
        return json.loads(value_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{value_name} must contain valid JSON: {exc}") from exc


def build_ccs_config_api_url() -> str:
    full_url = read_first_env("CCS_CONFIG_API_URL")
    if full_url:
        return full_url

    base_url = (
        read_first_env("CCS_CONFIG_API_BASE_URL") or DEFAULT_CCS_CONFIG_API_BASE_URL
    )
    return build_url(base_url, CCS_CONFIG_API_PATH)


def quote_url_path_value(value: str) -> str:
    return urllib.parse.quote(value, safe="")


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


def build_ccs_config_request() -> tuple[str, bytes]:
    api_url = build_ccs_config_api_url()
    app_id = read_first_env("APP_ID", "CCS_APP_ID")
    app_version = read_first_env("APP_VERSION", "CCS_APP_VERSION")
    schema_type = read_first_env("SCHEMA_TYPE", "CCS_SCHEMA_TYPE")
    layout_type = read_first_env("LAYOUT_TYPE", "CCS_LAYOUT_TYPE")
    config_name = read_first_env("CONFIG_NAME", "CCS_CONFIG_NAME")
    config_schema = read_first_env("CONFIG_SCHEMA", "CCS_CONFIG_SCHEMA")
    config_layout = read_first_env("CONFIG_LAYOUT", "CCS_CONFIG_LAYOUT")

    required_values = {
        "APP_ID or CCS_APP_ID": app_id,
        "APP_VERSION or CCS_APP_VERSION": app_version,
        "SCHEMA_TYPE or CCS_SCHEMA_TYPE": schema_type,
        "LAYOUT_TYPE or CCS_LAYOUT_TYPE": layout_type,
        "CONFIG_NAME or CCS_CONFIG_NAME": config_name,
        "CONFIG_SCHEMA or CCS_CONFIG_SCHEMA": config_schema,
        "CONFIG_LAYOUT or CCS_CONFIG_LAYOUT": config_layout,
    }
    missing = [name for name, value in required_values.items() if not value]
    if missing:
        raise ValueError("Missing repository variables: " + ", ".join(missing))

    request_url = build_url_with_query(
        api_url,
        {
            "APP_ID": app_id,
            "App_Version": app_version,
            "Schema_Type": schema_type,
            "Layout_Type": layout_type,
        },
    )
    request_body = {
        "Name": config_name,
        "schema": parse_json_env_value(config_schema, "CONFIG_SCHEMA"),
        "layout": parse_json_env_value(config_layout, "CONFIG_LAYOUT"),
    }
    return request_url, json.dumps(request_body).encode("utf-8")


def build_ccs_environment_request() -> tuple[str, bytes]:
    base_url = read_first_env("VERSORI_API_BASE_URL") or DEFAULT_BASE_URL
    org_id = read_first_env("VERSORI_ORG_ID", "ORGANISATION_ID", "ORG_ID")
    project_id = read_first_env("PROJECT_ID", "VERSORI_PROJECT_ID")
    environment_id = read_first_env("ENVIRONMENT_ID", "VERSORI_ENVIRONMENT_ID")
    app_id = read_first_env("APP_ID", "CCS_APP_ID")
    app_version = read_first_env("APP_VERSION", "CCS_APP_VERSION")
    schema_type = read_first_env("SCHEMA_TYPE", "CCS_SCHEMA_TYPE")
    layout_type = read_first_env("LAYOUT_TYPE", "CCS_LAYOUT_TYPE")

    required_values = {
        "VERSORI_ORG_ID or ORGANISATION_ID or ORG_ID": org_id,
        "PROJECT_ID or VERSORI_PROJECT_ID": project_id,
        "ENVIRONMENT_ID or VERSORI_ENVIRONMENT_ID": environment_id,
        "APP_ID or CCS_APP_ID": app_id,
        "APP_VERSION or CCS_APP_VERSION": app_version,
        "SCHEMA_TYPE or CCS_SCHEMA_TYPE": schema_type,
        "LAYOUT_TYPE or CCS_LAYOUT_TYPE": layout_type,
    }
    missing = [name for name, value in required_values.items() if not value]
    if missing:
        raise ValueError("Missing repository variables: " + ", ".join(missing))

    path = (
        f"/o/{quote_url_path_value(org_id)}"
        f"/projects/{quote_url_path_value(project_id)}"
        f"/environments/{quote_url_path_value(environment_id)}"
        "/ccs"
    )
    request_body = {
        "appId": app_id,
        "appVersion": app_version,
        "schemaType": schema_type,
        "layoutType": layout_type,
    }
    return build_url(base_url, path), json.dumps(request_body).encode("utf-8")


def run_ccs_config_upsert(token: str, *, dry_run: bool) -> bool:
    print("=== Pre-deployment CCS application config upsert ===")

    try:
        url, body = build_ccs_config_request()
    except Exception as exc:  # noqa: BLE001
        print(f"Skipping CCS config API call: {exc}")
        print("Deployment will continue.")
        return False

    print("method: POST")
    print(f"url: {url}")

    if dry_run:
        print("Dry run enabled. Skipping CCS config API call.")
        return False

    try:
        status_code, response_text = call_versori_api(
            method="POST",
            url=url,
            token=token,
            body=body,
        )
        print(f"status_code: {status_code}")
        print("response:")
        print(response_text)
        if not 200 <= status_code < 300:
            print("CCS config API call failed; deployment will continue.")
            return False
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"CCS config API call error: {exc}")
        print("Deployment will continue.")
        return False


def run_ccs_environment_update(token: str, *, dry_run: bool) -> None:
    print("=== CCS environment update ===")

    try:
        url, body = build_ccs_environment_request()
    except Exception as exc:  # noqa: BLE001
        print(f"Skipping CCS environment update API call: {exc}")
        print("Deployment will continue.")
        return

    print("method: PUT")
    print(f"url: {url}")

    if dry_run:
        print("Dry run enabled. Skipping CCS environment update API call.")
        return

    try:
        status_code, response_text = call_versori_api(
            method="PUT",
            url=url,
            token=token,
            body=body,
        )
        print(f"status_code: {status_code}")
        print("response:")
        print(response_text)
        if not 200 <= status_code < 300:
            print("CCS environment update API call failed; deployment will continue.")
    except Exception as exc:  # noqa: BLE001
        print(f"CCS environment update API call error: {exc}")
        print("Deployment will continue.")


def run_optional_api_call(
    *,
    api_path: str,
    org_id: str | None,
    external_user_id: str,
    base_url: str,
    method: str,
    token: str,
    body_text: str | None,
    dry_run: bool,
    in_ci: bool,
) -> None:
    print("=== Optional Versori API call ===")

    try:
        resolved_path = render_api_path(api_path, org_id, external_user_id)
        url = build_url(base_url, resolved_path)
        body = parse_json_body(body_text)
        curl_command = build_curl_command(
            method=method,
            url=url,
            token=token,
            body=body,
        )

        print(f"method: {method.upper()}")
        print(f"url: {url}")
        if in_ci:
            print("curl: (redacted in CI logs)")
        else:
            print(f"curl: {curl_command}")

        if dry_run:
            print("Dry run enabled. Skipping API call.")
            return

        status_code, response_text = call_versori_api(
            method=method,
            url=url,
            token=token,
            body=body,
        )

        print(f"status_code: {status_code}")
        print("response:")
        print(response_text)
        if not 200 <= status_code < 300:
            print("API call failed; deployment will continue.")
    except Exception as exc:  # noqa: BLE001
        print(f"API call error: {exc}")
        print("Deployment will continue.")


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
        "--branch",
        help="Git branch being deployed. Falls back to DEPLOY_BRANCH or GITHUB_REF_NAME.",
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
        branch = read_branch(args.branch)
        in_ci = os.getenv("GITHUB_ACTIONS") == "true"

        print("=== Deployment context ===")
        print(f"branch: {branch}")
        print(f"timestamp_utc: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
        print(f"ci_run: {in_ci}")

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
        displayed_token = mask_token(token) if in_ci else token
        print(f"jwt_token: {displayed_token}")

        ccs_config_upsert_succeeded = run_ccs_config_upsert(
            token, dry_run=args.dry_run
        )
        if ccs_config_upsert_succeeded:
            run_ccs_environment_update(token, dry_run=args.dry_run)
        else:
            print(
                "Skipping CCS environment update because the config upsert did not return 2xx."
            )

        if not api_path:
            print(
                "No API path configured yet. Set VERSORI_API_PATH or pass --api-path when the endpoint is decided."
            )
            return 0

        run_optional_api_call(
            api_path=api_path,
            org_id=org_id,
            external_user_id=external_user_id,
            base_url=args.base_url,
            method=args.method,
            token=token,
            body_text=body_text,
            dry_run=args.dry_run,
            in_ci=in_ci,
        )
        return 0

    except json.JSONDecodeError as exc:
        print(f"Invalid JSON body: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
