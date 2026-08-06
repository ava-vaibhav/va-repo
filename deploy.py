#!/usr/bin/env python3
"""
Generate a Versori JWT and deploy a tarball via the Versori from-git API.

This script is designed to be CI/CD friendly:
- secrets come from environment variables or a private key file
- the JWT is signed with your organisation PKCS #8 private key
- tarball deploy uses multipart POST with X-Versori-Internal-Token (tunnel testing)

Required configuration:
- VERSORI_SIGNING_KEY_ID
- VERSORI_EXTERNAL_USER_ID
- one of:
  - VERSORI_PRIVATE_KEY
  - VERSORI_PRIVATE_KEY_FILE

Tarball deploy configuration:
- VERSORI_ORG_ID
- VERSORI_PROJECT_ID
- VERSORI_PROJECT_NAME
- VERSORI_PROJECT_ENV
- VERSORI_API_PATH  (e.g. o/{org_id}/projects/{proj_id}/deploy/from-git/tarball?project_env={versori_env})
- VERSORI_API_BASE_URL
- VERSORI_INTERNAL_TOKEN

Optional configuration:
- DEPLOY_BRANCH / GITHUB_REF_NAME (branch being deployed)
- GITHUB_SHA (commit SHA for deploy metadata)
- VERSORI_VERSION_NAME (override default versionName)
- VERSORI_TOKEN_LIFETIME_SECONDS (default: 3600)

Examples:
  python deploy.py --branch cicd-test --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

try:
    import jwt
except ImportError as exc:
    raise SystemExit(
        "PyJWT is required. Install it with: pip install PyJWT[crypto]"
    ) from exc


DEFAULT_BASE_URL = "https://platform.versori.com"


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


def render_api_path(
    template: str,
    org_id: str | None,
    external_user_id: str,
    proj_id: str | None = None,
    versori_env: str | None = None,
) -> str:
    replacements = {
        "org_id": org_id or "",
        "external_user_id": external_user_id,
        "proj_id": proj_id or "",
        "versori_env": versori_env or "",
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


def resolve_tarball_path(project_name: str) -> str:
    return f"tarballs/{project_name}/files.tar"


def git_show_file(ref: str, repo_path: str) -> bytes | None:
    try:
        result = subprocess.run(
            ["git", "show", f"{ref}:{repo_path}"],
            capture_output=True,
            check=False,
        )
    except (OSError, FileNotFoundError):
        return None

    if result.returncode == 0:
        return result.stdout
    return None


def locate_tarball(
    branch: str,
    project_name: str,
    tarball_override: str | None = None,
) -> tuple[str, bool]:
    """Return tarball path and whether it is a temporary extracted file."""
    if tarball_override:
        if not os.path.isfile(tarball_override):
            raise FileNotFoundError(f"Tarball not found: {tarball_override}")
        return tarball_override, False

    repo_path = resolve_tarball_path(project_name)
    if os.path.isfile(repo_path):
        return repo_path, False

    for ref in (branch, f"origin/{branch}"):
        data = git_show_file(ref, repo_path)
        if data is None:
            continue

        temp = tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".tar",
            prefix="versori-deploy-",
        )
        try:
            temp.write(data)
            temp.close()
        except Exception:
            temp.close()
            os.unlink(temp.name)
            raise

        print(
            f"Loaded tarball from git {ref}:{repo_path} ({len(data)} bytes)"
        )
        return temp.name, True

    raise FileNotFoundError(
        f"Tarball not found: {repo_path}\n"
        f"  Checked working tree and git refs '{branch}' / 'origin/{branch}'.\n"
        f"  Fix: git checkout {branch}\n"
        f"  Or:  set VERSORI_TARBALL_PATH to your files.tar"
    )


def read_commit_sha() -> str:
    return os.getenv("GITHUB_SHA", "")


def build_deploy_metadata(branch: str, commit_sha: str) -> str:
    version_name = os.getenv("VERSORI_VERSION_NAME")
    if not version_name:
        short_sha = commit_sha[:7] if commit_sha else "unknown"
        version_name = f"{branch}-{short_sha}"

    metadata = {
        "versionName": version_name,
        "branch": branch,
        "commitSha": commit_sha or "unknown",
    }
    return json.dumps(metadata, separators=(",", ":"))


def build_multipart_body(metadata_json: str, tarball_path: str) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    crlf = b"\r\n"

    with open(tarball_path, "rb") as handle:
        tarball_data = handle.read()

    metadata_part = (
        f"--{boundary}".encode()
        + crlf
        + b'Content-Disposition: form-data; name="metadata"'
        + crlf
        + crlf
        + metadata_json.encode("utf-8")
        + crlf
    )

    tarball_header = (
        f"--{boundary}".encode()
        + crlf
        + b'Content-Disposition: form-data; name="tarball"; filename="files.tar"'
        + crlf
        + b"Content-Type: application/octet-stream"
        + crlf
        + crlf
    )

    closing = f"--{boundary}--".encode() + crlf
    body = metadata_part + tarball_header + tarball_data + crlf + closing
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def call_tarball_deploy_api(
    url: str,
    internal_token: str,
    metadata_json: str,
    tarball_path: str,
) -> tuple[int, str]:
    body, content_type = build_multipart_body(metadata_json, tarball_path)
    headers = {
        "X-Versori-Internal-Token": internal_token,
        "Accept": "application/json",
        "Content-Type": content_type,
    }

    request = urllib.request.Request(
        url=url,
        data=body,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(request) as response:
            response_body = response.read().decode("utf-8")
            return response.status, response_body
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        return exc.code, error_body


def build_tarball_curl_command(
    url: str,
    internal_token: str,
    metadata_json: str,
    tarball_path: str,
) -> str:
    """Build a PowerShell-friendly curl command for tarball deploy."""

    def quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    return " ".join(
        [
            "curl",
            "-X",
            quote("POST"),
            quote(url),
            "-H",
            quote(f"X-Versori-Internal-Token: {internal_token}"),
            "-F",
            quote(f"metadata={metadata_json}"),
            "-F",
            quote(f"tarball=@{tarball_path}"),
        ]
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a Versori JWT and deploy a tarball to Versori."
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
            "API path or full URL. Supports {org_id}, {proj_id}, {versori_env}, "
            "and {external_user_id} placeholders. Falls back to VERSORI_API_PATH."
        ),
    )
    parser.add_argument(
        "--lifetime-seconds",
        type=int,
        default=int(os.getenv("VERSORI_TOKEN_LIFETIME_SECONDS", "3600")),
        help="JWT lifetime in seconds. Defaults to 3600.",
    )
    parser.add_argument(
        "--tarball-path",
        help="Path to files.tar. Falls back to VERSORI_TARBALL_PATH or repo tarballs/{project}/files.tar.",
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
    temp_tarball_path: str | None = None

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
        proj_id = os.getenv("VERSORI_PROJECT_ID")
        project_name = os.getenv("VERSORI_PROJECT_NAME")
        versori_env = os.getenv("VERSORI_PROJECT_ENV")
        internal_token = os.getenv("VERSORI_INTERNAL_TOKEN")
        api_path = args.api_path or os.getenv("VERSORI_API_PATH")
        commit_sha = read_commit_sha()

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

        if not api_path:
            print(
                "No API path configured yet. Set VERSORI_API_PATH or pass --api-path when the endpoint is decided."
            )
            return 0

        if not project_name:
            raise ValueError("Missing required value: VERSORI_PROJECT_NAME")
        if not internal_token:
            raise ValueError("Missing required value: VERSORI_INTERNAL_TOKEN")

        resolved_path = render_api_path(
            api_path,
            org_id=org_id,
            external_user_id=external_user_id,
            proj_id=proj_id,
            versori_env=versori_env,
        )
        url = build_url(args.base_url, resolved_path)
        tarball_override = args.tarball_path or os.getenv("VERSORI_TARBALL_PATH")
        tarball_path, is_temp_tarball = locate_tarball(
            branch=branch,
            project_name=project_name,
            tarball_override=tarball_override,
        )
        if is_temp_tarball:
            temp_tarball_path = tarball_path
        metadata_json = build_deploy_metadata(branch, commit_sha)

        tarball_size = os.path.getsize(tarball_path)
        displayed_internal_token = mask_token(internal_token) if in_ci else internal_token
        curl_command = build_tarball_curl_command(
            url=url,
            internal_token=internal_token,
            metadata_json=metadata_json,
            tarball_path=tarball_path,
        )

        print(f"method: POST")
        print(f"url: {url}")
        print(f"tarball_path: {resolve_tarball_path(project_name)}")
        if tarball_path != resolve_tarball_path(project_name):
            print(f"tarball_source: {tarball_path}")
        print(f"tarball_size_bytes: {tarball_size}")
        print(f"metadata: {metadata_json}")
        print(f"internal_token: {displayed_internal_token}")
        if in_ci:
            print("curl: (redacted in CI logs)")
        else:
            print(f"curl: {curl_command}")

        if args.dry_run:
            print("Dry run enabled. Skipping API call.")
            return 0

        status_code, response_text = call_tarball_deploy_api(
            url=url,
            internal_token=internal_token,
            metadata_json=metadata_json,
            tarball_path=tarball_path,
        )

        print(f"status_code: {status_code}")
        print("response:")
        print(response_text)
        return 0 if 200 <= status_code < 300 else 1

    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    finally:
        if temp_tarball_path and os.path.isfile(temp_tarball_path):
            os.unlink(temp_tarball_path)


if __name__ == "__main__":
    raise SystemExit(main())
