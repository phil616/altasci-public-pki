#!/usr/bin/env python3
"""Small HTTPS client for the independent CSR API; no third-party packages.

Set SIGNING_TOKEN or use --token-file (never put credentials in command arguments).
The issue operation persists its request hash/key before sending. Re-run with the
same CSR, validity, endpoint and state file after timeouts; use a NEW state file
for each renewal. The client does not generate or transfer leaf private keys.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, build_opener, Request


class NoRedirect(HTTPRedirectHandler):
    # Authorization must never be forwarded to a redirect target.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def atomic_write(path, data):
    destination = Path(path)
    fd, name = tempfile.mkstemp(prefix=".signing-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, destination)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def validate_files(paths):
    """Reject output/state aliases before creating files or sending a request."""
    seen = []
    for label, value in paths.items():
        if not value:
            continue
        path = Path(value)
        for previous_label, previous in seen:
            aliases = path.resolve() == previous.resolve()
            if not aliases and path.exists() and previous.exists():
                aliases = path.samefile(previous)
            if aliases:
                raise ValueError(f"{label} and {previous_label} must refer to different files")
        seen.append((label, path))


def request_key(state_path, endpoint, body, credential_hash):
    digest = hashlib.sha256(endpoint.encode() + b"\n" + credential_hash.encode() + b"\n" + body).hexdigest()
    path = Path(state_path)
    if not path.exists():
        payload = {"request_hash": digest, "idempotency_key": secrets.token_urlsafe(24)}
        # Exclusive creation avoids different callers claiming the same state file.
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "w") as stream:
                json.dump(payload, stream)
                stream.flush()
                os.fsync(stream.fileno())
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict) or payload.get("request_hash") != digest:
        raise ValueError("State belongs to a different request. Use a new state file for renewal.")
    key = payload.get("idempotency_key")
    if not isinstance(key, str) or not 8 <= len(key) <= 128:
        raise ValueError("Invalid idempotency state file")
    return key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["issue", "read", "revoke"])
    parser.add_argument("--endpoint", required=True, help="Published HTTPS URL ending in /issue")
    parser.add_argument("--token-file", help="File containing the credential; alternatively set SIGNING_TOKEN")
    parser.add_argument("--ca-file", help="PEM roots for verifying the API's HTTPS certificate")
    parser.add_argument("--csr", help="PKCS#10 PEM file, for issue")
    parser.add_argument("--state", help="Persistent per-request state file, required for issue")
    parser.add_argument("--output", help="Certificate-chain output PEM, required for issue/read")
    parser.add_argument("--certificate-id", help="Certificate UUID, for read/revoke")
    parser.add_argument("--validity-seconds", type=int, default=0)
    parser.add_argument("--reason", type=int, default=0)
    args = parser.parse_args()
    origin = urlsplit(args.endpoint)
    if origin.scheme != "https" or not origin.hostname or origin.username or origin.password or origin.query or origin.fragment or not origin.path.endswith("/issue"):
        parser.error("Endpoint must be a plain HTTPS URL ending in /issue")
    validate_files({
        "token file": args.token_file, "TLS CA file": args.ca_file,
        "CSR": args.csr if args.operation == "issue" else None,
        "state": args.state if args.operation == "issue" else None,
        "output": args.output if args.operation in {"issue", "read"} else None,
    })
    token = Path(args.token_file).read_text().strip() if args.token_file else os.environ.get("SIGNING_TOKEN", "")
    if not token.startswith("ist_") or len(token) != 47 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for c in token[4:]):
        parser.error("Provide a valid credential through --token-file or SIGNING_TOKEN")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json", "Content-Type": "application/json"}
    endpoint = args.endpoint
    method, body = "POST", None
    if args.operation == "issue":
        if not args.csr or not args.state or not args.output:
            parser.error("issue requires --csr, --state and --output")
        csr = Path(args.csr)
        if csr.stat().st_size > 65536:
            parser.error("CSR exceeds 64 KiB")
        body = json.dumps({"csr_pem": csr.read_text(), "validity_seconds": args.validity_seconds}, separators=(",", ":")).encode()
        headers["Idempotency-Key"] = request_key(args.state, endpoint, body, hashlib.sha256(token.encode()).hexdigest())
    else:
        import uuid
        if not args.certificate_id:
            parser.error("read/revoke requires --certificate-id")
        certificate = str(uuid.UUID(args.certificate_id))
        endpoint = endpoint[:-len("/issue")] + "/certificates/" + certificate
        if args.operation == "read":
            if not args.output:
                parser.error("read requires --output")
            method = "GET"
        else:
            endpoint += "/revoke"
            body = json.dumps({"reason": args.reason}).encode()
    context = ssl.create_default_context(cafile=args.ca_file)
    opener = build_opener(NoRedirect(), HTTPSHandler(context=context))
    try:
        with opener.open(Request(endpoint, data=body, headers=headers, method=method), timeout=30) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError("Response exceeds size limit")
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError("Response must be a JSON object; retain state and retry")
    except HTTPError as error:
        raw = error.read(65536)
        try:
            detail = json.loads(raw).get("detail", "Request failed")
        except (ValueError, AttributeError):
            detail = "Request failed"
        raise ValueError(f"HTTP {error.code}: {detail}. Keep the state file for an identical retry.") from None
    if args.operation == "issue" and result.get("status") != "good":
        raise ValueError("The original certificate is revoked or expired. Use a new operation for renewal.")
    if args.operation in {"issue", "read"}:
        chain = result.get("chain_pem")
        if not isinstance(chain, str) or not chain.startswith("-----BEGIN CERTIFICATE-----"):
            raise ValueError("Response does not contain a certificate chain; retain state and retry")
        atomic_write(args.output, chain.encode())
    print(json.dumps({key: result.get(key) for key in ("id", "serial", "status", "not_after")}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, URLError) as error:
        sys.exit(f"Signing client failed: {error}")
