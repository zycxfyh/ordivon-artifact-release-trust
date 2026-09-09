#!/usr/bin/env python3
"""Minimal stdlib-only Sigstore keyless release signing bridge.

This bridge is intentionally narrow. It runs in the GitHub Actions job that owns
`id-token: write`, so it does not import repository dependencies or execute
third-party Actions. Semantic VSA/Provenance validation happens in the separate
prepare job before the digest-bound payload crosses into the signing job.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.parse
from typing import Any

GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
SLSA_VERIFICATION_SUMMARY_V1 = "https://slsa.dev/verification_summary/v1"
COSIGN_SIGNING_VERSION = "3.1.3"
COSIGN_LINUX_AMD64_SHA256 = "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _uri(value: Any) -> bool:
    return isinstance(value, str) and bool(urllib.parse.urlparse(value).scheme)


def _signer(policy: dict[str, Any], signer_id: str) -> dict[str, Any] | None:
    for signer in policy.get("signers", []) if isinstance(policy.get("signers"), list) else []:
        if isinstance(signer, dict) and signer.get("id") == signer_id:
            return signer
    return None


def readiness(policy_path: Path, signer_id: str, environment: dict[str, str] | None = None) -> dict[str, Any]:
    failures: list[str] = []
    env = dict(os.environ if environment is None else environment)
    try:
        policy = load_json(policy_path)
    except Exception as error:
        return {"status": "FAIL", "failures": [f"trust policy is unreadable JSON: {error}"]}
    if not isinstance(policy, dict):
        return {"status": "FAIL", "failures": ["trust policy root is not an object"]}
    policy_digest = sha256_file(policy_path)
    expected_policy_digest = env.get("ORDIVON_RELEASE_TRUST_POLICY_SHA256")
    if not isinstance(expected_policy_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_policy_digest):
        failures.append("protected environment did not supply a lowercase SHA-256 trust-policy authority")
    elif policy_digest != expected_policy_digest:
        failures.append("trust policy digest does not match protected environment authority")
    signer = _signer(policy, signer_id)
    if signer is None:
        failures.append(f"trusted signer id is absent from policy: {signer_id}")
        signer = {}
    if signer.get("mode") != "keyless":
        failures.append("release signing bridge accepts only keyless signers")
    identity = signer.get("certificateIdentity")
    issuer = signer.get("certificateOidcIssuer")
    github = signer.get("githubActions")
    if not _uri(identity):
        failures.append("keyless signer certificateIdentity is absent or not a URI")
    if issuer != GITHUB_ACTIONS_OIDC_ISSUER:
        failures.append("release signing bridge currently accepts only GitHub Actions OIDC")
    if signer.get("requireTransparencyLog") is not True:
        failures.append("keyless release signer must require transparency-log verification")
    if signer.get("trustedRoot") is not None:
        failures.append("custom trustedRoot is not supported by the public-Sigstore production bridge")
    if not isinstance(github, dict):
        failures.append("GitHub Actions signer lacks exact workflow claims")
        github = {}
    sha_authority = github.get("shaAuthority")
    expected_sha = github.get("sha") if sha_authority == "policy" else env.get("ORDIVON_RELEASE_WORKFLOW_SHA")
    if sha_authority not in {"policy", "runtime"}:
        failures.append("GitHub Actions signer lacks shaAuthority=policy|runtime")
    elif sha_authority == "policy":
        if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
            failures.append("policy SHA authority lacks exact 40-hex githubActions.sha")
    else:
        if github.get("sha") is not None:
            failures.append("runtime SHA authority must not embed githubActions.sha")
        if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
            failures.append("protected environment did not supply exact ORDIVON_RELEASE_WORKFLOW_SHA")
    expected_runtime = {
        "GITHUB_REPOSITORY": github.get("repository"),
        "GITHUB_WORKFLOW_REF": github.get("workflowRef"),
        "GITHUB_REF": github.get("ref"),
        "GITHUB_SHA": expected_sha,
        "GITHUB_WORKFLOW": github.get("name"),
        "GITHUB_EVENT_NAME": github.get("trigger"),
    }
    if env.get("GITHUB_ACTIONS") != "true":
        failures.append("runtime is not an admitted GitHub Actions job")
    for key, expected in expected_runtime.items():
        if not isinstance(expected, str) or not expected:
            failures.append(f"signer policy lacks exact GitHub claim: {key}")
        elif env.get(key) != expected:
            failures.append(f"GitHub Actions runtime claim mismatch: {key}")
    if isinstance(identity, str) and isinstance(github.get("workflowRef"), str):
        if identity != f"https://github.com/{github['workflowRef']}":
            failures.append("certificateIdentity does not exactly match githubActions.workflowRef")
    if not env.get("ACTIONS_ID_TOKEN_REQUEST_URL"):
        failures.append("GitHub OIDC request URL is unavailable")
    if not env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
        failures.append("GitHub OIDC request authority is unavailable")
    return {
        "status": "PASS" if not failures else "FAIL",
        "policySha256": policy_digest,
        "signerId": signer_id,
        "certificateIdentity": identity,
        "certificateOidcIssuer": issuer,
        "githubActions": github,
        "runtimeClaims": {key: env.get(key) for key in expected_runtime},
        "oidcRequestUrlPresent": bool(env.get("ACTIONS_ID_TOKEN_REQUEST_URL")),
        "oidcRequestAuthorityPresent": bool(env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")),
        "failures": failures,
        "boundary": "PASS is issuance readiness only; Fulcio issuance, signing, Rekor logging and post-sign verification must still succeed in this exact job occurrence.",
    }


def _statement_authorization(statement: dict[str, Any], subject: Path, signer: dict[str, Any]) -> tuple[str | None, list[str]]:
    failures: list[str] = []
    predicate_type = statement.get("predicateType")
    if predicate_type not in {SLSA_PROVENANCE_V1, SLSA_VERIFICATION_SUMMARY_V1}:
        failures.append("statement predicateType is not an admitted release attestation predicate")
    observed_subject_digest = sha256_file(subject)
    subjects = statement.get("subject")
    bound = False
    if isinstance(subjects, list):
        for item in subjects:
            if not isinstance(item, dict):
                continue
            digest = item.get("digest")
            if item.get("name") == subject.name and isinstance(digest, dict) and digest.get("sha256") == observed_subject_digest:
                bound = True
                break
    if not bound:
        failures.append("statement does not bind the exact subject name and SHA-256")
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    if predicate_type == SLSA_VERIFICATION_SUMMARY_V1:
        verifier = predicate.get("verifier") if isinstance(predicate.get("verifier"), dict) else {}
        verifier_id = verifier.get("id")
        if verifier_id not in set(signer.get("allowedVerifierIds", [])):
            failures.append("signer is not authorized for VSA verifier.id")
    elif predicate_type == SLSA_PROVENANCE_V1:
        run_details = predicate.get("runDetails") if isinstance(predicate.get("runDetails"), dict) else {}
        builder = run_details.get("builder") if isinstance(run_details.get("builder"), dict) else {}
        builder_id = builder.get("id")
        if builder_id not in set(signer.get("allowedBuilderIds", [])):
            failures.append("signer is not authorized for SLSA Provenance builder.id")
    return predicate_type if isinstance(predicate_type, str) else None, failures


def _cosign_fact(cosign: Path) -> dict[str, Any]:
    failures: list[str] = []
    if not cosign.is_file():
        return {"status": "FAIL", "failures": ["Cosign signing binary is absent"]}
    digest = sha256_file(cosign)
    if digest != COSIGN_LINUX_AMD64_SHA256:
        failures.append("Cosign signing binary SHA-256 does not match locked upstream v3.1.3 linux-amd64")
    proc = subprocess.run([str(cosign), "version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=20)
    output = proc.stdout + "\n" + proc.stderr
    if proc.returncode != 0 or f"GitVersion:    v{COSIGN_SIGNING_VERSION}" not in output:
        failures.append("Cosign signing binary version is not exactly v3.1.3")
    return {
        "status": "PASS" if not failures else "FAIL",
        "path": str(cosign.resolve()),
        "sha256": digest,
        "version": COSIGN_SIGNING_VERSION,
        "rawVersion": output.strip()[:2000],
        "failures": failures,
    }


def sign(
    subject: Path,
    statement_path: Path,
    policy_path: Path,
    signer_id: str,
    cosign: Path,
    bundle_path: Path,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    env = dict(os.environ if environment is None else environment)
    ready = readiness(policy_path, signer_id, env)
    if ready.get("status") != "PASS":
        failures.append("production keyless signing readiness failed")
    try:
        statement = load_json(statement_path)
    except Exception as error:
        statement = {}
        failures.append(f"statement is unreadable JSON: {error}")
    policy = load_json(policy_path) if policy_path.is_file() else {}
    signer = _signer(policy, signer_id) if isinstance(policy, dict) else None
    predicate_type, authorization_failures = _statement_authorization(
        statement if isinstance(statement, dict) else {}, subject, signer or {}
    )
    failures.extend(authorization_failures)
    tool = _cosign_fact(cosign)
    if tool.get("status") != "PASS":
        failures.append("Cosign signing tool verification failed")
    if failures:
        return {
            "status": "FAIL",
            "signed": False,
            "readiness": ready,
            "tool": tool,
            "predicateType": predicate_type,
            "failures": failures,
        }
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    if bundle_path.exists():
        return {
            "status": "FAIL",
            "signed": False,
            "readiness": ready,
            "tool": tool,
            "predicateType": predicate_type,
            "failures": ["bundle output already exists; refusing ambiguous signing overwrite"],
        }
    sign_proc = subprocess.run(
        [str(cosign), "attest-blob", "--yes", "--statement", str(statement_path), "--bundle", str(bundle_path), str(subject)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
    )
    if sign_proc.returncode != 0 or not bundle_path.is_file():
        failures.append("Cosign keyless attest-blob failed")
    github = (signer or {}).get("githubActions", {}) if isinstance((signer or {}).get("githubActions"), dict) else {}
    verify_command = [
        str(cosign),
        "verify-blob-attestation",
        "--bundle", str(bundle_path),
        "--check-claims=true",
        "--type", str(predicate_type),
        "--certificate-identity", str((signer or {}).get("certificateIdentity")),
        "--certificate-oidc-issuer", str((signer or {}).get("certificateOidcIssuer")),
        "--certificate-github-workflow-repository", str(github.get("repository")),
        "--certificate-github-workflow-ref", str(github.get("ref")),
        "--certificate-github-workflow-sha", str(env.get("GITHUB_SHA")),
        "--certificate-github-workflow-name", str(github.get("name")),
        "--certificate-github-workflow-trigger", str(github.get("trigger")),
        str(subject),
    ]
    verify_proc = subprocess.run(
        verify_command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
    ) if not failures else None
    if verify_proc is None or verify_proc.returncode != 0:
        failures.append("post-sign Cosign verification under exact workflow identity failed")
    return {
        "status": "PASS" if not failures else "FAIL",
        "signed": sign_proc.returncode == 0 and bundle_path.is_file(),
        "verified": verify_proc is not None and verify_proc.returncode == 0,
        "subject": {"name": subject.name, "sha256": sha256_file(subject)},
        "statement": {"sha256": sha256_file(statement_path), "predicateType": predicate_type},
        "bundle": {"path": str(bundle_path), "sha256": sha256_file(bundle_path)} if bundle_path.is_file() else None,
        "readiness": ready,
        "tool": tool,
        "signingExitCode": sign_proc.returncode,
        "signingStdout": sign_proc.stdout.strip()[:2000],
        "signingStderr": sign_proc.stderr.strip()[:2000],
        "verificationExitCode": verify_proc.returncode if verify_proc is not None else None,
        "verificationStdout": verify_proc.stdout.strip()[:2000] if verify_proc is not None else "",
        "verificationStderr": verify_proc.stderr.strip()[:2000] if verify_proc is not None else "",
        "failures": failures,
        "boundary": "PASS observes this exact GitHub Actions occurrence obtaining a keyless signature and immediately verifying it under exact SAN/issuer/repository/ref/SHA/name/trigger constraints. Rekor/Fulcio evidence remains in the standardized Sigstore bundle consumed by downstream release verification.",
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("readiness")
    p.add_argument("--trust-policy", type=Path, required=True)
    p.add_argument("--signer-id", required=True)
    p.add_argument("--output", type=Path)
    p = sub.add_parser("sign")
    p.add_argument("--subject", type=Path, required=True)
    p.add_argument("--statement", type=Path, required=True)
    p.add_argument("--trust-policy", type=Path, required=True)
    p.add_argument("--signer-id", required=True)
    p.add_argument("--cosign", type=Path, required=True)
    p.add_argument("--bundle", type=Path, required=True)
    p.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "readiness":
        value = readiness(args.trust_policy, args.signer_id)
    else:
        value = sign(args.subject, args.statement, args.trust_policy, args.signer_id, args.cosign, args.bundle)
    if args.output:
        write_json(args.output, value)
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if value.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
