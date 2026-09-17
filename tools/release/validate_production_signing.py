#!/usr/bin/env python3
"""Validate Phase 5.10.2 production signing and key-custody evidence."""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / 'docs/releases/production-signing-readiness.json'
POLICY = ROOT / 'docs/releases/production-signing-and-key-custody.md'
HEX64 = re.compile(r'^[0-9a-f]{64}$')


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument('--release', action='store_true'); args = ap.parse_args()
    errors: list[str] = []
    if not STATE.is_file(): errors.append('missing production-signing-readiness.json'); data = {}
    else:
        try: data = json.loads(STATE.read_text(encoding='utf-8'))
        except Exception as exc: errors.append(f'invalid signing readiness JSON: {exc}'); data = {}
    if not POLICY.is_file(): errors.append('missing production signing policy')
    if data:
        if data.get('schema_version') != '1.0.0': errors.append('unexpected signing schema_version')
        if data.get('gate') != 'PPR-05': errors.append('signing state must identify PPR-05')
        if data.get('state') not in {'BLOCKED','PASS'}: errors.append('signing state must be BLOCKED or PASS')
        if data.get('timestamp_policy') != 'RFC3161_REQUIRED': errors.append('RFC3161 timestamp policy is mandatory')
        if data.get('private_key_exportable') is True: errors.append('production signing private key must not be exportable')
        fields = ('unsigned_artifact_sha256','signed_artifact_sha256','sbom_sha256','certificate_sha256_fingerprint','release_attestation_sha256')
        for f in fields:
            v=data.get(f)
            if v is not None and (not isinstance(v,str) or not HEX64.fullmatch(v)): errors.append(f'{f} must be null or lowercase SHA-256 hex')
        ready = all([
            data.get('provider_selected') is True,
            bool(data.get('signing_provider')), bool(data.get('custody_class')),
            bool(data.get('certificate_subject')), bool(data.get('certificate_serial')),
            isinstance(data.get('certificate_sha256_fingerprint'),str) and bool(HEX64.fullmatch(data['certificate_sha256_fingerprint'])),
            data.get('private_key_exportable') is False,
            bool(data.get('release_commit')),
            all(isinstance(data.get(f),str) and bool(HEX64.fullmatch(data[f])) for f in ('unsigned_artifact_sha256','signed_artifact_sha256','sbom_sha256','release_attestation_sha256')),
            data.get('rfc3161_timestamp_verified') is True,
            data.get('signature_verified') is True,
            bool(data.get('signing_run_or_audit_id')),
            data.get('rotation_procedure_documented') is True,
            data.get('revocation_procedure_documented') is True,
            data.get('compromise_response_documented') is True,
        ])
        if data.get('state') == 'PASS' and not ready: errors.append('PPR-05 cannot PASS without complete provider/custody/certificate and exact signed-artifact evidence')
        if data.get('state') == 'BLOCKED' and ready: errors.append('PPR-05 is mechanically ready but still BLOCKED; require explicit reviewed state transition')
        if args.release and data.get('state') != 'PASS': errors.append('strict release mode requires PPR-05 PASS')
    if POLICY.is_file():
        p=POLICY.read_text(encoding='utf-8')
        for token in ('non-exportable','RFC 3161','PPR-05 remains **BLOCKED**','No production private key, PFX'):
            if token not in p: errors.append(f'signing policy missing required token: {token}')
    if errors:
        print('PPR-05 signing validation FAILED:'); [print(f'- {e}') for e in errors]; return 1
    print(f"PPR-05 signing validation passed ({'strict release' if args.release else 'baseline'} mode).")
    return 0
if __name__ == '__main__': sys.exit(main())
