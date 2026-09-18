#!/usr/bin/env python3
"""Validate Phase 5.10.3 public packaging/distribution readiness."""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
STATE=ROOT/'docs/releases/public-packaging-readiness.json'
POLICY=ROOT/'docs/releases/public-packaging-and-distribution.md'
HEX64=re.compile(r'^[0-9a-f]{64}$')

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument('--release',action='store_true'); args=ap.parse_args()
    errors=[]
    try: data=json.loads(STATE.read_text(encoding='utf-8'))
    except Exception as exc: errors.append(f'invalid/missing packaging readiness JSON: {exc}'); data={}
    if not POLICY.is_file(): errors.append('missing packaging policy')
    if data:
        if data.get('schema_version')!='1.0.0': errors.append('unexpected schema_version')
        if data.get('gate')!='PPR-06': errors.append('state must identify PPR-06')
        if data.get('state') not in {'BLOCKED','PASS'}: errors.append('state must be BLOCKED or PASS')
        for f in ('signed_package_sha256','sbom_sha256','third_party_notices_sha256','release_notes_sha256'):
            v=data.get(f)
            if v is not None and (not isinstance(v,str) or not HEX64.fullmatch(v)): errors.append(f'{f} must be null or lowercase SHA-256 hex')
        required_true=('distribution_format_selected','publication_channel_selected','signature_verified','timestamp_verified','clean_windows_acceptance','knowledge_pack_acceptance','network_posture_acceptance','corruption_rejection_acceptance','upgrade_acceptance','rollback_recovery_acceptance','uninstall_or_remove_acceptance','accessibility_package_sha_bound','published_bytes_reverified')
        ready=all(data.get(f) is True for f in required_true) and bool(data.get('distribution_format')) and bool(data.get('publication_channel')) and bool(data.get('release_commit')) and isinstance(data.get('signed_package_size_bytes'),int) and data.get('signed_package_size_bytes',0)>0 and all(isinstance(data.get(f),str) and bool(HEX64.fullmatch(data[f])) for f in ('signed_package_sha256','sbom_sha256','third_party_notices_sha256','release_notes_sha256'))
        if data.get('state')=='PASS' and not ready: errors.append('PPR-06 cannot PASS without exact selected channel/format and complete package acceptance evidence')
        if data.get('state')=='BLOCKED' and ready: errors.append('PPR-06 is mechanically ready but BLOCKED; require explicit reviewed state transition')
        if args.release and data.get('state')!='PASS': errors.append('strict release mode requires PPR-06 PASS')
    if POLICY.is_file():
        text=POLICY.read_text(encoding='utf-8')
        for token in ('Signed portable ZIP','Signed MSI','Signed MSIX','PPR-06 remains **BLOCKED**','binary auto-update'):
            if token not in text: errors.append(f'packaging policy missing token: {token}')
    if errors:
        print('PPR-06 packaging validation FAILED:'); [print(f'- {e}') for e in errors]; return 1
    print(f"PPR-06 packaging validation passed ({'strict release' if args.release else 'baseline'} mode).")
    return 0
if __name__=='__main__': sys.exit(main())
