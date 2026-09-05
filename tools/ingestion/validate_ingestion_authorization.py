#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path, PurePosixPath
import importlib.util, subprocess, sys
ROOT=Path(__file__).resolve().parents[2]; FOUNDATION_PATH=ROOT/"tools/ingestion/validate_ingestion_foundation.py"; SPEC=importlib.util.spec_from_file_location("atlas_ingestion_foundation",FOUNDATION_PATH); foundation=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(foundation)
AUTHORIZED_IMPLEMENTATIONS={
"ingestion/connectors/mitre-attack-enterprise.json":"phase-5.3.2","ingestion/parsers/mitre-attack-stix21.definition.json":"phase-5.3.2","ingestion/parsers/mitre_attack_stix.py":"phase-5.3.2","ingestion/normalizers/mitre-attack-enterprise.definition.json":"phase-5.3.2","ingestion/normalizers/mitre_attack.py":"phase-5.3.2",
"ingestion/connectors/microsoft-sysmon-docs.json":"phase-5.3.3","ingestion/parsers/microsoft-sysmon-markdown.definition.json":"phase-5.3.3","ingestion/parsers/microsoft_sysmon_markdown.py":"phase-5.3.3","ingestion/parsers/microsoft-sysmon-schema.definition.json":"phase-5.3.3","ingestion/parsers/microsoft_sysmon_schema.py":"phase-5.3.3","ingestion/normalizers/microsoft-sysmon-docs.definition.json":"phase-5.3.3","ingestion/normalizers/microsoft_sysmon_docs.py":"phase-5.3.3","ingestion/normalizers/microsoft-sysmon-schema.definition.json":"phase-5.3.3","ingestion/normalizers/microsoft_sysmon_schema.py":"phase-5.3.3","ingestion/connectors/microsoft-windows-security-event-4688-doc.json":"phase-5.3.3","ingestion/parsers/microsoft-windows-security-event-html.definition.json":"phase-5.3.3","ingestion/parsers/microsoft_windows_security_event_html.py":"phase-5.3.3","ingestion/normalizers/microsoft-windows-security-event-doc.definition.json":"phase-5.3.3","ingestion/normalizers/microsoft_windows_security_event_doc.py":"phase-5.3.3","ingestion/parsers/microsoft-windows-provider-metadata.definition.json":"phase-5.3.3","ingestion/parsers/microsoft_windows_provider_metadata.py":"phase-5.3.3","ingestion/normalizers/microsoft-windows-provider-metadata.definition.json":"phase-5.3.3","ingestion/normalizers/microsoft_windows_provider_metadata.py":"phase-5.3.3",
"ingestion/connectors/mitre-d3fend-ontology.json":"phase-5.3.4","ingestion/parsers/mitre-d3fend-turtle.definition.json":"phase-5.3.4","ingestion/parsers/mitre_d3fend_turtle.py":"phase-5.3.4","ingestion/normalizers/mitre-d3fend.definition.json":"phase-5.3.4","ingestion/normalizers/mitre_d3fend.py":"phase-5.3.4","ingestion/connectors/mitre-car-sample.json":"phase-5.3.4","ingestion/parsers/mitre-car-yaml.definition.json":"phase-5.3.4","ingestion/parsers/mitre_car_yaml.py":"phase-5.3.4","ingestion/normalizers/mitre-car.definition.json":"phase-5.3.4","ingestion/normalizers/mitre_car.py":"phase-5.3.4","ingestion/parsers/defenseops-export.definition.json":"phase-5.3.4","ingestion/parsers/defenseops_export.py":"phase-5.3.4","ingestion/normalizers/defenseops-export.definition.json":"phase-5.3.4","ingestion/normalizers/defenseops_export.py":"phase-5.3.4"}
BLANKET_DENIAL_PREFIX="broad/live ingestion implementation is not authorized: "; CONTROLLED_DIRS={"ingestion/connectors","ingestion/parsers","ingestion/normalizers"}
def _git_tracked_paths(root):
    p=subprocess.run(["git","-C",str(root),"ls-files","-z"],check=True,capture_output=True,text=False); return [x.decode() for x in p.stdout.split(b"\0") if x]
def implementation_authorization_errors(tracked_paths):
    errors=[]; tracked={str(PurePosixPath(x.replace("\\","/"))) for x in tracked_paths}
    for path in sorted(tracked):
        pp=PurePosixPath(path)
        if str(pp.parent) not in CONTROLLED_DIRS or pp.name=="README.md": continue
        if path not in AUTHORIZED_IMPLEMENTATIONS: errors.append(f"undeclared ingestion implementation is not authorized: {path}")
    for path,slice_id in sorted(AUTHORIZED_IMPLEMENTATIONS.items()):
        if path not in tracked: errors.append(f"authorized implementation missing from repository ({slice_id}): {path}")
    return errors
def validate_repository(root=None):
    root=Path(root or ROOT); filtered=[]
    for error in foundation.validate_repository(root):
        if error.startswith(BLANKET_DENIAL_PREFIX) and error[len(BLANKET_DENIAL_PREFIX):] in AUTHORIZED_IMPLEMENTATIONS: continue
        filtered.append(error)
    try: filtered.extend(implementation_authorization_errors(_git_tracked_paths(root)))
    except (OSError,subprocess.CalledProcessError) as exc: filtered.append(f"unable to enforce ingestion implementation authorization: {exc}")
    return filtered
def main():
    e=validate_repository(ROOT)
    if e: [print(x) for x in e]; print(f"Atlas ingestion validation FAILED with {len(e)} error(s)."); return 1
    print("Atlas ingestion foundation + phase-aware implementation authorization passed."); print("Authorized slices: Phase 5.3.2 ATT&CK, Phase 5.3.3 Windows/Sysmon, Phase 5.3.4 D3FEND/CAR/DefenseOps."); return 0
if __name__=="__main__": sys.exit(main())
