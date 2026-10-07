#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from xml.etree import ElementTree as ET

R = Path(__file__).resolve().parents[1]
IDS = ["4753","4754","4755","4756","4757","4758","4759","4760","4761","4762"]
RUN = 37680802160
ART = 11508793624
AD = "sha256:5033778ccdf7a966a8fc16121f2bcdcd7d9652baf85bff51341b86c2940f7882"
RAW = "sha256-67a6e722b1b4da6f31a51c5c673b60079eec8d24b0d3734f9a290d1c2ce4e952"
SID = "atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4753-4762"
SV = "windows-server-2025-build-26100-security-auditing-4753-4762"
NOW = "2026-10-07T20:17:05Z"
DIST_URL = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-distribution-group-management"
SEC_URL = "https://learn.microsoft.com/en-gb/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management"
APPENDIX_URL = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/Appendix-L--Events-to-Monitor"
META = {
    "4753": {"title":"A security-disabled global group was deleted","subcategory":"Audit Distribution Group Management","template":"4748","url":"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4753"},
    "4754": {"title":"A security-enabled universal group was created","subcategory":"Audit Security Group Management","template":"4731","url":SEC_URL},
    "4755": {"title":"A security-enabled universal group was changed","subcategory":"Audit Security Group Management","template":"4735","url":SEC_URL},
    "4756": {"title":"A member was added to a security-enabled universal group","subcategory":"Audit Security Group Management","template":"4732","url":SEC_URL},
    "4757": {"title":"A member was removed from a security-enabled universal group","subcategory":"Audit Security Group Management","template":"4733","url":SEC_URL},
    "4758": {"title":"A security-enabled universal group was deleted","subcategory":"Audit Security Group Management","template":"4734","url":SEC_URL},
    "4759": {"title":"A security-disabled universal group was created","subcategory":"Audit Distribution Group Management","template":"4749","url":DIST_URL},
    "4760": {"title":"A security-disabled universal group was changed","subcategory":"Audit Distribution Group Management","template":"4750","url":DIST_URL},
    "4761": {"title":"A member was added to a security-disabled universal group","subcategory":"Audit Distribution Group Management","template":"4751","url":DIST_URL},
    "4762": {"title":"A member was removed from a security-disabled universal group","subcategory":"Audit Distribution Group Management","template":"4752","url":DIST_URL},
}


def dump(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def digest_without_field(record: dict, field: str = "digest") -> str:
    payload = copy.deepcopy(record)
    payload.pop(field, None)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256-" + hashlib.sha256(raw).hexdigest()


def load_discovery() -> dict:
    path = Path(os.environ["ATLAS_DISCOVERY_JSON"])
    body = path.read_bytes()
    assert "sha256-" + hashlib.sha256(body).hexdigest() == RAW
    data = json.loads(body.decode("utf-8-sig"))
    assert data["schema"] == "atlas.windows-provider-structural-discovery/v1"
    assert data["structural_only"] is True
    assert str(data["runner_os"]["OsBuildNumber"]) == "26100"
    assert data["provider"] == "Microsoft-Windows-Security-Auditing"
    assert data["channel_scope"] == "Security"
    assert [str(x) for x in data["requested_ids"]] == IDS
    assert data["unique_event_id_count"] == 10
    assert data["event_version_definition_count"] == 12
    return data


def shapes(data: dict) -> dict:
    ns = {"e":"http://schemas.microsoft.com/win/2004/08/events"}
    out = {eid: [] for eid in IDS}
    for row in data["events"]:
        eid = str(row["id"])
        root = ET.fromstring(row["template"])
        fields = [(x.attrib["name"], x.attrib.get("inType"), x.attrib.get("outType")) for x in root.findall("e:data", ns)]
        out[eid].append({"version":int(row["version"]), "level":row["level"], "fields":fields})
    expected = {
        "4753":{0:8}, "4754":{0:10}, "4755":{0:10}, "4756":{0:10,1:11}, "4757":{0:10},
        "4758":{0:8}, "4759":{0:10}, "4760":{0:10}, "4761":{0:10,1:11}, "4762":{0:10},
    }
    assert {eid:{x["version"]:len(x["fields"]) for x in rows} for eid,rows in out.items()} == expected
    for eid in ("4756","4761"):
        byv = {x["version"]:[f[0] for f in x["fields"]] for x in out[eid]}
        assert byv[1] == byv[0] + ["MembershipExpirationTime"]
    return out


def source_record(source_id: str, key: str, title: str, urls: list[str], *, publisher="Microsoft", source_class="tier-a-authoritative", official="official", license_status="unknown", redistribution_policy="restricted", redistribution_notes="ATLAS stores independently authored normalized facts and source locators; substantial Microsoft documentation prose is not redistributed.", cadence="documentation-maintained", stale=180, strategy="content-diff", notes="Microsoft semantic authority; provider structural authority.") -> dict:
    return {
        "schema_version":"1.0.0", "record_kind":"source", "id":source_id, "record_revision":1,
        "created_at":NOW, "updated_at":NOW, "curation_status":"validated", "namespace":"atlas.source",
        "canonical_key":key, "title":title, "publisher":publisher, "source_class":source_class,
        "canonical_urls":urls, "official_status":official, "license":{"status":license_status},
        "redistribution":{"policy":redistribution_policy, "notes":redistribution_notes},
        "freshness_policy":{"expected_update_cadence":cadence, "stale_after_days":stale},
        "change_detection_policy":{"strategy":strategy, "notes":notes},
    }


def build_inventory(s: dict) -> dict:
    identities=[]
    for eid in IDS:
        versions=[]
        for row in s[eid]:
            versions.append({
                "version":row["version"], "field_count":len(row["fields"]), "level":row["level"],
                "fields":[{"name":n,"in_type":i,"out_type":o} for n,i,o in row["fields"]],
            })
        identities.append({"event_id":eid,"versions":versions})
    inv={
        "ingestion_contract_version":"1.0.0", "inventory_contract_version":"1.0.0",
        "inventory_id":"atlas:inventory:atlas.ingestion:windows-security-auditing-4753-4762-26100",
        "inventory_kind":"telemetry",
        "declared_scope":"Microsoft-Windows-Security-Auditing Event IDs 4753-4762 / Security / Windows Server 2025 build 26100",
        "source_ids":[SID], "inventory_method":"provider-runtime-metadata", "inventory_source_version":SV,
        "expected_identity_count":10,
        "identity_dimensions":["provider","channel","native-id","product","platform","version"],
        "scope_metadata":{
            "provider":"Microsoft-Windows-Security-Auditing", "channel":"Security", "product":"Windows Server 2025 Datacenter",
            "platform":"Windows", "windows_build":"26100", "architecture":"64-bit", "workflow_run_id":RUN,
            "artifact_id":ART, "artifact_digest":AD, "raw_artifact_sha256":RAW,
            "provider_event_version_definition_count":12, "provider_unique_event_id_count":10,
            "expected_identities":identities,
            "completeness_semantics":"bounded structural evidence for ten identities inside the frozen 423-ID denominator; twelve version definitions preserved",
        },
        "guardrails":{"max_unexplained_shrink_percent":0,"max_unexplained_growth_percent":0},
    }
    inv["digest"] = digest_without_field(inv)
    return inv


def promote_blueprints(s: dict) -> None:
    path = R / "content/encyclopedia/approved-exemplars.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    events = doc["events"]
    byid = {str(x.get("native_event_id")):x for x in events if x.get("namespace") == "microsoft.windows.security"}
    assert all(eid not in byid for eid in IDS)
    insert_at = next(i for i,x in enumerate(events) if str(x.get("native_event_id")) == "4752") + 1
    promoted=[]
    for eid in IDS:
        meta=META[eid]
        base=copy.deepcopy(byid[meta["template"]])
        title=meta["title"]
        base.update({
            "id":f"atlas:event:microsoft.windows.security:{eid}", "canonical_key":eid,
            "title":f"Windows Security Event {eid} — {title}", "native_event_id":eid,
            "aliases":[eid,f"Event ID {eid}",f"Windows {eid}",title],
            "source_id":f"atlas:source:atlas.source:microsoft-windows-security-event-{eid}",
            "source_version":f"event-{eid}-provider-bound-doc", "source_url":meta["url"],
            "source_locator":f"{eid}(S): {title}",
        })
        versions = ",".join(str(x["version"]) for x in s[eid])
        base["structural_source"]={"source_id":SID,"source_version":SV,"locator":f"Microsoft-Windows-Security-Auditing / Security / Event ID {eid} / versions {versions}"}
        base["external_reference"]={
            "source_id":f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}",
            "url":f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={eid}",
            "role":"PRIMARY_EXTERNAL_QUICK_DETAIL_REFERENCE", "redistribution":"source-link-and-coverage-benchmark-only",
        }
        summary=f"Records {title.lower()} while preserving provider-rendered identity and change context."
        if eid in ("4756","4761"):
            summary += " Version 1 adds MembershipExpirationTime and remains distinct."
        base["overview"]={
            "summary":summary, "category":"Account Management", "subcategory":meta["subcategory"], "event_type":"Success",
            "provider_level":"Informational",
            "event_versions":[{"version":str(x["version"]),"generation":"Documented and/or provider-validated shape","field_count":len(x["fields"]),"notes":"Controlled Windows Server 2025 provider structural shape."} for x in s[eid]],
        }
        base["collection"]={
            "requirements":[f"Enable {meta['subcategory']} success auditing.","Preserve exact provider version and subject/target context."],
            "interpretation_note":"Unexpected universal-group or distribution-group changes require validation against approved identity and access-management activity.",
        }
        base["correlations"]=[]
        base["analysis"]=["Validate against approved identity, access and group-lifecycle records before assigning malicious intent."]
        actual={}
        for row in s[eid]:
            for n,_,_ in row["fields"]:
                actual.setdefault(n,[]).append(str(row["version"]))
        template_fields={x["native_name"]:x for x in base["fields"]}
        assert set(template_fields) == set(actual), (eid,set(template_fields),set(actual))
        for n,field in template_fields.items():
            field["versions"] = sorted(actual[n], key=int)
        promoted.append(base)
    events[insert_at:insert_at] = promoted
    dump(path, doc)


def write_sources() -> None:
    sd=R/"content/encyclopedia/sources"
    provider=source_record(
        SID, "microsoft-windows-security-auditing-provider-26100-4753-4762",
        "Microsoft-Windows-Security-Auditing provider metadata — build 26100 — Batch 12",
        ["https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log"],
        strategy="checksum", notes=f"Workflow {RUN}; artifact {ART}; {AD}; {RAW}."
    )
    dump(sd/"microsoft-windows-security-auditing-provider-26100-4753-4762.json",provider)
    for eid in IDS:
        meta=META[eid]
        ms=source_record(
            f"atlas:source:atlas.source:microsoft-windows-security-event-{eid}",
            f"microsoft-windows-security-event-{eid}", f"Microsoft Windows Security Event {eid}",
            [meta["url"],APPENDIX_URL]
        )
        dump(sd/f"microsoft-windows-security-event-{eid}.json",ms)
        uws=source_record(
            f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}",
            f"ultimate-windows-security-event-{eid}", f"Ultimate Windows Security Event {eid}",
            [f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={eid}"],
            publisher="Monterey Technology Group, Inc.", source_class="tier-c-secondary-research", official="secondary-reference",
            license_status="restricted", redistribution_policy="prohibited",
            redistribution_notes="External Quick Detail / coverage benchmark only; no substantial page prose is packaged.",
            cadence="web-reference", stale=90, strategy="manual", notes="Coverage/Quick Detail only; no bulk ingestion."
        )
        dump(sd/f"ultimate-windows-security-event-{eid}.json",uws)


def update_coverage() -> None:
    path=R/"content/encyclopedia/coverage-manifest.json"
    doc=json.loads(path.read_text(encoding="utf-8"))
    b=doc["windows_security_log_review_benchmark"]
    assert b["completion_ratio"] == "116/422"
    covered=set(map(str,b["covered_event_ids"])); assert not (covered & set(IDS))
    b["covered_event_ids"] = sorted(covered | set(IDS), key=int)
    b["encyclopedia_grade_listed_id_count"] = 126
    b["remaining_listed_id_count"] = 296
    b["completion_ratio"] = "126/422"
    b["completion_percent"] = 29.86
    fam=next(x for x in doc["families"] if x["id"]=="windows-security-auditing")
    assert (fam["denominator_count"],fam["encyclopedia_grade_count"],fam["remaining_count"]) == (423,110,313)
    fam["encyclopedia_grade_count"] = 120
    fam["remaining_count"] = 303
    dump(path,doc)
    spec=importlib.util.spec_from_file_location("snap",R/"tools/content/build_windows_security_coverage_snapshot.py")
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    snap=mod.build_snapshot()
    assert (snap["encyclopedia_grade_count"],snap["remaining_count"],snap["completion_ratio"],snap["completion_percent"]) == (120,303,"120/423",28.37)
    dump(R/"content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json",snap)


def update_tests(s: dict) -> None:
    p=R/"tests/phase51010/test_windows_security_coverage_snapshot.py"
    t=p.read_text(encoding="utf-8")
    for a,b in [("== 110","== 120"),("== 313","== 303"),("== \"110/423\"","== \"120/423\""),("== 26.0","== 28.37")]:
        t=t.replace(a,b)
    p.write_text(t,encoding="utf-8")
    p=R/"tests/phase51010/test_windows_security_auditing_4743_4752.py"
    t=p.read_text(encoding="utf-8")
    old='m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());assert m["windows_security_log_review_benchmark"]["completion_ratio"]=="116/422";f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert (f["encyclopedia_grade_count"],f["remaining_count"])==(110,313)'
    new='m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());assert int(m["windows_security_log_review_benchmark"]["completion_ratio"].split("/")[0])>=116;f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=110'
    assert old in t
    p.write_text(t.replace(old,new),encoding="utf-8")
    expected={eid:{str(x["version"]):len(x["fields"]) for x in s[eid]} for eid in IDS}
    test=f'''import json\nfrom pathlib import Path\nR=Path(__file__).resolve().parents[2];E={expected!r}\ndef bp():return {{str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}}\ndef test_versions():\n d=bp();assert all({{str(x["version"]):x["field_count"] for x in d[e]["overview"]["event_versions"]}}==E[e] for e in E);assert {{x["native_name"]:x for x in d["4756"]["fields"]}}["MembershipExpirationTime"]["versions"]==["1"] and {{x["native_name"]:x for x in d["4761"]["fields"]}}["MembershipExpirationTime"]["versions"]==["1"]\ndef test_semantics():\n d=bp();assert all(d[e]["overview"]["subcategory"]=="Audit Security Group Management" for e in ("4754","4755","4756","4757","4758"));assert all(d[e]["overview"]["subcategory"]=="Audit Distribution Group Management" for e in ("4753","4759","4760","4761","4762"))\ndef test_coverage():\n m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());assert m["windows_security_log_review_benchmark"]["completion_ratio"]=="126/422";f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert (f["encyclopedia_grade_count"],f["remaining_count"])==(120,303)\ndef test_binding():\n x=json.loads((R/"ingestion/inventories/windows-security-auditing-4753-4762-26100.telemetry.json").read_text())["scope_metadata"];assert (x["workflow_run_id"],x["artifact_id"],x["provider_event_version_definition_count"])==({RUN},{ART},12) and x["artifact_digest"]=={AD!r} and x["raw_artifact_sha256"]=={RAW!r}\n'''
    (R/"tests/phase51010/test_windows_security_auditing_4753_4762.py").write_text(test,encoding="utf-8")


def update_docs() -> None:
    p=R/"docs/windows-security-log-scope.md"
    t=p.read_text(encoding="utf-8")
    changes=[
        ("after the eleventh bounded Windows Security Log batch","after the twelfth bounded Windows Security Log batch"),
        ("`116/422` listed identities encyclopedia-grade (`27.49%`), `306` remaining","`126/422` listed identities encyclopedia-grade (`29.86%`), `296` remaining"),
        ("`4743`, `4744`, `4745`, `4746`, `4747`, `4748`, `4749`, `4750`, `4751`, `4752`","`4753`, `4754`, `4755`, `4756`, `4757`, `4758`, `4759`, `4760`, `4761`, `4762`"),
        ("`110/423` encyclopedia-grade with `313` provider-specific identities remaining","`120/423` encyclopedia-grade with `303` provider-specific identities remaining"),
    ]
    for old,new in changes:
        assert t.count(old)==1, old
        t=t.replace(old,new)
    p.write_text(t,encoding="utf-8")
    invp=R/"docs/releases/third-party-redistribution-inventory.json"
    inv=json.loads(invp.read_text(encoding="utf-8"))
    row=next(x for x in inv["entries"] if x["id"]=="microsoft-windows-security-documentation")
    additions=[*[f"content/encyclopedia/sources/microsoft-windows-security-event-{eid}.json" for eid in IDS],"ingestion/inventories/windows-security-auditing-4753-4762-26100.telemetry.json","content/encyclopedia/sources/microsoft-windows-security-auditing-provider-26100-4753-4762.json"]
    existing=[x.strip() for x in row.get("review_evidence","").split(" + ") if x.strip()]
    row["review_evidence"]=" + ".join(existing+[x for x in additions if x not in existing])
    dump(invp,inv)


def main() -> None:
    data=load_discovery(); s=shapes(data)
    dump(R/"ingestion/inventories/windows-security-auditing-4753-4762-26100.telemetry.json",build_inventory(s))
    write_sources(); promote_blueprints(s); update_coverage(); update_tests(s); update_docs()
    print("coverage=126/422 security_auditing=120/423 ids=10 versions=12")


if __name__ == "__main__":
    main()
