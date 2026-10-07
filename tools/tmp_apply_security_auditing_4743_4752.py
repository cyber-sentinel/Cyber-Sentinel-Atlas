#!/usr/bin/env python3
import hashlib,importlib.util,json,os,subprocess,tempfile
from pathlib import Path
from xml.etree import ElementTree as ET
R=Path(__file__).resolve().parents[1]
IDS=['4743','4744','4745','4746','4747','4748','4749','4750','4751','4752']
RUN=37664692346; ART=11502400552
AD='sha256:729297c7038391b9d7f0e2e81869a5615a2f1e8f12bd7e0fc8da98edacee9b28'
RAW='sha256-79439457a025d2acfa7ef9672b6fc1c59e3a1ce596d610d10ec896df65d1c9d0'
SID='atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4743-4752'
SV='windows-server-2025-build-26100-security-auditing-4743-4752'
S={
'4743':('A computer account was deleted','Audit Computer Account Management'),
'4744':('A security-disabled local group was created','Audit Distribution Group Management'),
'4745':('A security-disabled local group was changed','Audit Distribution Group Management'),
'4746':('A member was added to a security-disabled local group','Audit Distribution Group Management'),
'4747':('A member was removed from a security-disabled local group','Audit Distribution Group Management'),
'4748':('A security-disabled local group was deleted','Audit Distribution Group Management'),
'4749':('A security-disabled global group was created','Audit Distribution Group Management'),
'4750':('A security-disabled global group was changed','Audit Distribution Group Management'),
'4751':('A member was added to a security-disabled global group','Audit Distribution Group Management'),
'4752':('A member was removed from a security-disabled global group','Audit Distribution Group Management')}

def load_b10():
 t=subprocess.check_output(['git','show','fd1eccb830be836addb615fafcb2c7ccdb50ce46:tools/tmp_apply_security_auditing_4731_4742.py'],text=True)
 p=Path(tempfile.mkdtemp())/'b10.py';p.write_text(t);s=importlib.util.spec_from_file_location('b10',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def meta():
 d={}; dist='https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-distribution-group-management'; comp='https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4743'
 for e,(title,sub) in S.items():
  isdist=e!='4743'; ver=' Version 1 adds MembershipExpirationTime and remains distinct.' if e in {'4746','4751'} else ''
  d[e]={'title':title,'category':'Account Management','subcategory':sub,'event_type':'Success','marker':'S','summary':f'Records {title.lower()} while preserving provider-rendered subject, target and directory-change context.'+ver,'requirements':[f'Enable {sub} success auditing.']+(['Collect on domain controllers; this subcategory is generated there.'] if isdist else ['Collect Security auditing from domain controllers where computer-account management occurs.']),'interpretation':('Unexpected computer-account deletion can indicate unauthorized directory administration or destructive identity activity.' if e=='4743' else 'Unexpected distribution-group changes can indicate unauthorized directory administration or manipulation of business communication groups.'),'analysis':['Validate the actor, target object and change against approved identity/directory administration records.'],'correlations':[],'source_version':f'event-{e}-provider-bound-doc','url':dist if isdist else comp}
 return d

def raw():
 p=Path(os.environ['ATLAS_DISCOVERY_JSON']);b=p.read_bytes();assert 'sha256-'+hashlib.sha256(b).hexdigest()==RAW
 d=json.loads(b.decode('utf-8-sig'));assert d['schema']=='atlas.windows-provider-structural-discovery/v1' and d['structural_only'] is True;assert d['unique_event_id_count']==10 and d['event_version_definition_count']==12 and [str(x) for x in d['requested_ids']]==IDS;assert str(d['runner_os']['OsBuildNumber'])=='26100' and d['provider']=='Microsoft-Windows-Security-Auditing';return d

def shapes(d):
 ns={'e':'http://schemas.microsoft.com/win/2004/08/events'};o={e:[] for e in IDS}
 for v in d['events']:
  x=ET.fromstring(v['template']);f=[(z.attrib['name'],z.attrib.get('inType'),z.attrib.get('outType')) for z in x.findall('e:data',ns)];o[str(v['id'])].append({'version':int(v['version']),'level':v['level'],'fields':f})
 w={'4743':{0:12},'4744':{0:10},'4745':{0:9},'4746':{0:10,1:11},'4747':{0:10},'4748':{0:12},'4749':{0:10},'4750':{0:9},'4751':{0:10,1:11},'4752':{0:10}}
 assert {e:{x['version']:len(x['fields']) for x in a} for e,a in o.items()}==w
 for e in ('4746','4751'):
  b={x['version']:[y[0] for y in x['fields']] for x in o[e]};assert b[1]==b[0]+['MembershipExpirationTime']
 return o

def inv(base,s):
 q=[{'event_id':e,'versions':[{'version':x['version'],'field_count':len(x['fields']),'level':x['level'],'fields':[{'name':n,'in_type':i,'out_type':u} for n,i,u in x['fields']]} for x in s[e]]} for e in IDS]
 d={'ingestion_contract_version':'1.0.0','inventory_contract_version':'1.0.0','inventory_id':'atlas:inventory:atlas.ingestion:windows-security-auditing-4743-4752-26100','inventory_kind':'telemetry','declared_scope':'Microsoft-Windows-Security-Auditing Event IDs 4743-4752 / Security / Windows Server 2025 build 26100','source_ids':[SID],'inventory_method':'provider-runtime-metadata','inventory_source_version':SV,'expected_identity_count':10,'identity_dimensions':['provider','channel','native-id','product','platform','version'],'scope_metadata':{'provider':'Microsoft-Windows-Security-Auditing','channel':'Security','product':'Windows Server 2025 Datacenter','platform':'Windows','windows_build':'26100','architecture':'64-bit','workflow_run_id':RUN,'artifact_id':ART,'artifact_digest':AD,'raw_artifact_sha256':RAW,'provider_event_version_definition_count':12,'provider_unique_event_id_count':10,'expected_identities':q,'completeness_semantics':'bounded structural evidence for ten identities inside the frozen 423-ID denominator; twelve version definitions preserved'},'guardrails':{'max_unexplained_shrink_percent':0,'max_unexplained_growth_percent':0}}
 d['digest']=base.digest_without_field(d);return d

def state(base):
 p=R/'content/encyclopedia/coverage-manifest.json';d=json.loads(p.read_text());b=d['windows_security_log_review_benchmark'];assert b['completion_ratio']=='106/422';b.update({'covered_event_ids':sorted(set(b['covered_event_ids'])|set(IDS),key=int),'encyclopedia_grade_listed_id_count':116,'remaining_listed_id_count':306,'completion_ratio':'116/422','completion_percent':27.49});f=next(x for x in d['families'] if x['id']=='windows-security-auditing');assert (f['encyclopedia_grade_count'],f['remaining_count'])==(100,323);f.update({'encyclopedia_grade_count':110,'remaining_count':313});base.dump(p,d)
 s=importlib.util.spec_from_file_location('s',R/'tools/content/build_windows_security_coverage_snapshot.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);z=m.build_snapshot();assert (z['encyclopedia_grade_count'],z['remaining_count'],z['completion_ratio'],z['completion_percent'])==(110,313,'110/423',26.0);(R/'content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json').write_text(json.dumps(z,sort_keys=True,indent=2)+'\n')

def sources(base,M):
 sd=R/'content/encyclopedia/sources';base.dump(sd/'microsoft-windows-security-auditing-provider-26100-4743-4752.json',base.source_record(SID,'microsoft-windows-security-auditing-provider-26100-4743-4752','Microsoft-Windows-Security-Auditing provider metadata — build 26100 — Batch 11',['https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log'],change={'strategy':'checksum','notes':f'Workflow {RUN}; artifact {ART}; {AD}; {RAW}.'}));ap='https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/Appendix-L--Events-to-Monitor';pol='https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration'
 for e in IDS:
  urls=[M[e]['url'],ap,pol];base.dump(sd/f'microsoft-windows-security-event-{e}.json',base.source_record(f'atlas:source:atlas.source:microsoft-windows-security-event-{e}',f'microsoft-windows-security-event-{e}',f'Microsoft Windows Security Event {e}',urls,change={'strategy':'content-diff','notes':'Microsoft semantic authority; provider structural authority.'}));base.dump(sd/f'ultimate-windows-security-event-{e}.json',base.source_record(f'atlas:source:atlas.source:ultimate-windows-security-event-{e}',f'ultimate-windows-security-event-{e}',f'Ultimate Windows Security Event {e}',[f'https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={e}'],secondary=True,change={'strategy':'manual','notes':'Coverage/Quick Detail only; no bulk ingestion.'}))

def tests(s):
 p=R/'tests/phase51010/test_windows_security_coverage_snapshot.py';t=p.read_text();X=[('snapshot["encyclopedia_grade_count"] == 100','snapshot["encyclopedia_grade_count"] == 110'),('snapshot["remaining_count"] == 323','snapshot["remaining_count"] == 313'),('snapshot["completion_ratio"] == "100/423"','snapshot["completion_ratio"] == "110/423"'),('snapshot["completion_percent"] == 23.64','snapshot["completion_percent"] == 26.0')]
 for a,b in X: assert a in t;t=t.replace(a,b)
 p.write_text(t)
 p=R/'tests/phase51010/test_windows_security_auditing_4731_4742.py';t=p.read_text();a='assert m["windows_security_log_review_benchmark"]["completion_ratio"]=="106/422";f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert (f["encyclopedia_grade_count"],f["remaining_count"])==(100,323)';b='assert m["windows_security_log_review_benchmark"]["encyclopedia_grade_listed_id_count"]>=106;f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=100 and f["remaining_count"]<=323';assert a in t;p.write_text(t.replace(a,b))
 E={e:{str(x['version']):len(x['fields']) for x in s[e]} for e in IDS};(R/'tests/phase51010/test_windows_security_auditing_4743_4752.py').write_text(f'''import json\nfrom pathlib import Path\nR=Path(__file__).resolve().parents[2];E={E!r}\ndef bp():return {{str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}}\ndef test_versions():\n d=bp();assert all({{str(x["version"]):x["field_count"] for x in d[e]["overview"]["event_versions"]}}==E[e] for e in E);assert all({{x["native_name"]:x for x in d[e]["fields"]}}["MembershipExpirationTime"]["versions"]==["1"] for e in ("4746","4751"))\ndef test_semantics():\n d=bp();assert d["4743"]["overview"]["subcategory"]=="Audit Computer Account Management";assert all(d[e]["overview"]["subcategory"]=="Audit Distribution Group Management" for e in E if e!="4743")\ndef test_coverage():\n m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());b=m["windows_security_log_review_benchmark"];assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(116,306,"116/422",27.49);assert set(E).issubset(set(b["covered_event_ids"]));f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert (f["encyclopedia_grade_count"],f["remaining_count"])==(110,313)\ndef test_binding():\n x=json.loads((R/"ingestion/inventories/windows-security-auditing-4743-4752-26100.telemetry.json").read_text())["scope_metadata"];assert (x["workflow_run_id"],x["artifact_id"],x["provider_event_version_definition_count"])==({RUN},{ART},12) and x["artifact_digest"]=={AD!r} and x["raw_artifact_sha256"]=={RAW!r}\n''')

def docs(base):
 p=R/'docs/windows-security-log-scope.md';t=p.read_text();X=[('after the tenth bounded Windows Security Log batch','after the eleventh bounded Windows Security Log batch'),('`106/422` listed identities encyclopedia-grade (`25.12%`), `316` remaining','`116/422` listed identities encyclopedia-grade (`27.49%`), `306` remaining'),('`4731`, `4732`, `4733`, `4734`, `4735`, `4737`, `4738`, `4739`, `4741`, `4742`','`4743`, `4744`, `4745`, `4746`, `4747`, `4748`, `4749`, `4750`, `4751`, `4752`'),('`100/423` encyclopedia-grade with `323` provider-specific identities remaining','`110/423` encyclopedia-grade with `313` provider-specific identities remaining')]
 for a,b in X: assert t.count(a)==1;t=t.replace(a,b)
 p.write_text(t)
 p=R/'docs/releases/third-party-redistribution-inventory.json';d=json.loads(p.read_text());r=next(x for x in d['entries'] if x['id']=='microsoft-windows-security-documentation');A=[*[f'content/encyclopedia/sources/microsoft-windows-security-event-{e}.json' for e in IDS],'ingestion/inventories/windows-security-auditing-4743-4752-26100.telemetry.json','content/encyclopedia/sources/microsoft-windows-security-auditing-provider-26100-4743-4752.json'];q=[x.strip() for x in r.get('review_evidence','').split(' + ') if x.strip()];r['review_evidence']=' + '.join(q+[x for x in A if x not in q]);base.dump(p,d)

def main():
 b10=load_b10();m=b10.prev();M=meta();ex=dict(m.EXTRA_FIELD_DETAILS)
 for n,v in {'ROOT':R,'NOW':'2026-10-07T18:20:00Z','IDS':IDS,'RUN_ID':RUN,'ARTIFACT_ID':ART,'ARTIFACT_DIGEST':AD,'RAW_SHA256':RAW,'STRUCTURAL_ID':SID,'STRUCTURAL_VERSION':SV,'META':M,'EXTRA_FIELD_DETAILS':ex}.items():setattr(m,n,v)
 b8=m.load_previous();b7=b8.load_previous();b6=b7.load_impl();base=b6.load_base();b6.configure_base(base);d=raw();s=shapes(d);base.dump(R/'ingestion/inventories/windows-security-auditing-4743-4752-26100.telemetry.json',inv(base,s));sources(base,M);base.update_blueprint(s);state(base);tests(s);docs(base);print('coverage=116/422 security_auditing=110/423')
if __name__=='__main__':main()
