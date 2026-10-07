#!/usr/bin/env python3
from __future__ import annotations
import copy, hashlib, importlib.util, json, os, re
from pathlib import Path
from xml.etree import ElementTree as ET

R=Path(__file__).resolve().parents[1]
IDS=['4763','4764','4765','4766','4767','4770','4772','4773','4774','4775']
RUN=37683880855; ART=11509498136
AD='sha256:b5e5abe42a8229c381d31ad1673dfc639e47936294c6b847f7baf1d08897eeee'
RAW='sha256-dbda8672f69d06561e3a714f70f25a558f82ccaafd2e08d30da3aeb46969f8a9'
SID='atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch13'
SV='windows-server-2025-build-26100-security-auditing-batch13'
NOW='2026-10-07T20:42:00Z'
APP='https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/Appendix-L--Events-to-Monitor'
META={
'4763':('A security-disabled universal group was deleted','Account Management','Audit Distribution Group Management','Success'),
'4764':("A group's type was changed",'Account Management','Audit Security Group Management','Success'),
'4765':('SID History was added to an account','Account Management','Audit User Account Management','Success'),
'4766':('An attempt to add SID History to an account failed','Account Management','Audit User Account Management','Failure'),
'4767':('A user account was unlocked','Account Management','Audit User Account Management','Success'),
'4770':('A Kerberos service ticket was renewed','Account Logon','Audit Kerberos Service Ticket Operations','Success'),
'4772':('A Kerberos authentication ticket request failed','Account Logon','Audit Kerberos Authentication Service','Defined / not generated'),
'4773':('A Kerberos service ticket request failed','Account Logon','Audit Kerberos Service Ticket Operations','Defined / not generated'),
'4774':('An account was mapped for logon','Account Logon','Audit Credential Validation','Success/Failure'),
'4775':('An account could not be mapped for logon','Account Logon','Audit Credential Validation','Failure'),
}
MARK={'4763':'S','4764':'S','4765':'S','4766':'F','4767':'S','4770':'S','4772':'F','4773':'F','4774':'S, F','4775':'F'}
EXPECTED={'4763':{0:8},'4764':{0:9},'4765':{0:11},'4766':{0:8},'4767':{0:7},'4770':{0:8,1:10},'4772':{0:7},'4773':{0:7},'4774':{0:3},'4775':{0:2}}
CUSTOM={
'GroupTypeChange':('Change Type','group-type-change','Provider-rendered description of the group type or scope transition.'),
'SourceUserName':('Source Account','source-user-name','Account name of the source identity involved in the operation.'),
'SourceSid':('Source Account','source-sid','Security identifier of the source identity.'),
'SidList':('Additional Information','sid-list','Provider-rendered SID history values added to the target account.'),
'RequestTicketHash':('Additional Information','request-ticket-hash','Provider-rendered hash associated with the Kerberos ticket request.'),
'ResponseTicketHash':('Additional Information','response-ticket-hash','Provider-rendered hash associated with the Kerberos ticket response.'),
'MappingBy':('Mapping','mapping-by','Provider-rendered authentication or mapping mechanism.'),
'ClientUserName':('Mapping','client-user-name','Provider-rendered client account identity used for mapping.'),
'MappedName':('Mapping','mapped-name','Provider-rendered account name resulting from mapping.'),
}

def dump(p,v): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
def digest(v):
 x=copy.deepcopy(v);x.pop('digest',None);b=json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode();return 'sha256-'+hashlib.sha256(b).hexdigest()
def src_url(e):
 return ('https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4767' if e=='4767' else f'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-{e}')
def raw():
 p=Path(os.environ['ATLAS_DISCOVERY_JSON']);b=p.read_bytes();assert 'sha256-'+hashlib.sha256(b).hexdigest()==RAW;d=json.loads(b.decode('utf-8-sig'));assert [str(x) for x in d['requested_ids']]==IDS and d['unique_event_id_count']==10 and d['event_version_definition_count']==11 and str(d['runner_os']['OsBuildNumber'])=='26100';return d
def shapes(d):
 ns={'e':'http://schemas.microsoft.com/win/2004/08/events'};o={e:[] for e in IDS}
 for v in d['events']:
  root=ET.fromstring(v['template']);f=[(x.attrib['name'],x.attrib.get('inType'),x.attrib.get('outType')) for x in root.findall('e:data',ns)];o[str(v['id'])].append({'version':int(v['version']),'level':v['level'],'fields':f})
 assert {e:{x['version']:len(x['fields']) for x in rows} for e,rows in o.items()}==EXPECTED
 byv={x['version']:[f[0] for f in x['fields']] for x in o['4770']};assert byv[1]==byv[0]+['RequestTicketHash','ResponseTicketHash'];return o
def source_record(i,key,title,urls,secondary=False,notes='Microsoft semantic authority; provider structural authority.'):
 return {'schema_version':'1.0.0','record_kind':'source','id':i,'record_revision':1,'created_at':NOW,'updated_at':NOW,'curation_status':'validated','namespace':'atlas.source','canonical_key':key,'title':title,'publisher':'Monterey Technology Group, Inc.' if secondary else 'Microsoft','source_class':'tier-c-secondary-research' if secondary else 'tier-a-authoritative','canonical_urls':urls,'official_status':'secondary-reference' if secondary else 'official','license':{'status':'restricted' if secondary else 'unknown'},'redistribution':{'policy':'prohibited' if secondary else 'restricted','notes':'External Quick Detail / coverage benchmark only; no substantial page prose is packaged.' if secondary else 'ATLAS stores independently authored normalized facts and source locators; substantial Microsoft documentation prose is not redistributed.'},'freshness_policy':{'expected_update_cadence':'web-reference' if secondary else 'documentation-maintained','stale_after_days':90 if secondary else 180},'change_detection_policy':{'strategy':'manual' if secondary else 'content-diff','notes':'Coverage/Quick Detail only; no bulk ingestion.' if secondary else notes}}
def inventory(s):
 q=[]
 for e in IDS:q.append({'event_id':e,'versions':[{'version':x['version'],'field_count':len(x['fields']),'level':x['level'],'fields':[{'name':n,'in_type':i,'out_type':u} for n,i,u in x['fields']]} for x in s[e]]})
 d={'ingestion_contract_version':'1.0.0','inventory_contract_version':'1.0.0','inventory_id':'atlas:inventory:atlas.ingestion:windows-security-auditing-batch13-26100','inventory_kind':'telemetry','declared_scope':'Microsoft-Windows-Security-Auditing Event IDs 4763-4767, 4770, 4772-4775 / Security / Windows Server 2025 build 26100','source_ids':[SID],'inventory_method':'provider-runtime-metadata','inventory_source_version':SV,'expected_identity_count':10,'identity_dimensions':['provider','channel','native-id','product','platform','version'],'scope_metadata':{'provider':'Microsoft-Windows-Security-Auditing','channel':'Security','product':'Windows Server 2025 Datacenter','platform':'Windows','windows_build':'26100','architecture':'64-bit','workflow_run_id':RUN,'artifact_id':ART,'artifact_digest':AD,'raw_artifact_sha256':RAW,'provider_event_version_definition_count':11,'provider_unique_event_id_count':10,'expected_identities':q,'completeness_semantics':'bounded structural evidence for ten sparse identities inside the frozen 423-ID denominator; eleven version definitions preserved; already-covered 4768, 4769 and 4771 intentionally excluded'},'guardrails':{'max_unexplained_shrink_percent':0,'max_unexplained_growth_percent':0}};d['digest']=digest(d);return d
def section(e,n):
 if e in ('4770','4772','4773'):
  if n in ('TargetUserName','TargetDomainName'):return 'Account Information'
  if n in ('ServiceName','ServiceSid'):return 'Service Information'
  if n in ('IpAddress','IpPort'):return 'Network Information'
  return 'Additional Information'
 if e in ('4774','4775'):return 'Mapping'
 if n.startswith('Subject'):return 'Subject'
 if n.startswith('Source'):return 'Source Account'
 if n in ('PrivilegeList','SidList','GroupTypeChange'):return CUSTOM.get(n,('Additional Information','',''))[0]
 return 'Target Account'
def key(n): return re.sub(r'(?<!^)(?=[A-Z])','-',n).lower()
def meaning(n):
 common={'TargetUserName':'Name of the target account, group or Kerberos principal.','TargetDomainName':'Domain or realm context associated with the target identity.','TargetSid':'Security identifier of the target identity when the provider supplies one.','SubjectUserSid':'Security identifier of the subject account.','SubjectUserName':'Account name of the subject.','SubjectDomainName':'Domain or computer associated with the subject.','SubjectLogonId':'Provider-rendered logon-session identifier for subject correlation.','PrivilegeList':'Provider-rendered privileges associated with the operation.','ServiceName':'Kerberos service principal or service name.','ServiceSid':'Security identifier of the target service when supplied.','TicketOptions':'Provider-rendered Kerberos ticket option flags.','TicketEncryptionType':'Provider-rendered Kerberos ticket encryption type.','FailureCode':'Provider-rendered Kerberos failure code.','IpAddress':'Provider-rendered client IP address.','IpPort':'Provider-rendered client source port.'}
 return CUSTOM[n][2] if n in CUSTOM else common.get(n,'Provider-rendered field preserved without inventing undocumented semantics.')
def promote(s):
 p=R/'content/encyclopedia/approved-exemplars.json';d=json.loads(p.read_text());assert not any(str(x.get('native_event_id')) in IDS and x.get('namespace')=='microsoft.windows.security' for x in d['events']);insert=next(i for i,x in enumerate(d['events']) if str(x.get('native_event_id'))=='4762' and x.get('namespace')=='microsoft.windows.security')+1;new=[]
 for e in IDS:
  title,cat,sub,etype=META[e];vers=[];names={}
  for row in s[e]:
   vers.append({'version':str(row['version']),'generation':'Documented and/or provider-validated shape','field_count':len(row['fields']),'notes':'Controlled Windows Server 2025 provider structural shape.'})
   for n,it,ot in row['fields']:names.setdefault(n,{'in':it,'versions':[]})['versions'].append(str(row['version']))
  fields=[{'key':CUSTOM.get(n,(None,key(n),None))[1] if n in CUSTOM else key(n),'section':section(e,n),'native_name':n,'type':v['in'].split(':',1)[-1],'meaning':meaning(n),'versions':v['versions']} for n,v in names.items()]
  summary=f'Records {title.lower()} while preserving provider-rendered identity and operation context.'
  if e=='4770':summary+=' Version 1 adds RequestTicketHash and ResponseTicketHash and remains distinct.'
  if e in ('4772','4773'):summary+=' Microsoft documents this identity as defined but not generated by the operating system; the corresponding modern failure is recorded under another Kerberos event.'
  req=[f'Enable {sub} auditing appropriate to the documented success/failure outcome.','Preserve exact provider version and native context.']
  new.append({'id':f'atlas:event:microsoft.windows.security:{e}','namespace':'microsoft.windows.security','canonical_key':e,'title':f'Windows Security Event {e} — {title}','provider':'Microsoft-Windows-Security-Auditing','channel':'Security','product':'Windows Security Auditing','platform':'Windows','native_event_id':e,'aliases':[e,f'Event ID {e}',f'Windows {e}',title],'lifecycle':'current','source_id':f'atlas:source:atlas.source:microsoft-windows-security-event-{e}','source_version':f'event-{e}-provider-bound-doc','source_url':src_url(e),'source_locator':f'{e}({MARK[e]}): {title}','structural_source':{'source_id':SID,'source_version':SV,'locator':f"Microsoft-Windows-Security-Auditing / Security / Event ID {e} / versions {','.join(str(x['version']) for x in s[e])}"},'external_reference':{'source_id':f'atlas:source:atlas.source:ultimate-windows-security-event-{e}','url':f'https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={e}','role':'PRIMARY_EXTERNAL_QUICK_DETAIL_REFERENCE','redistribution':'source-link-and-coverage-benchmark-only'},'overview':{'summary':summary,'category':cat,'subcategory':sub,'event_type':etype,'provider_level':'Informational','event_versions':vers},'collection':{'requirements':req,'interpretation_note':'Interpret in documented account, group, Kerberos or credential-validation context and validate against expected administrative/authentication activity.'},'correlations':[],'analysis':['Validate the event against expected identity, authentication and change-control activity before assigning malicious intent.'],'fields':fields})
 d['events'][insert:insert]=new;dump(p,d)
def sources():
 sd=R/'content/encyclopedia/sources';provider=source_record(SID,'microsoft-windows-security-auditing-provider-26100-batch13','Microsoft-Windows-Security-Auditing provider metadata — build 26100 — Batch 13',['https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log'],False,f'Workflow {RUN}; artifact {ART}; {AD}; {RAW}.');provider['change_detection_policy']={'strategy':'checksum','notes':f'Workflow {RUN}; artifact {ART}; {AD}; {RAW}.'};dump(sd/'microsoft-windows-security-auditing-provider-26100-batch13.json',provider)
 for e in IDS:
  dump(sd/f'microsoft-windows-security-event-{e}.json',source_record(f'atlas:source:atlas.source:microsoft-windows-security-event-{e}',f'microsoft-windows-security-event-{e}',f'Microsoft Windows Security Event {e}',[src_url(e),APP]))
  dump(sd/f'ultimate-windows-security-event-{e}.json',source_record(f'atlas:source:atlas.source:ultimate-windows-security-event-{e}',f'ultimate-windows-security-event-{e}',f'Ultimate Windows Security Event {e}',[f'https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={e}'],True))
def coverage():
 p=R/'content/encyclopedia/coverage-manifest.json';d=json.loads(p.read_text());b=d['windows_security_log_review_benchmark'];assert b['completion_ratio']=='126/422';assert not (set(IDS)&set(map(str,b['covered_event_ids'])));b['covered_event_ids']=sorted(set(map(str,b['covered_event_ids']))|set(IDS),key=int);b.update({'encyclopedia_grade_listed_id_count':136,'remaining_listed_id_count':286,'completion_ratio':'136/422','completion_percent':32.23});f=next(x for x in d['families'] if x['id']=='windows-security-auditing');assert (f['denominator_count'],f['encyclopedia_grade_count'],f['remaining_count'])==(423,120,303);f.update({'encyclopedia_grade_count':130,'remaining_count':293});dump(p,d);spec=importlib.util.spec_from_file_location('snap',R/'tools/content/build_windows_security_coverage_snapshot.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);z=m.build_snapshot();assert (z['encyclopedia_grade_count'],z['remaining_count'],z['completion_ratio'],z['completion_percent'])==(130,293,'130/423',30.73);dump(R/'content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json',z)
def tests():
 p=R/'tests/phase51010/test_windows_security_coverage_snapshot.py';t=p.read_text();
 for a,b in [('== 120','== 130'),('== 303','== 293'),('== "120/423"','== "130/423"'),('== 28.37','== 30.73')]:t=t.replace(a,b)
 p.write_text(t)
 p=R/'tests/phase51010/test_windows_security_auditing_4753_4762.py';t=p.read_text();old='m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());assert m["windows_security_log_review_benchmark"]["completion_ratio"]=="126/422";f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert (f["encyclopedia_grade_count"],f["remaining_count"])==(120,303)';new='m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());assert int(m["windows_security_log_review_benchmark"]["completion_ratio"].split("/")[0])>=126;f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=120';assert old in t;p.write_text(t.replace(old,new))
 body=f'''import json\nfrom pathlib import Path\nR=Path(__file__).resolve().parents[2];IDS={IDS!r};E={{{', '.join(repr(e)+':'+repr({str(k):v for k,v in EXPECTED[e].items()}) for e in IDS)}}}\ndef bp():return {{str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}}\ndef test_versions():\n d=bp();assert all({{str(x["version"]):x["field_count"] for x in d[e]["overview"]["event_versions"]}}==E[e] for e in IDS);f={{x["native_name"]:x for x in d["4770"]["fields"]}};assert f["RequestTicketHash"]["versions"]==["1"] and f["ResponseTicketHash"]["versions"]==["1"]\ndef test_semantics():\n d=bp();assert d["4764"]["overview"]["subcategory"]=="Audit Security Group Management";assert d["4765"]["overview"]["subcategory"]=="Audit User Account Management";assert d["4770"]["overview"]["subcategory"]=="Audit Kerberos Service Ticket Operations";assert d["4772"]["overview"]["event_type"]=="Defined / not generated" and d["4773"]["overview"]["event_type"]=="Defined / not generated";assert d["4774"]["overview"]["event_type"]=="Success/Failure"\ndef test_coverage():\n m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());assert m["windows_security_log_review_benchmark"]["completion_ratio"]=="136/422";f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert (f["encyclopedia_grade_count"],f["remaining_count"])==(130,293)\ndef test_binding():\n x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch13-26100.telemetry.json").read_text())["scope_metadata"];assert (x["workflow_run_id"],x["artifact_id"],x["provider_event_version_definition_count"])==({RUN},{ART},11) and x["artifact_digest"]=={AD!r} and x["raw_artifact_sha256"]=={RAW!r}\n''';(R/'tests/phase51010/test_windows_security_auditing_batch13.py').write_text(body)
def docs():
 p=R/'docs/windows-security-log-scope.md';t=p.read_text();changes=[('after the twelfth bounded Windows Security Log batch','after the thirteenth bounded Windows Security Log batch'),('`126/422` listed identities encyclopedia-grade (`29.86%`), `296` remaining','`136/422` listed identities encyclopedia-grade (`32.23%`), `286` remaining'),('`4753`, `4754`, `4755`, `4756`, `4757`, `4758`, `4759`, `4760`, `4761`, `4762`','`4763`, `4764`, `4765`, `4766`, `4767`, `4770`, `4772`, `4773`, `4774`, `4775`'),('`120/423` encyclopedia-grade with `303` provider-specific identities remaining','`130/423` encyclopedia-grade with `293` provider-specific identities remaining')]
 for a,b in changes:assert t.count(a)==1,a;t=t.replace(a,b)
 p.write_text(t);p=R/'docs/releases/third-party-redistribution-inventory.json';d=json.loads(p.read_text());r=next(x for x in d['entries'] if x['id']=='microsoft-windows-security-documentation');A=[*[f'content/encyclopedia/sources/microsoft-windows-security-event-{e}.json' for e in IDS],'ingestion/inventories/windows-security-auditing-batch13-26100.telemetry.json','content/encyclopedia/sources/microsoft-windows-security-auditing-provider-26100-batch13.json'];q=[x.strip() for x in r.get('review_evidence','').split(' + ') if x.strip()];r['review_evidence']=' + '.join(q+[x for x in A if x not in q]);dump(p,d)
def main():
 d=raw();s=shapes(d);dump(R/'ingestion/inventories/windows-security-auditing-batch13-26100.telemetry.json',inventory(s));sources();promote(s);coverage();tests();docs();print('batch13=PASS uws=136/422 security=130/423')
if __name__=='__main__':main()
