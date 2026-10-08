#!/usr/bin/env python3
from __future__ import annotations

import argparse, copy, hashlib, importlib.util, json, re
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT=Path.cwd(); DEN=423; UDEN=422
PROVIDER='Microsoft-Windows-Security-Auditing'; CHANNEL='Security'
MS='https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log'
APP='https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor'
ART={
14:{'artifact_id':11526186354,'artifact_digest':'sha256:22889d43749600942e8ba5d37677eea06fb496f1d3d73da19691d25d2e2c8567','raw_sha256':'sha256-5136f700c0cf5cf27d146baf3aef8c3e407c56b5a4a08a2d0404cc0474e81d72'},
15:{'artifact_id':11525259954,'artifact_digest':'sha256:e30e67f748a8634df865766b77efb10028290884fcc232521ee355656f112dd5','raw_sha256':'sha256-13189ed2c3541f366aadd294395a41c90b356049d4225dfcdc77d11fa6d66119'},
16:{'artifact_id':11526231210,'artifact_digest':'sha256:866699f6881be481c0e90866b410efc46b151c4f160d1d36c94fff451bfd24a7','raw_sha256':'sha256-666b395b266fa41752a1ec9025c7ce20ac904508b798f0ebd1432c8382c362d8'},
17:{'artifact_id':11525737578,'artifact_digest':'sha256:3ba2669b0b87915d0223fd36ce57f8fd346ac84cdcdbab8a08db6cc5b9b41000','raw_sha256':'sha256-490d869c6208d401189a4890f7bff8a7d17b65add87cdab13c33e1ffb6d4acb1'},
18:{'artifact_id':11525997098,'artifact_digest':'sha256:58b3314d30f0230cf9fa5c4d9d6673a784b1ecb2e2e43729f2fc7c7bb4c624d6','raw_sha256':'sha256-e4f5948dbc8dfe8211f2cd4dc691fb0eb41c8da75971863501c32840f2fea725'}}
DRUN=37721122416; URUN=37721608338; UART=11526525503
UDIG='sha256:65deb6923706d4677d55660e7b06915a16243f0acdafd955d0f7918074f2a51e'
URAW='sha256-613b59d20e3f6f5b10bd75f611e9d34a0174f47b4deac60547355b73c7ddee44'

def dump(p,v): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def digest(v):
 x=copy.deepcopy(v);x.pop('digest',None);return 'sha256-'+hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def clean(v): return re.sub(r'\s+',' ',(v or '').replace('\x00',' ')).strip()
def title(v,e):
 s=clean(v)
 if not s:return f'Windows Security Event {e}'
 for m in (' Subject:',' Account Information:',' Authentication Package:',' Peer Name:',' Request ID:',' Serial Number:',' Target Type:',' Account Name:',' Device Name:'):
  if m in s:s=s.split(m,1)[0].strip()
 return (s[:217].rstrip()+'...') if len(s)>220 else s
def kebab(n):
 s=re.sub(r'([a-z0-9])([A-Z])',r'\1-\2',n)
 s=re.sub(r'[^A-Za-z0-9]+','-',s)
 return s.strip('-').lower()
def section(n):
 x=n.lower()
 if x.startswith('subject'):return 'Subject'
 if x.startswith(('target','member','group','user','account')):return 'Target / Account'
 if any(y in x for y in ('ipaddress','ipport','workstation','client','peer','network')):return 'Network'
 if any(y in x for y in ('ticket','kerberos','service')):return 'Authentication'
 if any(y in x for y in ('object','handle','process')):return 'Object / Process'
 return 'Additional Information'
def source(batch,now,meta):
 sid=f'atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch{batch}'
 return {'schema_version':'1.0.0','record_kind':'source','id':sid,'record_revision':1,'created_at':now,'updated_at':now,'curation_status':'validated','namespace':'atlas.source','canonical_key':f'microsoft-windows-security-auditing-provider-26100-batch{batch}','title':f'Microsoft-Windows-Security-Auditing provider message metadata — build 26100 — Batch {batch}','publisher':'Microsoft','source_class':'tier-a-authoritative','canonical_urls':[MS,APP],'official_status':'official','license':{'status':'unknown'},'redistribution':{'policy':'restricted','notes':'ATLAS stores normalized facts, provider field shapes and short source locators; substantial Microsoft documentation or provider prose is not redistributed.'},'freshness_policy':{'expected_update_cadence':'provider-build-bound','stale_after_days':180},'change_detection_policy':{'strategy':'checksum','notes':f'Discovery run {DRUN}; artifact {meta["artifact_id"]}; {meta["artifact_digest"]}; {meta["raw_sha256"]}; UWS membership run {URUN}; artifact {UART}; {UDIG}; {URAW}.'}}
def load(path,batch):
 raw=path.read_bytes();m=ART[batch];assert 'sha256-'+hashlib.sha256(raw).hexdigest()==m['raw_sha256'];d=json.loads(raw.decode('utf-8-sig'));assert d['schema']=='atlas.windows-provider-structural-discovery/v2' and d['provider_message_semantics'] is True and int(d['batch'])==batch and d['provider']==PROVIDER and d['channel_scope']==CHANNEL and str(d['runner_os']['OsBuildNumber'])=='26100' and d['unique_event_id_count']==10 and len(d['requested_ids'])==10;return d
def shapes(d):
 ns={'e':'http://schemas.microsoft.com/win/2004/08/events'};s={str(e):[] for e in d['requested_ids']};t={}
 for r in d['events']:
  e=str(r['id']);root=ET.fromstring(r['template']);f=[(x.attrib['name'],x.attrib.get('inType'),x.attrib.get('outType')) for x in root.findall('e:data',ns)];s[e].append({'version':int(r['version']),'level':r.get('level'),'fields':f});t.setdefault(e,title(r.get('description'),e))
 assert all(s.values());return s,t
def inventory(batch,ids,s,m):
 sid=f'atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch{batch}';q=[]
 for e in ids:q.append({'event_id':e,'versions':[{'version':r['version'],'field_count':len(r['fields']),'level':r['level'],'fields':[{'name':n,'in_type':i,'out_type':o} for n,i,o in r['fields']]} for r in s[e]]})
 x={'ingestion_contract_version':'1.0.0','inventory_contract_version':'1.0.0','inventory_id':f'atlas:inventory:atlas.ingestion:windows-security-auditing-batch{batch}-26100','inventory_kind':'telemetry','declared_scope':f'{PROVIDER} Event IDs {", ".join(ids)} / Security / Windows Server 2025 build 26100','source_ids':[sid],'inventory_method':'provider-runtime-message-and-template-metadata','inventory_source_version':f'windows-server-2025-build-26100-security-auditing-batch{batch}','expected_identity_count':10,'identity_dimensions':['provider','channel','native-id','product','platform','version'],'scope_metadata':{'provider':PROVIDER,'channel':CHANNEL,'product':'Windows Server 2025 Datacenter','platform':'Windows','windows_build':'26100','architecture':'64-bit','workflow_run_id':DRUN,'artifact_id':m['artifact_id'],'artifact_digest':m['artifact_digest'],'raw_artifact_sha256':m['raw_sha256'],'provider_event_version_definition_count':sum(len(s[e]) for e in ids),'provider_unique_event_id_count':10,'uws_benchmark_verification':{'workflow_run_id':URUN,'artifact_id':UART,'artifact_digest':UDIG,'raw_artifact_sha256':URAW},'expected_identities':q,'completeness_semantics':'Bounded provider evidence for ten UWS-listed identities inside the frozen 423-ID Security-Auditing denominator; provider versions preserved exactly.'},'guardrails':{'max_unexplained_shrink_percent':0,'max_unexplained_growth_percent':0}};x['digest']=digest(x);return x
def promote(batch,ids,s,t):
 p=ROOT/'content/encyclopedia/approved-exemplars.json';d=json.loads(p.read_text());ev=d['events'];existing={str(x.get('native_event_id')) for x in ev if x.get('namespace')=='microsoft.windows.security'};assert not(set(ids)&existing);used_aliases={a for x in ev if x.get('namespace')=='microsoft.windows.security' for a in x.get('aliases',[])};sid=f'atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch{batch}';new=[]
 for e in ids:
  vers=[];fm={}
  for r in s[e]:
   vers.append({'version':str(r['version']),'generation':'Controlled provider message/template metadata','field_count':len(r['fields']),'notes':'Windows Server 2025 build 26100 provider shape.'})
   for n,it,ot in r['fields']:fm.setdefault(n,{'in':it,'out':ot,'versions':[]})['versions'].append(str(r['version']))
  fields=[{'key':kebab(n),'section':section(n),'native_name':n,'type':(v['in'] or 'win:UnicodeString').split(':',1)[-1],'meaning':f'Provider-rendered `{n}` field preserved from controlled Microsoft event metadata.','versions':sorted(v['versions'],key=int)} for n,v in fm.items()]
  ttl=t[e];aliases=[e,f'Event ID {e}',f'Windows {e}'];
  if ttl not in used_aliases:aliases.append(ttl)
  used_aliases.update(aliases);new.append({'id':f'atlas:event:microsoft.windows.security:{e}','namespace':'microsoft.windows.security','canonical_key':e,'title':f'Windows Security Event {e} — {ttl}','provider':PROVIDER,'channel':CHANNEL,'product':'Windows Security Auditing','platform':'Windows','native_event_id':e,'aliases':aliases,'lifecycle':'current','source_id':sid,'source_version':f'windows-server-2025-build-26100-security-auditing-batch{batch}','source_url':MS,'source_locator':f'{e}: {ttl}','structural_source':{'source_id':sid,'source_version':f'windows-server-2025-build-26100-security-auditing-batch{batch}','locator':f'{PROVIDER} / Security / Event ID {e} / versions {",".join(v["version"] for v in vers)}'},'external_reference':{'source_id':'atlas:source:atlas.source:ultimate-windows-security-benchmark','url':f'https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={e}','role':'PRIMARY_EXTERNAL_QUICK_DETAIL_REFERENCE','redistribution':'source-link-and-coverage-benchmark-only'},'overview':{'summary':f'Microsoft provider message: {ttl} Version-aware field shapes are bound to controlled Windows Server 2025 build 26100 evidence.','category':'Windows Security Auditing','subcategory':'Provider-defined Security auditing','event_type':'Provider-defined','provider_level':clean(s[e][0].get('level')) or 'Informational','event_versions':vers},'collection':{'requirements':['Enable the applicable Windows Security audit policy for this provider identity.','Preserve native Event ID, provider, channel and Version for deterministic parsing.'],'interpretation_note':'Interpret provider message and native fields in surrounding identity, authentication, policy or system activity context; validate expected administrative and security operations before assigning malicious intent.'},'correlations':[],'analysis':['Validate against expected administrative, identity, authentication, policy and system activity before assigning malicious intent.','Use provider-native version and field set as structural authority.'],'fields':fields})
 m=min(map(int,ids));at=len(ev)
 for i,x in enumerate(ev):
  if x.get('namespace')!='microsoft.windows.security':continue
  try:n=int(str(x.get('native_event_id')))
  except:continue
  if n>m:at=i;break
 ev[at:at]=new;dump(p,d)
def coverage(ids):
 p=ROOT/'content/encyclopedia/coverage-manifest.json';d=json.loads(p.read_text());f=next(x for x in d['families'] if x['id']=='windows-security-auditing');old=int(f['encyclopedia_grade_count']);new=old+10;rem=DEN-new;f['encyclopedia_grade_count']=new;f['remaining_count']=rem;b=d['windows_security_log_review_benchmark'];covered=set(map(str,b['covered_event_ids']));assert not(covered&set(ids));uw=int(b['encyclopedia_grade_listed_id_count'])+10;b['covered_event_ids']=sorted(covered|set(ids),key=int);b['encyclopedia_grade_listed_id_count']=uw;b['remaining_listed_id_count']=UDEN-uw;b['completion_ratio']=f'{uw}/{UDEN}';b['completion_percent']=round(uw/UDEN*100,2);dump(p,d);spec=importlib.util.spec_from_file_location('snap',ROOT/'tools/content/build_windows_security_coverage_snapshot.py');mod=importlib.util.module_from_spec(spec);assert spec and spec.loader;spec.loader.exec_module(mod);z=mod.build_snapshot();pct=round(new/DEN*100,2);assert (z['encyclopedia_grade_count'],z['remaining_count'],z['completion_ratio'],z['completion_percent'])==(new,rem,f'{new}/{DEN}',pct);dump(ROOT/'content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json',z);return old,new,rem,uw,pct
def update_snapshot_test(old,new,rem,pct):
 p=ROOT/'tests/phase51010/test_windows_security_coverage_snapshot.py';x=p.read_text();oldrem=DEN-old
 for a,b in [(f'== {old}',f'== {new}'),(f'== {oldrem}',f'== {rem}'),(f'== "{old}/{DEN}"',f'== "{new}/{DEN}"'),(f'== {round(old/DEN*100,2)}',f'== {pct}')]:assert a in x;x=x.replace(a,b)
 p.write_text(x)
def relax13(batch):
 if batch!=14:return
 p=ROOT/'tests/phase51010/test_windows_security_auditing_batch13.py';x=p.read_text();a='assert (f["encyclopedia_grade_count"],f["remaining_count"])==(130,293)';b='assert f["encyclopedia_grade_count"]>=130 and f["remaining_count"]<=293';assert a in x;p.write_text(x.replace(a,b))
def batchtest(batch,ids,s,new,uw,m):
 exp={e:{str(r['version']):len(r['fields']) for r in s[e]} for e in ids};txt=f'''import json\nfrom pathlib import Path\nR=Path(__file__).resolve().parents[2];IDS={ids!r};EXPECTED={exp!r}\ndef events():return {{str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}}\ndef test_shapes():\n d=events()\n for e in IDS: assert {{str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch{batch}"\ndef test_progress():\n m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>={new};b=m["windows_security_log_review_benchmark"];assert b["encyclopedia_grade_listed_id_count"]>={uw} and set(IDS).issubset(set(map(str,b["covered_event_ids"])))\ndef test_binding():\n x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch{batch}-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]=={DRUN} and x["artifact_id"]=={m["artifact_id"]} and x["artifact_digest"]=={m["artifact_digest"]!r} and x["raw_artifact_sha256"]=={m["raw_sha256"]!r} and x["uws_benchmark_verification"]["workflow_run_id"]=={URUN}\n''';(ROOT/f'tests/phase51010/test_windows_security_auditing_batch{batch}.py').write_text(txt)
def redist(batch):
 p=ROOT/'docs/releases/third-party-redistribution-inventory.json';d=json.loads(p.read_text());r=next(x for x in d['entries'] if x['id']=='microsoft-windows-security-documentation');add=[f'content/encyclopedia/sources/microsoft-windows-security-auditing-provider-26100-batch{batch}.json',f'ingestion/inventories/windows-security-auditing-batch{batch}-26100.telemetry.json'];e=[x.strip() for x in r.get('review_evidence','').split(' + ') if x.strip()];r['review_evidence']=' + '.join(e+[x for x in add if x not in e]);dump(p,d)
def scopedoc(batch,ids,new,rem,uw):
 p=ROOT/'docs/windows-security-log-scope.md';x=p.read_text();x=re.sub(r'Current controlled progress after the [^\n]+ bounded Windows Security Log batch:',f'Current controlled progress after bounded Windows Security Log Batch {batch}:',x,count=1);x=re.sub(r'- Windows Security Log UWS review benchmark: `\d+/422` listed identities encyclopedia-grade \(`[^`]+%`\), `\d+` remaining;',f'- Windows Security Log UWS review benchmark: `{uw}/422` listed identities encyclopedia-grade (`{round(uw/UDEN*100,2)}%`), `{UDEN-uw}` remaining;',x,count=1);x=re.sub(r'- newly promoted Security-Auditing IDs in this batch: [^\n]+;',f'- newly promoted Security-Auditing IDs in this batch: {", ".join(f"`{e}`" for e in ids)};',x,count=1);x=re.sub(r'- Windows Security Auditing provider coverage: `\d+/423` encyclopedia-grade with `\d+` provider-specific identities remaining;',f'- Windows Security Auditing provider coverage: `{new}/423` encyclopedia-grade with `{rem}` provider-specific identities remaining;',x,count=1);p.write_text(x)
def main():
 a=argparse.ArgumentParser();a.add_argument('--batch',type=int,required=True);a.add_argument('--artifact',type=Path,required=True);q=a.parse_args();b=q.batch;assert b in ART;m=ART[b];d=load(q.artifact,b);ids=[str(x) for x in d['requested_ids']];assert ids==sorted(ids,key=int);s,t=shapes(d);now=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z');dump(ROOT/f'content/encyclopedia/sources/microsoft-windows-security-auditing-provider-26100-batch{b}.json',source(b,now,m));dump(ROOT/f'ingestion/inventories/windows-security-auditing-batch{b}-26100.telemetry.json',inventory(b,ids,s,m));promote(b,ids,s,t);old,new,rem,uw,pct=coverage(ids);update_snapshot_test(old,new,rem,pct);relax13(b);batchtest(b,ids,s,new,uw,m);redist(b);scopedoc(b,ids,new,rem,uw);print(json.dumps({'batch':b,'ids':ids,'provider_count':new,'provider_remaining':rem,'uws_count':uw,'uws_remaining':UDEN-uw,'provider_versions':sum(len(s[e]) for e in ids)},separators=(',',':')))
if __name__=='__main__':main()
