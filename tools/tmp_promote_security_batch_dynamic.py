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

def dump(p,v):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

def digest(v):
    x=copy.deepcopy(v); x.pop('digest',None)
    return 'sha256-'+hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

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
    return {
      'schema_version':'1.0.0','record_kind':'source','id':sid,'record_revision':1,
      'created_at':now,'updated_at':now,'curation_status':'validated','namespace':'atlas.source',
      'canonical_key':f'microsoft-windows-security-auditing-provider-26100-batch{batch}',
      'title':f'Microsoft-Windows-Security-Auditing provider message metadata — build 26100 — Batch {batch}',
      'publisher':'Microsoft','source_class':'tier-a-authoritative','canonical_urls':[MS,APP],
      'official_status':'official','license':{'status':'unknown'},
      'redistribution':{'policy':'restricted','notes':'ATLAS stores normalized facts, provider field shapes and short source locators; substantial Microsoft documentation or provider prose is not redistributed.'},
      'freshness_policy':{'expected_update_cadence':'provider-build-bound','stale_after_days':180},
      'change_detection_policy':{'strategy':'checksum','notes':f'Discovery run {meta["discovery_run_id"]}; artifact {meta["provider_artifact_id"]}; {meta["provider_artifact_digest"]}; {meta["provider_raw_sha256"]}; UWS membership run {meta["uws_run_id"]}; artifact {meta["uws_artifact_id"]}; {meta["uws_artifact_digest"]}; {meta["uws_raw_sha256"]}.'}
    }

def load_provider(path,batch,meta):
    raw=path.read_bytes()
    assert 'sha256-'+hashlib.sha256(raw).hexdigest()==meta['provider_raw_sha256']
    d=json.loads(raw.decode('utf-8-sig'))
    assert d['schema']=='atlas.windows-provider-structural-discovery/v2'
    assert d['provider_message_semantics'] is True
    assert int(d['batch'])==batch and d['provider']==PROVIDER and d['channel_scope']==CHANNEL
    assert str(d['runner_os']['OsBuildNumber'])=='26100'
    assert 1<=d['unique_event_id_count']<=10 and d['unique_event_id_count']==len(d['requested_ids'])
    return d

def shapes(d):
    ns={'e':'http://schemas.microsoft.com/win/2004/08/events'}
    s={str(e):[] for e in d['requested_ids']}; t={}
    for r in d['events']:
        e=str(r['id']); tmpl=r.get('template') or ''
        root=ET.fromstring(tmpl) if tmpl.strip() else None
        fields=[] if root is None else [(x.attrib['name'],x.attrib.get('inType'),x.attrib.get('outType')) for x in root.findall('e:data',ns)]
        s[e].append({'version':int(r['version']),'level':r.get('level'),'fields':fields})
        t.setdefault(e,title(r.get('description'),e))
    assert all(s.values())
    return s,t

def inventory(batch,ids,s,meta,listed):
    sid=f'atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch{batch}'
    q=[]
    for e in ids:
        q.append({'event_id':e,'versions':[{'version':r['version'],'field_count':len(r['fields']),'level':r['level'],'fields':[{'name':n,'in_type':i,'out_type':o} for n,i,o in r['fields']]} for r in s[e]]})
    x={
      'ingestion_contract_version':'1.0.0','inventory_contract_version':'1.0.0',
      'inventory_id':f'atlas:inventory:atlas.ingestion:windows-security-auditing-batch{batch}-26100',
      'inventory_kind':'telemetry','declared_scope':f'{PROVIDER} Event IDs {", ".join(ids)} / Security / Windows Server 2025 build 26100',
      'source_ids':[sid],'inventory_method':'provider-runtime-message-and-template-metadata',
      'inventory_source_version':f'windows-server-2025-build-26100-security-auditing-batch{batch}',
      'expected_identity_count':len(ids),'identity_dimensions':['provider','channel','native-id','product','platform','version'],
      'scope_metadata':{
        'provider':PROVIDER,'channel':CHANNEL,'product':'Windows Server 2025 Datacenter','platform':'Windows','windows_build':'26100','architecture':'64-bit',
        'workflow_run_id':meta['discovery_run_id'],'artifact_id':meta['provider_artifact_id'],'artifact_digest':meta['provider_artifact_digest'],'raw_artifact_sha256':meta['provider_raw_sha256'],
        'provider_event_version_definition_count':sum(len(s[e]) for e in ids),'provider_unique_event_id_count':len(ids),
        'uws_benchmark_verification':{'workflow_run_id':meta['uws_run_id'],'artifact_id':meta['uws_artifact_id'],'artifact_digest':meta['uws_artifact_digest'],'raw_artifact_sha256':meta['uws_raw_sha256'],'listed_event_ids':sorted(listed,key=int),'listed_count':len(listed)},
        'expected_identities':q,
        'completeness_semantics':f'Bounded provider evidence for {len(ids)} identities inside the frozen 423-ID Security-Auditing denominator. UWS membership is tracked independently as a secondary review benchmark; provider versions are preserved exactly.'
      },
      'guardrails':{'max_unexplained_shrink_percent':0,'max_unexplained_growth_percent':0}
    }
    x['digest']=digest(x); return x

def promote(batch,ids,s,t,listed):
    p=ROOT/'content/encyclopedia/approved-exemplars.json'; d=json.loads(p.read_text()); ev=d['events']
    existing={str(x.get('native_event_id')) for x in ev if x.get('namespace')=='microsoft.windows.security'}
    assert not(set(ids)&existing)
    used_aliases={a for x in ev if x.get('namespace')=='microsoft.windows.security' for a in x.get('aliases',[])}
    sid=f'atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch{batch}'; new=[]
    for e in ids:
        vers=[]; fm={}
        for r in s[e]:
            vers.append({'version':str(r['version']),'generation':'Controlled provider message/template metadata','field_count':len(r['fields']),'notes':'Windows Server 2025 build 26100 provider shape.'})
            for n,it,ot in r['fields']:fm.setdefault(n,{'in':it,'out':ot,'versions':[]})['versions'].append(str(r['version']))
        fields=[{'key':kebab(n),'section':section(n),'native_name':n,'type':(v['in'] or 'win:UnicodeString').split(':',1)[-1],'meaning':f'Provider-rendered `{n}` field preserved from controlled Microsoft event metadata.','versions':sorted(v['versions'],key=int)} for n,v in fm.items()]
        ttl=t[e]; aliases=[e,f'Event ID {e}',f'Windows {e}']
        if ttl not in used_aliases: aliases.append(ttl)
        used_aliases.update(aliases)
        rec={
          'id':f'atlas:event:microsoft.windows.security:{e}','namespace':'microsoft.windows.security','canonical_key':e,
          'title':f'Windows Security Event {e} — {ttl}','provider':PROVIDER,'channel':CHANNEL,'product':'Windows Security Auditing','platform':'Windows','native_event_id':e,
          'aliases':aliases,'lifecycle':'current','source_id':sid,'source_version':f'windows-server-2025-build-26100-security-auditing-batch{batch}','source_url':MS,'source_locator':f'{e}: {ttl}',
          'structural_source':{'source_id':sid,'source_version':f'windows-server-2025-build-26100-security-auditing-batch{batch}','locator':f'{PROVIDER} / Security / Event ID {e} / versions {",".join(v["version"] for v in vers)}'},
          'overview':{'summary':f'Microsoft provider message: {ttl} Version-aware field shapes are bound to controlled Windows Server 2025 build 26100 evidence.','category':'Windows Security Auditing','subcategory':'Provider-defined Security auditing','event_type':'Provider-defined','provider_level':clean(s[e][0].get('level')) or 'Informational','event_versions':vers},
          'collection':{'requirements':['Enable the applicable Windows Security audit policy for this provider identity.','Preserve native Event ID, provider, channel and Version for deterministic parsing.'],'interpretation_note':'Interpret provider message and native fields in surrounding identity, authentication, policy or system activity context; validate expected administrative and security operations before assigning malicious intent.'},
          'correlations':[],'analysis':['Validate against expected administrative, identity, authentication, policy and system activity before assigning malicious intent.','Use provider-native version and field set as structural authority.'],'fields':fields
        }
        if e in listed:
            rec['external_reference']={'source_id':'atlas:source:atlas.source:ultimate-windows-security-benchmark','url':f'https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={e}','role':'PRIMARY_EXTERNAL_QUICK_DETAIL_REFERENCE','redistribution':'source-link-and-coverage-benchmark-only'}
        new.append(rec)
    m=min(map(int,ids)); at=len(ev)
    for i,x in enumerate(ev):
        if x.get('namespace')!='microsoft.windows.security':continue
        try:n=int(str(x.get('native_event_id')))
        except:continue
        if n>m:at=i;break
    ev[at:at]=new; dump(p,d)

def coverage(ids,listed):
    p=ROOT/'content/encyclopedia/coverage-manifest.json'; d=json.loads(p.read_text())
    f=next(x for x in d['families'] if x['id']=='windows-security-auditing')
    old=int(f['encyclopedia_grade_count']); new=old+len(ids); rem=DEN-new
    f['encyclopedia_grade_count']=new; f['remaining_count']=rem
    b=d['windows_security_log_review_benchmark']; covered=set(map(str,b['covered_event_ids']))
    assert not(covered & set(listed)); assert not(set(ids)-set(listed) & covered)
    uw=int(b['encyclopedia_grade_listed_id_count'])+len(listed)
    b['covered_event_ids']=sorted(covered|set(listed),key=int)
    b['encyclopedia_grade_listed_id_count']=uw; b['remaining_listed_id_count']=UDEN-uw
    b['completion_ratio']=f'{uw}/{UDEN}'; b['completion_percent']=round(uw/UDEN*100,2)
    dump(p,d)
    spec=importlib.util.spec_from_file_location('snap',ROOT/'tools/content/build_windows_security_coverage_snapshot.py'); mod=importlib.util.module_from_spec(spec); assert spec and spec.loader; spec.loader.exec_module(mod)
    z=mod.build_snapshot(); pct=round(new/DEN*100,2)
    assert (z['encyclopedia_grade_count'],z['remaining_count'],z['completion_ratio'],z['completion_percent'])==(new,rem,f'{new}/{DEN}',pct)
    dump(ROOT/'content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json',z)
    return old,new,rem,uw,pct

def update_snapshot_test(old,new,rem,pct):
    p=ROOT/'tests/phase51010/test_windows_security_coverage_snapshot.py'; x=p.read_text(); oldrem=DEN-old
    for a,b in [(f'== {old}',f'== {new}'),(f'== {oldrem}',f'== {rem}'),(f'== "{old}/{DEN}"',f'== "{new}/{DEN}"'),(f'== {round(old/DEN*100,2)}',f'== {pct}')]:
        assert a in x,(a,p); x=x.replace(a,b)
    p.write_text(x)

def batchtest(batch,ids,s,new,uw,meta,listed):
    exp={e:{str(r['version']):len(r['fields']) for r in s[e]} for e in ids}
    txt=f'''import json\nfrom pathlib import Path\nR=Path(__file__).resolve().parents[2];IDS={ids!r};LISTED={sorted(listed,key=int)!r};EXPECTED={exp!r}\ndef events():return {{str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}}\ndef test_shapes():\n d=events()\n for e in IDS: assert {{str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch{batch}"\ndef test_progress():\n m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>={new};b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>={uw} and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered\ndef test_binding():\n x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch{batch}-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]=={meta["discovery_run_id"]} and x["artifact_id"]=={meta["provider_artifact_id"]} and x["artifact_digest"]=={meta["provider_artifact_digest"]!r} and x["raw_artifact_sha256"]=={meta["provider_raw_sha256"]!r} and x["uws_benchmark_verification"]["workflow_run_id"]=={meta["uws_run_id"]}\n'''
    (ROOT/f'tests/phase51010/test_windows_security_auditing_batch{batch}.py').write_text(txt)

def redist(batch):
    p=ROOT/'docs/releases/third-party-redistribution-inventory.json'; d=json.loads(p.read_text()); r=next(x for x in d['entries'] if x['id']=='microsoft-windows-security-documentation')
    add=[f'content/encyclopedia/sources/microsoft-windows-security-auditing-provider-26100-batch{batch}.json',f'ingestion/inventories/windows-security-auditing-batch{batch}-26100.telemetry.json']
    e=[x.strip() for x in r.get('review_evidence','').split(' + ') if x.strip()]; r['review_evidence']=' + '.join(e+[x for x in add if x not in e]); dump(p,d)

def scopedoc(batch,ids,new,rem,uw):
    p=ROOT/'docs/windows-security-log-scope.md'; x=p.read_text()
    x=re.sub(r'Current controlled progress after the [^\n]+ bounded Windows Security Log batch:',f'Current controlled progress after bounded Windows Security Log Batch {batch}:',x,count=1)
    x=re.sub(r'- Windows Security Log UWS review benchmark: `\d+/422` listed identities encyclopedia-grade \(`[^`]+%`\), `\d+` remaining;',f'- Windows Security Log UWS review benchmark: `{uw}/422` listed identities encyclopedia-grade (`{round(uw/UDEN*100,2)}%`), `{UDEN-uw}` remaining;',x,count=1)
    x=re.sub(r'- newly promoted Security-Auditing IDs in this batch: [^\n]+;',f'- newly promoted Security-Auditing IDs in this batch: {", ".join(f"`{e}`" for e in ids)};',x,count=1)
    x=re.sub(r'- Windows Security Auditing provider coverage: `\d+/423` encyclopedia-grade with `\d+` provider-specific identities remaining;',f'- Windows Security Auditing provider coverage: `{new}/423` encyclopedia-grade with `{rem}` provider-specific identities remaining;',x,count=1)
    p.write_text(x)

def main():
    a=argparse.ArgumentParser(); a.add_argument('--batch',type=int,required=True); a.add_argument('--artifact',type=Path,required=True); a.add_argument('--evidence',type=Path,required=True); q=a.parse_args()
    b=q.batch; meta=json.loads(q.evidence.read_text()); assert int(meta['batch'])==b
    listed={str(x) for x in meta['uws_listed_ids']}; d=load_provider(q.artifact,b,meta); ids=[str(x) for x in d['requested_ids']]; assert ids==sorted(ids,key=int); assert listed<=set(ids)
    s,t=shapes(d); now=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')
    dump(ROOT/f'content/encyclopedia/sources/microsoft-windows-security-auditing-provider-26100-batch{b}.json',source(b,now,meta))
    dump(ROOT/f'ingestion/inventories/windows-security-auditing-batch{b}-26100.telemetry.json',inventory(b,ids,s,meta,listed))
    promote(b,ids,s,t,listed); old,new,rem,uw,pct=coverage(ids,listed); update_snapshot_test(old,new,rem,pct); batchtest(b,ids,s,new,uw,meta,listed); redist(b); scopedoc(b,ids,new,rem,uw)
    print(json.dumps({'batch':b,'ids':ids,'uws_listed_ids':sorted(listed,key=int),'provider_count':new,'provider_remaining':rem,'uws_count':uw,'uws_remaining':UDEN-uw,'provider_versions':sum(len(s[e]) for e in ids)},separators=(',',':')))

if __name__=='__main__':main()

