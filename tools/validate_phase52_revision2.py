#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
from urllib.parse import urlparse, parse_qsl
from datetime import datetime
import copy, json, re, sys
import validate_phase52 as base

ROOT=Path(__file__).resolve().parents[1]
REGISTRY_DIR=ROOT/'model'/'registries'; SCHEMA_DIR=ROOT/'schemas'/'v1'
SCHEMA_URI_BASE='https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/'
SEMVER_RE=re.compile(r'^[0-9]+\.[0-9]+\.[0-9]+$')
REQUIRED_REGISTRIES={'entity-types','namespaces','relationship-types','native-identifier-types','claim-predicates','alias-kinds'}
TELEMETRY={'event','audit-record','audit-action','operation','activity','finding','flow-record'}
VERSION_SUBJECTS={'platform','product','telemetry-provider','technology'}
AUTH_TRANSFORMS={'direct-structured-import','normalized-fact'}
SUSPICIOUS={'token','access_token','api_key','apikey','key','sig','signature','session','sessionid','x-amz-signature','x-amz-credential','x-goog-signature'}

# Revision 2 corrects the Phase 5.2 relationship evidence classification while
# retaining the original validator as a regression gate.
base.SEMANTIC_RELATIONSHIPS_REQUIRING_SUPPORT.update({'PRECEDES','FOLLOWS'})
base.STRUCTURAL_RELATIONSHIPS.difference_update({'PRECEDES','FOLLOWS'})

load_json=base.load_json
canonical_json=base.canonical_json
normalize_applicability=base.normalize_applicability
claim_semantic_payload=base.claim_semantic_payload
relationship_semantic_payload=base.relationship_semantic_payload
sha_key=base.sha_key
parse_canonical_id=base.parse_canonical_id
load_fixture_records=base.load_fixture_records
root_validator=base.root_validator
resolve_query=base.resolve_query
validate_exact_resolution=base.validate_exact_resolution
validate_migration=base.validate_migration
validate_legacy_schema_preservation=base.validate_legacy_schema_preservation
MIGRATION_MAP=base.MIGRATION_MAP


def parse_dt(v):
    x=datetime.fromisoformat(v.replace('Z','+00:00'))
    if x.tzinfo is None or x.utcoffset() is None: raise ValueError('datetime must be offset-aware')
    return x


def _walk_refs(v):
    if isinstance(v,dict):
        if '$ref' in v: yield v['$ref']
        for x in v.values(): yield from _walk_refs(x)
    elif isinstance(v,list):
        for x in v: yield from _walk_refs(x)


def load_registries(registry_dir:Path|None=None):
    d=registry_dir or REGISTRY_DIR; out={}; seen={}
    for p in sorted(d.glob('*.json')):
        x=load_json(p); name=x.get('registry'); ver=x.get('registry_version'); vals=x.get('values')
        if not isinstance(name,str) or not name: raise ValueError(f'registry field missing/invalid: {p}')
        if name in seen: raise ValueError(f'duplicate registry identity {name}: {seen[name]} and {p}')
        seen[name]=p
        if p.stem!=name: raise ValueError(f'registry name {name} does not match filename {p.name}')
        if not isinstance(ver,str) or not SEMVER_RE.fullmatch(ver): raise ValueError(f'invalid registry_version for {name}: {ver!r}')
        if not isinstance(vals,list): raise ValueError(f'invalid registry values structure: {p}')
        values=[v.get('value') for v in vals if isinstance(v,dict)]
        if len(values)!=len(vals) or any(not isinstance(v,str) or not v for v in values): raise ValueError(f'invalid registry values: {p}')
        if len(values)!=len(set(values)): raise ValueError(f'duplicate registry values: {p}')
        out[name]=set(values)
    missing=REQUIRED_REGISTRIES-set(out)
    if missing: raise ValueError(f'missing required registries: {sorted(missing)}')
    return out


def validate_schema_uri_policy(errors):
    for p in sorted(SCHEMA_DIR.rglob('*.json')):
        x=load_json(p); rel=p.relative_to(SCHEMA_DIR).as_posix(); want=SCHEMA_URI_BASE+rel
        if x.get('$id')!=want: errors.append(f'{rel}: schema $id must be {want}')
        for ref in _walk_refs(x):
            if ref.startswith('https://json-schema.org/'): continue
            if not ref.startswith(SCHEMA_URI_BASE): errors.append(f'{rel}: non-canonical $ref {ref}')


def rec(byid,rid):
    x=byid.get(rid); return x[1] if x else None


def require_kind(owner,label,target,byid,kind,errors,entity_types=None):
    x=rec(byid,target)
    if not x: return
    if x.get('record_kind')!=kind:
        errors.append(f'{owner}: {label} must resolve to {kind} record')
    elif entity_types and x.get('entity_type') not in entity_types:
        errors.append(f'{owner}: {label} must resolve to EntityRecord entity_type in {sorted(entity_types)}')


def apps(r):
    out=[]
    if isinstance(r.get('applicability'),dict): out.append(r['applicability'])
    if r.get('record_kind')=='entity':
        for n in r.get('native_identifiers',[]):
            if isinstance(n.get('applicability'),dict): out.append(n['applicability'])
        for a in r.get('aliases',[]):
            if isinstance(a.get('applicability'),dict): out.append(a['applicability'])
    return out


def validate_typed_refs(r,byid,errors):
    rid=r['id']
    for a in apps(r):
        for x in a.get('platform_ids',[]): require_kind(rid,'applicability.platform_ids',x,byid,'entity',errors,{'platform'})
        for x in a.get('product_ids',[]): require_kind(rid,'applicability.product_ids',x,byid,'entity',errors,{'product'})
        for x in a.get('provider_ids',[]): require_kind(rid,'applicability.provider_ids',x,byid,'entity',errors,{'telemetry-provider'})
        for x in a.get('version_ids',[]): require_kind(rid,'applicability.version_ids',x,byid,'version',errors)
        for x in a.get('explanatory_claim_ids',[]): require_kind(rid,'applicability.explanatory_claim_ids',x,byid,'claim',errors)
        for vc in a.get('version_constraints',[]): require_kind(rid,'version_constraint.subject_id',vc['subject_id'],byid,'entity',errors,VERSION_SUBJECTS)
    if r.get('record_kind')=='entity':
        for x in r.get('lifecycle',{}).get('reason_claim_ids',[]): require_kind(rid,'lifecycle.reason_claim_ids',x,byid,'claim',errors)
        for a in r.get('aliases',[]):
            p=a.get('scope',{}).get('provider_id')
            if p: require_kind(rid,'alias.scope.provider_id',p,byid,'entity',errors,{'telemetry-provider'})
    elif r.get('record_kind')=='claim':
        if r.get('object',{}).get('kind')=='entity-ref': require_kind(rid,'claim.object.entity_id',r['object']['entity_id'],byid,'entity',errors)
        for e in r.get('evidence',[]): require_kind(rid,'evidence.source_id',e['source_id'],byid,'source',errors)
    elif r.get('record_kind')=='relationship':
        for x in r.get('supporting_claim_ids',[]): require_kind(rid,'relationship.supporting_claim_ids',x,byid,'claim',errors)
    elif r.get('record_kind')=='version':
        x=rec(byid,r['subject_id'])
        if x and x.get('record_kind') not in {'entity','source'}: errors.append(f'{rid}: version.subject_id must resolve to EntityRecord or SourceRecord')
        for e in r.get('evidence',[]): require_kind(rid,'evidence.source_id',e['source_id'],byid,'source',errors)
    elif r.get('record_kind')=='coverage-snapshot':
        for x in r.get('scope',{}).get('subject_ids',[]): require_kind(rid,'coverage.scope.subject_ids',x,byid,'entity',errors)


def validate_spine(r,byid,errors):
    if r.get('record_kind')!='relationship': return
    rid,t=r['id'],r['relationship_type']; left,right=rec(byid,r['from']),rec(byid,r['to'])
    if not left or not right: return
    if t=='HAS_TELEMETRY_PROVIDER':
        require_kind(rid,'relationship.from',r['from'],byid,'entity',errors,{'product'}); require_kind(rid,'relationship.to',r['to'],byid,'entity',errors,{'telemetry-provider'})
    elif t=='HAS_TELEMETRY_SOURCE':
        require_kind(rid,'relationship.from',r['from'],byid,'entity',errors,{'telemetry-provider'}); require_kind(rid,'relationship.to',r['to'],byid,'entity',errors,{'telemetry-source'})
    elif t=='EMITS':
        require_kind(rid,'relationship.from',r['from'],byid,'entity',errors,{'telemetry-source'}); require_kind(rid,'relationship.to',r['to'],byid,'entity',errors,TELEMETRY)
    elif t=='HAS_FIELD':
        require_kind(rid,'relationship.from',r['from'],byid,'entity',errors,TELEMETRY); require_kind(rid,'relationship.to',r['to'],byid,'entity',errors,{'field'})
    elif t=='RUNS_ON':
        require_kind(rid,'relationship.from',r['from'],byid,'entity',errors); require_kind(rid,'relationship.to',r['to'],byid,'entity',errors)


def validate_extensions(r,regs,errors):
    seen=set()
    for e in r.get('extensions',[]):
        if e['namespace'] not in regs['namespaces']: errors.append(f"{r['id']}: unregistered extension namespace {e['namespace']}")
        k=(e['namespace'],e['schema_version'])
        if k in seen: errors.append(f"{r['id']}: duplicate extension identity {k[0]}@{k[1]}")
        seen.add(k)


def validate_native(r,errors):
    if r.get('record_kind')!='entity': return
    xs=r.get('native_identifiers',[])
    if xs and not any(x.get('primary') is True for x in xs): errors.append(f"{r['id']}: non-empty native_identifiers requires at least one primary=true")
    seen=set()
    for x in xs:
        k=canonical_json({'type':x.get('type'),'value':x.get('value'),'namespace':x.get('namespace'),'context':x.get('context'),'case_sensitive':x.get('case_sensitive'),'applicability':normalize_applicability(x.get('applicability'))})
        if k in seen: errors.append(f"{r['id']}: duplicate native identifier semantic tuple")
        seen.add(k)


def validate_source_urls(r,errors):
    if r.get('record_kind')!='source': return
    for u in r.get('canonical_urls',[]):
        p=urlparse(u)
        if p.scheme.lower()!='https' or not p.netloc: errors.append(f"{r['id']}: canonical URL must use HTTPS")
        if p.username or p.password: errors.append(f"{r['id']}: canonical URL contains userinfo credentials")
        for k,_ in parse_qsl(p.query,keep_blank_values=True):
            kl=k.lower()
            if kl in SUSPICIOUS or kl.startswith(('x-amz-','x-goog-')): errors.append(f"{r['id']}: canonical URL contains credential/signature query parameter {k}")


def authoritative_claim_ok(r,byid):
    if r.get('record_kind')!='claim' or r.get('confidence')!='authoritative': return False
    for e in r.get('evidence',[]):
        s=rec(byid,e.get('source_id'))
        if s and s.get('record_kind')=='source' and s.get('source_class')=='tier-a-authoritative' and e.get('reviewer_status')=='approved' and e.get('transformation_type') in AUTH_TRANSFORMS: return True
    return False


def validate_trust(r,byid,errors):
    if r.get('record_kind')=='claim' and r.get('confidence')=='authoritative' and not authoritative_claim_ok(r,byid): errors.append(f"{r['id']}: authoritative claim requires approved Tier A direct/normalized evidence")
    if r.get('record_kind')=='relationship' and r.get('confidence')=='authoritative':
        if not any(authoritative_claim_ok(rec(byid,x),byid) for x in r.get('supporting_claim_ids',[]) if rec(byid,x)): errors.append(f"{r['id']}: authoritative relationship requires authoritative trusted supporting claim")


def validate_time(r,errors):
    try: c,u=parse_dt(r['created_at']),parse_dt(r['updated_at'])
    except ValueError as e: errors.append(f"{r['id']}: invalid record datetime: {e}"); return
    if u<c: errors.append(f"{r['id']}: updated_at precedes created_at")


def alias_same(a,b):
    return a['value']==b['value'] if a.get('case_sensitive') and b.get('case_sensitive') else a['value'].casefold()==b['value'].casefold()


def scope_overlap(a,b):
    sa,sb=a.get('scope',{}),b.get('scope',{})
    for x,y in ((sa.get('namespace'),sb.get('namespace')),(sa.get('entity_type'),sb.get('entity_type')),(sa.get('provider_id'),sb.get('provider_id')),(a.get('locale'),b.get('locale'))):
        if x is not None and y is not None and x!=y: return False
    return True


def validate_aliases(records,errors):
    xs=[(r['id'],a) for _,r in records if r.get('record_kind')=='entity' for a in r.get('aliases',[])]
    for i,(aid,a) in enumerate(xs):
        for bid,b in xs[i+1:]:
            if aid!=bid and alias_same(a,b) and scope_overlap(a,b): errors.append(f"ambiguous alias overlapping scope: {a['value']!r} -> {aid}, {bid}")


def validate_coverage(r,errors):
    if r.get('record_kind')!='coverage-snapshot': return
    if 'coverage_percent' in r: errors.append(f"{r['id']}: coverage_percent must remain derived/absent")
    basis=r.get('numerator_basis'); allowed={'collected','normalized','validated','published'} if r['metric_type']=='telemetry' else {'covered','validated'}
    if basis not in allowed: errors.append(f"{r['id']}: invalid numerator_basis {basis!r}")
    elif r['state_counts'].get(basis)!=r['numerator_count']: errors.append(f"{r['id']}: numerator_count must equal state_counts[{basis!r}]")


def validate_revision2(records,regs):
    errors=[]; byid={r['id']:(p,r) for p,r in records}
    validate_schema_uri_policy(errors)
    base_errors=base.validate_semantics(records,regs); errors.extend(base_errors)
    for _,r in records:
        validate_typed_refs(r,byid,errors); validate_spine(r,byid,errors); validate_extensions(r,regs,errors); validate_native(r,errors); validate_source_urls(r,errors); validate_trust(r,byid,errors); validate_time(r,errors); validate_coverage(r,errors)
    validate_aliases(records,errors)
    return errors


def main():
    try: regs=load_registries(); records=load_fixture_records(); errors=validate_revision2(records,regs)
    except Exception as e: print(f'Revision 2 validation failed: {e}'); return 1
    if errors: print('\n'.join(errors)); return 1
    print('Phase 5.2 Revision 2 validation PASSED'); print(f'schema_uri_base={SCHEMA_URI_BASE}'); return 0

if __name__=='__main__': sys.exit(main())
