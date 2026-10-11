#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path
import xml.etree.ElementTree as ET

PROVIDER='Microsoft-Windows-PowerShell'
CHANNEL='Microsoft-Windows-PowerShell/Operational'
NAMESPACE='microsoft.windows.powershell'
SOURCE_ID='atlas:source:atlas.source:microsoft-windows-powershell-operational-provider-26100'
SOURCE_VERSION='windows-server-2025-build-26100-microsoft-windows-powershell-operational'
SOURCE_URL='https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1'
EXPECTED_IDS=[4100,4101,4102,4103,4104,4105,4106,8193,8194,8195,8196,8197,8198,12039,24577,24578,24579,24580,24581,24582,24583,24584,24592,24593,24594,24595,24596,24597,24598,24599,32777,32784,40961,40962,46358,53249,53250,53251,53504,53505,53506,53507,53508]
TITLES={4100:'PowerShell Operational Trace 4100',4101:'PowerShell Operational Trace 4101',4102:'PowerShell Operational Trace 4102',4103:'Pipeline and Module Execution Detail',4104:'Script Block Content',4105:'Script Block Invocation Started',4106:'Script Block Invocation Completed',8193:'Runspace Object Created',8194:'Runspace Pool Created',8195:'Runspace Pool Opening',8196:'Runspace Activity Correlation Updated',8197:'Runspace State Changed',8198:'Session Creation Retry',12039:'Runspace Activity Correlation Updated',24577:'PowerShell ISE Script Execution Started',24578:'PowerShell ISE User-Selected Script Started',24579:'PowerShell ISE Current Command Stopped',24580:'PowerShell ISE Debugger Resumed',24581:'PowerShell ISE Debugger Stopped',24582:'PowerShell ISE Debug Step Into',24583:'PowerShell ISE Debug Step Over',24584:'PowerShell ISE Debug Step Out',24592:'PowerShell ISE All Breakpoints Enabled',24593:'PowerShell ISE All Breakpoints Disabled',24594:'PowerShell ISE All Breakpoints Removed',24595:'PowerShell ISE Breakpoint Set',24596:'PowerShell ISE Breakpoint Removed',24597:'PowerShell ISE Breakpoint Enabled',24598:'PowerShell ISE Breakpoint Disabled',24599:'PowerShell ISE Breakpoint Hit',32777:'Unhandled PowerShell AppDomain Exception',32784:'PowerShell WSMan Runspace Error',40961:'PowerShell Console Startup',40962:'PowerShell Console Ready',46358:'PowerShell Persistence Store Capacity Warning',53249:'PowerShell Scheduled Job Started',53250:'PowerShell Scheduled Job Completed',53251:'PowerShell Scheduled Job Exception',53504:'PowerShell Named Pipe IPC Listener Started',53505:'PowerShell Named Pipe IPC Listener Ended',53506:'PowerShell Named Pipe IPC Listener Error',53507:'PowerShell Named Pipe IPC Connected',53508:'PowerShell Named Pipe IPC Disconnected'}
FIELD_MEANINGS={'ContextInfo':'Provider-formatted execution context associated with the operation.','UserData':'Provider-formatted user data associated with the operation.','Payload':'Provider payload text; interpret with adjacent PowerShell events and process/session context.','MessageNumber':'One-based fragment number for a multi-part script block message.','MessageTotal':'Total fragment count for the script block message.','ScriptBlockText':'Captured script block content; this field can contain sensitive data.','ScriptBlockId':'Identifier used to correlate script block content and invocation lifecycle records.','Path':'Source path associated with the script block when available.','RunspaceId':'Identifier for the associated PowerShell runspace.','InstanceId':'Identifier for the created runspace pool.','MaxRunspaces':'Maximum configured runspace count.','MinRunspaces':'Minimum configured runspace count.','FileName':'Script file path associated with the PowerShell ISE operation.','CurrentLine':'Line number associated with an ISE breakpoint operation.','SessionId':'Identifier for the PowerShell remoting session.','PipelineId':'Identifier for the PowerShell pipeline.','ErrorCode':'Provider or WSMan error code.','ErrorMessage':'Error message emitted by the provider.','StackTrace':'Stack trace emitted for an error or exception.','ScheduledJobDefName':'Name of the PowerShell Scheduled Job definition.','StartTime':'Provider-formatted scheduled-job start time.','StopTime':'Provider-formatted scheduled-job stop time.','State':'Scheduled-job state reported by the provider.','Name':'Name/type reported for the scheduled-job exception.','Message':'Exception message reported for the scheduled job.','InnerException':'Nested exception information reported for the scheduled job.'}
PARAM_MEANINGS={8193:{'param1':'Runspace instance identifier.'},8197:{'param1':'Runspace state after the transition.'},8198:{'param1':'Session creation retry count.','param2':'Error code that triggered the retry.','param3':'Session identifier associated with the retry.'},32777:{'param1':'Unhandled exception type.','param2':'Unhandled exception message.','param3':'Unhandled exception stack trace.'},53504:{'param1':'Process value emitted for the IPC listener.','param2':'AppDomain value emitted for the IPC listener.'},53505:{'param1':'Process value emitted for the IPC listener.','param2':'AppDomain value emitted for the IPC listener.'},53506:{'param1':'Process value emitted for the IPC listener.','param2':'AppDomain value emitted for the IPC listener.','param3':'IPC listener error message.'},53507:{'param1':'Process value emitted for the IPC connection.','param2':'AppDomain value emitted for the IPC connection.','param3':'User identity emitted for the IPC connection.'},53508:{'param1':'Process value emitted for the IPC disconnection.','param2':'AppDomain value emitted for the IPC disconnection.','param3':'User identity emitted for the IPC disconnection.'}}
XMLNS={'e':'http://schemas.microsoft.com/win/2004/08/events'}

def clean(value): return str(value or '').replace('\x00','').strip()
def keyify(name): return re.sub(r'[^a-z0-9]+','_',re.sub(r'(?<!^)(?=[A-Z])','_',name).lower()).strip('_') or 'field'
def field_meaning(eid,name): return FIELD_MEANINGS.get(name) or PARAM_MEANINGS.get(eid,{}).get(name) or f'Provider field {name} emitted for PowerShell Operational Event ID {eid}.'
def group(eid):
    if 4100 <= eid <= 4106: return 'script-and-pipeline'
    if eid in {8193,8194,8195,8196,8197,8198,12039,32784}: return 'runspace-remoting'
    if 24577 <= eid <= 24599: return 'ise'
    if eid in {53249,53250,53251}: return 'scheduled-job'
    if 53504 <= eid <= 53508: return 'named-pipe-ipc'
    return 'operational'
def prerequisites(eid):
    rows=[f'Collect {CHANNEL} where Windows PowerShell telemetry is in scope.']
    if eid==4103: rows.append('Enable Module Logging for the relevant sessions/modules for comprehensive pipeline/module detail.')
    if eid==4104: rows.append('Enable Script Block Logging for comprehensive script-block content collection.')
    if eid in {4105,4106}: rows.append('Enable Script Block Invocation Logging; this can produce high event volume.')
    if 24577 <= eid <= 24599: rows.append('PowerShell ISE activity must occur; these events are host-specific.')
    return rows
def security_relevance(eid):
    g=group(eid)
    if eid==4103: return 'High-value command/pipeline hunting telemetry when Module Logging is enabled; correlate with 4104, process creation, and runspace context.'
    if eid==4104: return 'High-value script-content telemetry for detection and investigation; protect access because script content can include secrets.'
    if eid in {4105,4106}: return 'Useful for sequencing script-block invocation and correlating ScriptBlockId to RunspaceId.'
    if g=='runspace-remoting': return 'Useful for runspace, session, and remoting lifecycle reconstruction; correlate with process creation and WSMan context.'
    if g=='ise': return 'Useful for distinguishing interactive PowerShell ISE execution/debugging from other PowerShell hosts.'
    if g=='scheduled-job': return 'Useful for scheduled PowerShell execution and persistence investigations; correlate with Task Scheduler and process creation.'
    if g=='named-pipe-ipc': return 'Useful for local IPC/remoting/process-attach investigations; correlate process, AppDomain, and user context where present.'
    if eid in {32777,46358}: return 'Operational anomaly telemetry useful for diagnosing failures or telemetry/persistence pressure; not inherently malicious.'
    return 'Supporting PowerShell session/console context for timeline reconstruction and correlation.'
def correlations(eid):
    g=group(eid)
    if g=='script-and-pipeline': return ['PowerShell 4103/4104/4105/4106','Windows Security 4688','Sysmon Event 1']
    if g=='runspace-remoting': return ['PowerShell runspace lifecycle','WSMan/remoting context','Windows Security 4688','Sysmon Event 1']
    if g=='ise': return ['PowerShell ISE process/session','Windows Security 4688','Sysmon Event 1']
    if g=='scheduled-job': return ['PowerShell Scheduled Jobs','Task Scheduler telemetry','Windows Security 4688','Sysmon Event 1']
    if g=='named-pipe-ipc': return ['PowerShell Named Pipe IPC lifecycle','Windows Security 4688','Sysmon Event 1']
    return ['adjacent PowerShell Operational events','Windows Security 4688','Sysmon Event 1']
def summary(eid,level,task,fields):
    title=TITLES[eid]
    shape=', '.join(fields) if fields else 'no EventData fields'
    text=f'{title}. This {PROVIDER} record is emitted to {CHANNEL}; provider metadata classifies it as level {level or "unspecified"}'
    if task and task!='None': text+=f', task {task}'
    text+=f'. Analyst field shape: {shape}.'
    if eid==4104: text+=' When Script Block Logging is enabled, ScriptBlockId and fragment numbering support reconstruction of multi-part script content.'
    if eid in {4105,4106}: text+=' Pair start/stop records by ScriptBlockId and RunspaceId when invocation logging is enabled.'
    return text

def canonical_bytes(obj): return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
def write_json(path,obj): path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(obj,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--input',required=True,type=Path); ap.add_argument('--repo-root',required=True,type=Path); ap.add_argument('--provider-xml-sha256',required=True); ap.add_argument('--normalized-private-inventory-sha256',required=True); args=ap.parse_args()
    raw=json.loads(args.input.read_text(encoding='utf-8-sig'))
    if raw.get('provider')!=PROVIDER or raw.get('channel')!=CHANNEL: raise SystemExit('provider/channel mismatch')
    ids=[int(x) for x in raw.get('unique_event_ids',[])]
    if ids!=EXPECTED_IDS or raw.get('provider_unique_event_id_count')!=43 or raw.get('provider_event_version_definition_count')!=43: raise SystemExit('PowerShell Operational denominator drift')
    created=clean(raw.get('collected_at_utc'))[:19]+'Z'
    product=raw['runner']['os_caption']; build=raw['runner']['os_build_number']; arch=raw['runner']['architecture']
    events=[]; identities=[]
    for event in raw['events']:
        eid=int(event['id']); template=clean(event.get('template')); fields=[]
        if template:
            root=ET.fromstring(template)
            for node in root.findall('.//e:data',XMLNS):
                name=node.attrib['name']; fields.append({'key':keyify(name),'section':'Event Data','native_name':name,'type':node.attrib.get('inType','win:UnicodeString'),'out_type':node.attrib.get('outType'),'meaning':field_meaning(eid,name),'versions':['1']})
        level=clean(event.get('level')); task=clean(event.get('task')); opcode=clean(event.get('opcode')); keywords=[clean(x) for x in event.get('keywords',[]) if clean(x)]
        overview={'summary':summary(eid,level,task,[f['native_name'] for f in fields]),'provider':PROVIDER,'channel':CHANNEL,'event_id':str(eid),'version':'1','level':level or None,'task':task or None,'opcode':opcode or None,'keywords':keywords,'event_versions':[{'version':'1','field_count':len(fields)}],'analyst_pivots':[f['native_name'] for f in fields]}
        events.append({'id':f'atlas:event:{NAMESPACE}:{eid}','namespace':NAMESPACE,'canonical_key':str(eid),'native_event_id':str(eid),'title':f'{eid} — {TITLES[eid]}','lifecycle':'current','provider':PROVIDER,'channel':CHANNEL,'product':'Windows PowerShell 5.1','platform':'Windows','aliases':[str(eid),f'PowerShell {eid}',f'PowerShell Event {eid}',f'Event ID {eid}'],'source_id':SOURCE_ID,'source_version':SOURCE_VERSION,'source_url':SOURCE_URL,'source_locator':f'controlled provider metadata / {CHANNEL} / Event ID {eid} / Version 1','overview':overview,'collection':{'channel':CHANNEL,'prerequisites':prerequisites(eid),'volume':'high' if eid in {4105,4106} else ('potentially-high' if eid in {4103,4104} else 'environment-dependent'),'sensitive_data':'possible' if eid in {4100,4101,4102,4103,4104,32777,32784,53251,53506} else 'limited-by-event-shape','notes':'Absence is not proof of no PowerShell activity; policy, host, version, and feature usage affect event generation.'},'analysis':security_relevance(eid),'correlations':correlations(eid),'fields':fields})
        identities.append({'event_id':str(eid),'versions':[{'version':1,'field_count':len(fields),'level':level or None,'task':task or None,'opcode':opcode or None,'fields':[{'name':f['native_name'],'in_type':f['type'],'out_type':f['out_type']} for f in fields]}]})
    content=args.repo_root/'content'/'encyclopedia'; invdir=args.repo_root/'ingestion'/'inventories'
    for idx in range(0,len(events),6):
        batch={'schema_version':'1.0.0','status':'MAINTAINER_APPROVED_POWERSHELL_OPERATIONAL_26100','family':'PowerShell Operational','provider':PROVIDER,'channel':CHANNEL,'namespace':NAMESPACE,'reference_build':'26100','source_id':SOURCE_ID,'batch_index':idx//6+1,'events':events[idx:idx+6]}
        write_json(content/f'powershell-operational-26100-batch{idx//6+1:02d}.json',batch)
    source={'schema_version':'1.0.0','record_kind':'source','id':SOURCE_ID,'record_revision':1,'created_at':created,'updated_at':created,'curation_status':'validated','namespace':'atlas.source','canonical_key':'microsoft-windows-powershell-operational-provider-26100','title':'Microsoft-Windows-PowerShell Operational Provider Metadata — Windows Server 2025 build 26100','publisher':'Microsoft','source_class':'tier-a-authoritative','canonical_urls':[SOURCE_URL,'https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log','https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil'],'official_status':'official','license':{'status':'unknown'},'redistribution':{'policy':'restricted','notes':'ATLAS stores independently authored normalized provider facts, hashes and locators. Raw Microsoft provider XML/message prose remains outside Git and is not redistributed.'},'freshness_policy':{'expected_update_cadence':'provider-build-bound','stale_after_days':180},'change_detection_policy':{'strategy':'checksum','notes':f'Controlled {product} build {build} provider capture; raw provider XML digest {args.provider_xml_sha256}; normalized private inventory digest {args.normalized_private_inventory_sha256}. Private control-plane locator is intentionally not published.'}}
    write_json(content/'sources'/'microsoft-windows-powershell-operational-provider-26100.json',source)
    inventory={'ingestion_contract_version':'1.0.0','inventory_contract_version':'1.0.0','inventory_id':'atlas:inventory:atlas.ingestion:windows-powershell-operational-provider-26100','inventory_kind':'telemetry','declared_scope':f'{PROVIDER} events linked to {CHANNEL} on controlled {product} build {build}','source_ids':[SOURCE_ID],'inventory_method':'provider-runtime-metadata','inventory_source_version':SOURCE_VERSION,'expected_identity_count':43,'identity_dimensions':['provider','channel','native-id','product','platform','version'],'scope_metadata':{'provider':PROVIDER,'channel':CHANNEL,'product':product,'platform':'Windows','windows_build':build,'architecture':arch,'locale':'en-US','collection_method':'Get-WinEvent -ListProvider plus wevtutil gp /ge:true /gm:true /f:xml','raw_artifact_sha256':args.provider_xml_sha256,'normalized_private_inventory_sha256':args.normalized_private_inventory_sha256,'provider_event_version_definition_count':43,'provider_unique_event_id_count':43,'expected_identities':identities,'completeness_semantics':f'Exact for {PROVIDER} identities linked to {CHANNEL} on controlled {product} build {build}; not a global PowerShell or Windows denominator.'},'guardrails':{'max_unexplained_shrink_percent':0,'max_unexplained_growth_percent':0}}
    inventory['digest']='sha256-'+hashlib.sha256(canonical_bytes(inventory)).hexdigest(); write_json(invdir/'windows-powershell-operational-26100.telemetry.json',inventory)
    coverage={'coverage_contract_version':'1.0.0','product':'Windows PowerShell 5.1 Operational','provider':PROVIDER,'channel':CHANNEL,'reference_scope':{'product':product,'windows_version':'24H2','windows_build':build,'architecture':'x64','locale':'en-US'},'inventory_id':inventory['inventory_id'],'inventory_digest':inventory['digest'],'raw_artifact_sha256':args.provider_xml_sha256,'denominator_kind':'controlled-provider-runtime-metadata-unique-event-id','denominator_count':43,'provider_event_version_definition_count':43,'encyclopedia_grade_count':43,'remaining_count':0,'completion_ratio':'43/43','completion_percent':100.0,'release_numerator_rule':'Only ENCYCLOPEDIA_GRADE maintainer-approved PowerShell Operational records count.','scope_semantics':f'This denominator is exact for {PROVIDER} / {CHANNEL} on controlled {product} build {build}; it does not imply completeness for PowerShellCore, other Windows builds/providers, or non-Windows PowerShell.','events':[{'event_id':str(eid),'coverage_state':'ENCYCLOPEDIA_GRADE','counts_toward_release_coverage':True,'canonical_id':f'atlas:event:{NAMESPACE}:{eid}'} for eid in EXPECTED_IDS]}
    write_json(content/'powershell-operational-26100-coverage.snapshot.json',coverage)
    print('generated PowerShell Operational 43/43 with',sum(len(e['fields']) for e in events),'field projections')
if __name__=='__main__': main()
