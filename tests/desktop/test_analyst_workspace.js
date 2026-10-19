'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..', '..');
const tauriRoot = path.join(root, 'benchmarks', 'desktop', 'phase56', 'candidates', 'tauri');
const webRoot = path.join(tauriRoot, 'www');
const html = fs.readFileSync(path.join(webRoot, 'index.html'), 'utf8');
const css = fs.readFileSync(path.join(webRoot, 'styles.css'), 'utf8');
const main = fs.readFileSync(path.join(webRoot, 'main.js'), 'utf8');
const buildRs = fs.readFileSync(path.join(tauriRoot, 'build.rs'), 'utf8');
const rustMain = fs.readFileSync(path.join(tauriRoot, 'src', 'main.rs'), 'utf8');
const tauri = JSON.parse(fs.readFileSync(path.join(tauriRoot, 'tauri.conf.json'), 'utf8'));
const entity = require(path.join(webRoot, 'entity-state.js'));
const projection = require(path.join(webRoot, 'entity-projection.js'));
const investigation = require(path.join(webRoot, 'investigation-model.js'));
const investigationFixtures = JSON.parse(fs.readFileSync(path.join(root, 'tests', 'fixtures', 'desktop', 'investigation-canaries.v0.json'), 'utf8'));
const entitySource = fs.readFileSync(path.join(webRoot, 'entity-state.js'), 'utf8');

test('ATLAS Entity exposes only the six explicit analyst states', () => {
  assert.deepEqual(entity.MODES, ['idle', 'searching', 'correlating', 'reasoning', 'finding', 'warning']);
  for (const mode of entity.MODES) {
    const state = entity.create(mode);
    assert.equal(state.mode, mode);
    assert.equal(state.label, mode.toUpperCase());
    assert.ok(state.detail.length > 0);
  }
});

test('ATLAS Entity fails closed on unknown or malformed state', () => {
  assert.equal(entity.create('untrusted').mode, 'warning');
  assert.equal(entity.fromOperation(null).mode, 'warning');
  assert.equal(entity.fromOperation({ error: true }).mode, 'warning');
  assert.equal(entity.fromOperation({ phase: 'graph' }).mode, 'reasoning');
  assert.equal(entity.create('finding', 'x'.repeat(400)).detail.length, 240);
});

test('Explore is search-first and keeps acceptance canaries out of primary product navigation', () => {
  for (const query of ['4624', '1100', '4688', 'Sysmon 1']) assert.match(html, new RegExp(`data-example-query="${query}"`));
  assert.ok(html.includes('What do you want to investigate?'));
  assert.ok(html.includes('Event ID, executable, ATT&amp;CK technique, provider, field or behavior'));
  assert.equal(html.includes('INVESTIGATION CANARIES'), false);
  assert.equal(html.includes('data-canary-query='), false);
  assert.ok(main.includes('.filter(m=>!isSynthetic(m))'));
  assert.ok(main.includes("s.includes('synthetic.test')"));
});

test('Quick Detail is analyst-facing and hides canonical internals behind Raw / Canonical', () => {
  for (const label of ['Overview', 'Fields', 'Example', 'Detection & Hunt', 'Sources', 'Raw / Canonical']) assert.ok(projection.TAB_MODELS.event.some(tab => tab[1] === label), `missing event quick-detail tab: ${label}`);
  assert.ok(main.includes("firstClaim(detail,entityProjection.overviewPredicate(base))"));
  assert.ok(main.includes("firstClaim(detail,'security.relevance')"));
  assert.ok(main.includes("claims(detail,'telemetry.field-semantics')"));
  assert.ok(main.includes('Key investigative pivots'));
  assert.ok(main.includes('No accepted example is packaged for this record yet.'));
  assert.ok(main.includes('Canonical/internal model data is intentionally kept out of the primary analyst view.'));
});

test('Tool and Hunt Profile projection is generic and does not fake Event fields', () => {
  const tool={entity_type:'tool',native_identifiers:[{type:'tool_name',value:'utility.exe'}]};
  const hunt={entity_type:'activity',native_identifiers:[{type:'hunt_profile',value:'profile'}]};
  assert.equal(projection.kind(tool),'tool');
  assert.equal(projection.kind(hunt),'hunt');
  assert.equal(projection.overviewPredicate(hunt),'behavior.description');
  assert.deepEqual(projection.tabs(tool).map(tab=>tab[1]),['Overview','Capabilities','Relationships','Sources','Raw / Canonical']);
  assert.deepEqual(projection.tabs(hunt).map(tab=>tab[1]),['Overview','Investigation','Relationships','Sources','Raw / Canonical']);
  assert.equal(projection.tabs(tool).some(tab=>tab[1]==='Fields'),false);
  assert.equal(projection.tabs(hunt).some(tab=>tab[1]==='Example'),false);
  assert.deepEqual(projection.entityPivots(tool,{}, {lolbas_categories:['Execute'],attack_techniques:['T1218']},{recommended_telemetry:['Windows 4688']}),['Execute','T1218','Windows 4688']);
  const gtfoSecurity={gtfobins_functions:[{function:'shell',label:'Shell',contexts:['sudo'],inherited_from:['less']}],execution_contexts:[{context:'sudo',meaning:'Requires sudo context.'}],attack_techniques:['T1059']};
  assert.deepEqual(projection.toolFunctions(gtfoSecurity),['Shell · contexts: sudo · inherited from: less']);
  assert.deepEqual(projection.toolContexts(gtfoSecurity),['sudo · Requires sudo context.']);
  assert.deepEqual(projection.toolTechniques(gtfoSecurity),['T1059']);
  assert.deepEqual(projection.entityPivots(tool,{},gtfoSecurity,{}),['Shell','sudo','T1059']);
  assert.deepEqual(projection.entityPivots(hunt,{artifact_families:['process-tree']},{related_event_ids:['4688']},{}),['process-tree','Event 4688']);
  assert.ok(main.includes("firstClaim(detail,entityProjection.overviewPredicate(base))"));
  assert.ok(main.includes("entityProjection.tabs(base)"));
  assert.ok(main.includes("entityProjection.entityPivots(base,overview,security,collection)"));
  assert.ok(main.includes("listCard('Execution Context',entityProjection.toolContexts(security)"));
  assert.ok(main.includes("listCard('Defensive Telemetry'"));
});

test('workspace extends the frozen Desktop boundary with one bounded catalog command', () => {
  const commands = [...main.matchAll(/invoke\('([a-z_]+)'/g)].map(match => match[1]);
  assert.deepEqual(commands, ['core_status','search_records','list_entities','get_record','expand_graph','pack_status','pack_update','pack_rollback']);
  assert.equal(tauri.app.security.capabilities[0].permissions.length, 8);
  assert.equal(tauri.app.security.csp.includes("connect-src 'none'"), true);
});

test('untrusted corpus data is rendered without HTML injection sinks', () => {
  assert.equal(main.includes('.innerHTML'), false);
  assert.equal(main.includes('insertAdjacentHTML'), false);
  assert.ok(main.includes('n.textContent=String(content)'));
  assert.ok(main.includes('p.textContent=JSON.stringify'));
});

test('ATLAS Entity participates in analyst navigation rather than acting only as a status lamp', () => {
  for (const id of ['entityVisual', 'entityStateLabel', 'entityInsightTitle', 'entityPivots']) assert.ok(html.includes(`id="${id}"`), `missing ${id}`);
  assert.ok(main.includes('renderEntityPivots(detail,base,overview,security,collection)'));
  assert.ok(main.includes("activateTab('fields')"));
  assert.ok(main.includes("showView('mindmap')"));
  assert.ok(css.includes('body[data-entity-mode="reasoning"]'));
  assert.ok(css.includes('@media(prefers-reduced-motion:reduce)'));
  assert.ok(css.includes('body[data-theme="high-contrast"]'));
  assert.ok(entitySource.includes('entity-gesture-field'));
  for (const mode of entity.MODES) assert.ok(entitySource.includes(`data-entity-mode="${mode}"`), `missing visible motion profile for ${mode}`);
  assert.ok(entitySource.includes('@media (prefers-reduced-motion:reduce)'));
});

test('search and record failures clear prior selection and use nested Shared Core scope metadata', () => {
  assert.ok(main.includes('state.currentMatch=match||null'));
  assert.ok(main.includes('window.AtlasStaleSelectionGuard?.resetWorkspaceAfterSearchMiss?.()'));
  assert.ok(main.includes('const loaded=await loadRecord(only.target_id,false,only);if(!loaded)return[];'));
  assert.ok(main.includes('const scope=m?.scope||{}'));
  assert.ok(main.includes('provider=m.provider||scope.provider'));
});

test('Tauri commands keep blocking child-process I/O off the WebView command executor', () => {
  assert.ok(rustMain.includes('async fn run_core_session_async'));
  assert.ok(rustMain.includes('tauri::async_runtime::spawn_blocking'));
  assert.ok(rustMain.includes('static CORE_SESSION_GATE: Mutex<()> = Mutex::new(())'));
  assert.equal((rustMain.match(/CORE_SESSION_GATE\s*\.lock\(\)/g) || []).length, 2, 'both status and application commands must share the first-run session gate');
  assert.ok(rustMain.includes('atlas-core session gate is poisoned'));
  for (const command of ['core_status','search_records','list_entities','get_record','expand_graph','pack_status','pack_update','pack_rollback']) {
    assert.ok(rustMain.includes(`async fn ${command}(`), `${command} must remain asynchronous`);
  }
  assert.ok(rustMain.includes('stdout_reader = thread::spawn'));
  assert.ok(rustMain.includes('stderr_reader = thread::spawn'));
});

test('Tauri host gives bounded enriched-pack cold activation enough time and reports timeout evidence', () => {
  assert.ok(rustMain.includes('const CORE_SESSION_TIMEOUT: Duration = Duration::from_secs(120);'));
  assert.ok(rustMain.includes('const CORE_SESSION_POLL_INTERVAL: Duration = Duration::from_millis(20);'));
  assert.equal(rustMain.includes('Duration::from_secs(15)'), false);
  assert.ok(rustMain.includes('atlas-core stdio request timed out after {elapsed_ms} ms'));
  assert.ok(rustMain.includes('stdout_bytes={}'));
  assert.ok(rustMain.includes('CORE_STDERR_DIAGNOSTIC_LIMIT'));
});

test('Tauri host applies an exact fail-closed WebView2 offline allowlist before startup', () => {
  const expectedArguments = [
    '--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection',
    '--disable-background-networking',
    '--disable-preconnect',
    '--disable-component-update',
    '--disable-sync',
    '--metrics-recording-only',
    '--no-first-run',
  ];
  const browserArgumentLiterals = [...rustMain.matchAll(/"(--[^"\r\n]+)"/g)]
    .map(match => match[1])
    .filter(value => value.includes('--disable-background-networking'));

  assert.ok(rustMain.includes('WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS'));
  assert.deepEqual(browserArgumentLiterals, [expectedArguments.join(' ')]);
  assert.equal(tauri.app.windows[0].additionalBrowserArgs, expectedArguments.join(' '));
  assert.equal(tauri.app.windows[0].useHttpsScheme, true, 'Windows custom protocol must not use the ambient HTTP.sys port 80 origin');
  assert.ok(rustMain.includes('normalized.starts_with("--edge-webview-switches")'));
  assert.ok(rustMain.includes('WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER'));
  assert.ok(rustMain.includes('WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER'));

  const mainIndex = rustMain.indexOf('fn main() {');
  const configureIndex = rustMain.indexOf('configure_offline_webview()', mainIndex);
  const builderIndex = rustMain.indexOf('tauri::Builder::default()', mainIndex);
  assert.notEqual(mainIndex, -1, 'host main entrypoint must remain explicit');
  assert.notEqual(configureIndex, -1, 'offline WebView2 configuration must be invoked');
  assert.notEqual(builderIndex, -1, 'Tauri Builder startup must remain explicit');
  assert.ok(configureIndex < builderIndex, 'offline WebView2 configuration must run before Tauri startup');

  const configuredSurface = `${rustMain}\n${JSON.stringify(tauri)}`;
  for (const forbiddenArgument of [
    '--remote-debugging-port',
    '--remote-debugging-pipe',
    '--remote-allow-origins',
    '--disable-web-security',
    '--allow-running-insecure-content',
    '--ignore-certificate-errors',
    '--allow-insecure-localhost',
    '--proxy-server',
    '--host-resolver-rules',
  ]) {
    assert.equal(configuredSurface.includes(forbiddenArgument), false, `forbidden WebView2 argument: ${forbiddenArgument}`);
  }
});

test('Mind Map renders a bounded graphical node-link view without arbitrary graph execution', () => {
  assert.ok(html.includes('id="graphResults"'));
  assert.ok(main.includes("createElementNS('http://www.w3.org/2000/svg',tag)"));
  assert.ok(main.includes("class:'graph-node root'"));
  assert.ok(main.includes('await atlas.graph(seed,depth)'));
  assert.ok(main.includes('Math.min(pivots.length,14)'));
});

test('release host and sidecar are configured to avoid companion console windows', () => {
  assert.ok(rustMain.includes('command.creation_flags(CREATE_NO_WINDOW)'));
  assert.ok(buildRs.includes('cargo:rustc-link-arg=/SUBSYSTEM:WINDOWS'));
  assert.equal(tauri.app.windows[0].title, 'Cyber-Sentinel ATLAS');
});

test('workspace exposes provenance metrics only as advanced/internal data and remains accessible', () => {
  for (const id of ['workspace', 'globalNotice', 'metricFields', 'metricClaims', 'metricSources', 'metricRelations', 'toggleEntity']) assert.ok(html.includes(`id="${id}"`), `missing ${id}`);
  assert.ok(html.includes('aria-live="polite"'));
  assert.ok(main.includes("localStorage.setItem('atlas-entity-collapsed'"));
  assert.ok(main.includes("setAttribute('aria-expanded',String(!collapsed))"));
});

test('investigation graph builds deterministic, explicitly classified canaries', () => {
  const canaries = [['atlas:event:microsoft.windows.security:4625','Target User Name'],['atlas:event:microsoft.windows.security:4688','New Process Name'],['atlas:event:microsoft.sysmon:1','ProcessGuid']];
  for (const [recordId, fieldTitle] of canaries) {
    const graph = investigation.build({detail_version:'1.0.0',record:{id:recordId,title:recordId},fields:[{id:`${recordId}.field`,title:fieldTitle,canonical_key:fieldTitle}],sources:[{id:`${recordId}.source`,title:'Authoritative source'}]});
    assert.equal(graph.record_id, recordId); assert.equal(graph.confidence, 'UNASSESSED');
    assert.ok(graph.nodes.some(node => node.classification === 'FACT' && node.status === 'VERIFIED'));
    assert.ok(graph.nodes.some(node => node.classification === 'EVIDENCE REQUIREMENT'));
    assert.ok(graph.nodes.some(node => node.classification === 'HYPOTHESIS' && node.status === 'UNASSESSED'));
    assert.ok(graph.nodes.some(node => node.classification === 'CHECK')); assert.ok(graph.nodes.some(node => node.classification === 'PROVENANCE'));
    assert.ok(graph.edges.every(edge => ['REQUIRES_EVIDENCE','INFORMS','REQUIRES_CHECK','SUPPORTS_SEMANTICS'].includes(edge.type)));
  }
});

test('investigation graph refuses unsupported records without blocking Explore', () => {
  assert.equal(investigation.build(null), null);
  assert.equal(investigation.build({ detail_version: '1.0.0' }), null);
  assert.equal(investigation.build({ detail_version: '1.0.0', record: { id: 'atlas:event:unknown:1' } }), null);
  assert.ok(html.includes('A hypothesis is never promoted to fact without evidence.'));
  assert.ok(main.includes('The record remains fully searchable and readable. Investigation enrichment is a separate content layer.'));
});

test('canary acceptance fixtures remain synthetic, bounded and complete', () => {
  assert.equal(investigationFixtures.schema, 'atlas-investigation-fixtures/v0'); assert.equal(investigationFixtures.fixture_only, true); assert.equal(investigationFixtures.canonical_corpus, false); assert.equal(investigationFixtures.scenarios.length, 9);
  const combinations = new Set(investigationFixtures.scenarios.map(item => `${item.record_id}:${item.case_kind}`));
  for (const recordId of Object.keys(investigation.PLAYBOOKS)) for (const caseKind of investigation.CASE_KINDS) assert.ok(combinations.has(`${recordId}:${caseKind}`));
});

test('explicit evidence produces deterministic support, refute and incomplete states', () => {
  for (const fixture of investigationFixtures.scenarios) {
    const base = investigation.build({detail_version:'1.0.0',record:{id:fixture.record_id,title:fixture.record_id},fields:[],sources:[{id:`${fixture.record_id}.source`,title:'Authoritative source'}]});
    const assessed = investigation.applyEvidence(base, fixture); assert.equal(assessed.scenario_id, fixture.scenario_id); assert.equal(assessed.case_kind, fixture.case_kind); assert.equal(assessed.nodes.filter(node=>node.classification==='EVIDENCE').length, fixture.observations.length);
    assert.ok(assessed.edges.every(edge => ['REQUIRES_EVIDENCE','INFORMS','REQUIRES_CHECK','SUPPORTS_SEMANTICS','DERIVED_FROM_RECORD_CONTEXT','SUPPORTS','REFUTES','UNKNOWN'].includes(edge.type)));
    if (fixture.case_kind === 'incomplete') assert.equal(assessed.confidence, 'INCOMPLETE'); else assert.equal(assessed.confidence, 'BOUNDED-EVIDENCE');
  }
});

test('evidence assessment fails closed on mismatched, duplicate or unbounded input', () => {
  const fixture = investigationFixtures.scenarios[0]; const base = investigation.build({detail_version:'1.0.0',record:{id:fixture.record_id},fields:[],sources:[]});
  assert.throws(() => investigation.applyEvidence(base, { ...fixture, record_id: 'atlas:event:unknown:1' }), /does not match/);
  assert.throws(() => investigation.applyEvidence(base, { ...fixture, case_kind: 'invented' }), /not supported/);
  assert.throws(() => investigation.applyEvidence(base, { ...fixture, observations: [...fixture.observations, fixture.observations[0]] }), /duplicate observation/);
  assert.throws(() => investigation.applyEvidence(base, { ...fixture, observations: [{ ...fixture.observations[0], assessments: [{ hypothesis_id: 'hypothesis-99', effect: 'SUPPORTS' }] }] }), /unknown hypothesis/);
});
