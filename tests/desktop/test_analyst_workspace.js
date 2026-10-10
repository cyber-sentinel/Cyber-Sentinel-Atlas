'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..', '..');
const webRoot = path.join(root, 'benchmarks', 'desktop', 'phase56', 'candidates', 'tauri', 'www');
const html = fs.readFileSync(path.join(webRoot, 'index.html'), 'utf8');
const css = fs.readFileSync(path.join(webRoot, 'styles.css'), 'utf8');
const main = fs.readFileSync(path.join(webRoot, 'main.js'), 'utf8');
const tauri = JSON.parse(fs.readFileSync(path.join(root, 'benchmarks', 'desktop', 'phase56', 'candidates', 'tauri', 'tauri.conf.json'), 'utf8'));
const entity = require(path.join(webRoot, 'entity-state.js'));
const investigation = require(path.join(webRoot, 'investigation-model.js'));
const investigationFixtures = JSON.parse(fs.readFileSync(path.join(root, 'tests', 'fixtures', 'desktop', 'investigation-canaries.v0.json'), 'utf8'));

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

test('analyst workspace binds all three corpus-backed canaries', () => {
  const canaries = [
    ['4625', 'atlas:event:microsoft.windows.security:4625'],
    ['4688', 'atlas:event:microsoft.windows.security:4688'],
    ['Sysmon 1', 'atlas:event:microsoft.sysmon:1']
  ];
  for (const [query, id] of canaries) {
    assert.match(html, new RegExp(`data-canary-query="${query}"`));
    assert.ok(html.includes(`data-canary-id="${id}"`));
  }
  assert.ok(main.includes('await runSearchQuery(query, expectedId)'));
  assert.ok(main.includes('matches.find(match => match?.target_id === canaryId)'));
});

test('workspace preserves the frozen seven-command Desktop boundary', () => {
  const commands = [...main.matchAll(/invoke\('([a-z_]+)'/g)].map(match => match[1]);
  assert.deepEqual(commands, [
    'core_status',
    'search_records',
    'get_record',
    'expand_graph',
    'pack_status',
    'pack_update',
    'pack_rollback'
  ]);
  const permissions = tauri.app.security.capabilities[0].permissions;
  assert.equal(permissions.length, 7);
  assert.equal(tauri.app.security.csp.includes("connect-src 'none'"), true);
});

test('untrusted corpus data is rendered without HTML injection sinks', () => {
  assert.equal(main.includes('.innerHTML'), false);
  assert.equal(main.includes('insertAdjacentHTML'), false);
  assert.ok(main.includes('node.textContent = content'));
  assert.ok(main.includes('pre.textContent = JSON.stringify'));
});

test('workspace exposes provenance, evidence metrics and accessible entity state', () => {
  for (const id of ['workspace', 'globalNotice', 'entityVisual', 'entityStateLabel', 'metricFields', 'metricClaims', 'metricSources', 'metricRelations']) {
    assert.ok(html.includes(`id="${id}"`), `missing ${id}`);
  }
  assert.ok(html.includes('No hidden model reasoning is displayed.'));
  assert.ok(main.includes('renderReferenceSources(detail, summary)'));
  assert.ok(main.includes('renderTimeline(detail, baseRecord, summary)'));
  assert.ok(css.includes('@media(prefers-reduced-motion:reduce)'));
  assert.ok(css.includes('body[data-theme="high-contrast"]'));
  assert.ok(html.includes('id="toggleEntity"'));
  assert.ok(main.includes("localStorage.setItem('atlas-entity-collapsed'"));
  assert.ok(main.includes("setAttribute('aria-expanded', String(!collapsed))"));
});

test('investigation graph builds deterministic, explicitly classified canaries', () => {
  const canaries = [
    ['atlas:event:microsoft.windows.security:4625', 'Target User Name'],
    ['atlas:event:microsoft.windows.security:4688', 'New Process Name'],
    ['atlas:event:microsoft.sysmon:1', 'ProcessGuid']
  ];
  for (const [recordId, fieldTitle] of canaries) {
    const graph = investigation.build({
      detail_version: '1.0.0',
      record: { id: recordId, title: recordId },
      fields: [{ id: `${recordId}.field`, title: fieldTitle, canonical_key: fieldTitle }],
      sources: [{ id: `${recordId}.source`, title: 'Authoritative source' }]
    });
    assert.equal(graph.record_id, recordId);
    assert.equal(graph.confidence, 'UNASSESSED');
    assert.ok(graph.nodes.some(node => node.classification === 'FACT' && node.status === 'VERIFIED'));
    assert.ok(graph.nodes.some(node => node.classification === 'EVIDENCE REQUIREMENT'));
    assert.ok(graph.nodes.some(node => node.classification === 'HYPOTHESIS' && node.status === 'UNASSESSED'));
    assert.ok(graph.nodes.some(node => node.classification === 'CHECK'));
    assert.ok(graph.nodes.some(node => node.classification === 'PROVENANCE'));
    assert.ok(graph.edges.every(edge => ['REQUIRES_EVIDENCE', 'INFORMS', 'REQUIRES_CHECK', 'SUPPORTS_SEMANTICS'].includes(edge.type)));
  }
});

test('investigation graph refuses unsupported or incomplete records', () => {
  assert.equal(investigation.build(null), null);
  assert.equal(investigation.build({ detail_version: '1.0.0' }), null);
  assert.equal(investigation.build({ detail_version: '1.0.0', record: { id: 'atlas:event:unknown:1' } }), null);
  assert.ok(html.includes('A hypothesis is never promoted to fact by this view.'));
  assert.ok(html.includes('src="investigation-model.js"'));
});

test('canary acceptance fixtures remain synthetic, bounded and complete', () => {
  assert.equal(investigationFixtures.schema, 'atlas-investigation-fixtures/v0');
  assert.equal(investigationFixtures.fixture_only, true);
  assert.equal(investigationFixtures.canonical_corpus, false);
  assert.equal(investigationFixtures.scenarios.length, 9);
  const combinations = new Set(investigationFixtures.scenarios.map(item => `${item.record_id}:${item.case_kind}`));
  for (const recordId of Object.keys(investigation.PLAYBOOKS)) {
    for (const caseKind of investigation.CASE_KINDS) assert.ok(combinations.has(`${recordId}:${caseKind}`));
  }
});

test('explicit evidence produces deterministic support, refute and incomplete states', () => {
  for (const fixture of investigationFixtures.scenarios) {
    const base = investigation.build({
      detail_version: '1.0.0',
      record: { id: fixture.record_id, title: fixture.record_id },
      fields: [],
      sources: [{ id: `${fixture.record_id}.source`, title: 'Authoritative source' }]
    });
    const assessed = investigation.applyEvidence(base, fixture);
    assert.equal(assessed.scenario_id, fixture.scenario_id);
    assert.equal(assessed.case_kind, fixture.case_kind);
    assert.equal(assessed.nodes.filter(node => node.classification === 'EVIDENCE').length, fixture.observations.length);
    assert.ok(assessed.edges.every(edge => ['REQUIRES_EVIDENCE', 'INFORMS', 'REQUIRES_CHECK', 'SUPPORTS_SEMANTICS', 'DERIVED_FROM_RECORD_CONTEXT', 'SUPPORTS', 'REFUTES', 'UNKNOWN'].includes(edge.type)));
    if (fixture.case_kind === 'incomplete') {
      assert.equal(assessed.confidence, 'INCOMPLETE');
      assert.ok(assessed.nodes.filter(node => node.classification === 'HYPOTHESIS').every(node => node.status === 'UNASSESSED'));
    } else {
      assert.equal(assessed.confidence, 'BOUNDED-EVIDENCE');
      assert.ok(assessed.nodes.some(node => node.classification === 'HYPOTHESIS' && node.status !== 'UNASSESSED'));
    }
  }
});

test('evidence assessment fails closed on mismatched, duplicate or unbounded input', () => {
  const fixture = investigationFixtures.scenarios[0];
  const base = investigation.build({ detail_version: '1.0.0', record: { id: fixture.record_id }, fields: [], sources: [] });
  assert.throws(() => investigation.applyEvidence(base, { ...fixture, record_id: 'atlas:event:unknown:1' }), /does not match/);
  assert.throws(() => investigation.applyEvidence(base, { ...fixture, case_kind: 'invented' }), /not supported/);
  assert.throws(() => investigation.applyEvidence(base, { ...fixture, observations: [...fixture.observations, fixture.observations[0]] }), /duplicate observation/);
  assert.throws(() => investigation.applyEvidence(base, { ...fixture, observations: [{ ...fixture.observations[0], assessments: [{ hypothesis_id: 'hypothesis-99', effect: 'SUPPORTS' }] }] }), /unknown hypothesis/);
});
