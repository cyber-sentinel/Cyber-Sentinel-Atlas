'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..', '..');
const webRoot = path.join(root, 'benchmarks', 'desktop', 'phase56', 'candidates', 'tauri', 'www');
const guardSource = fs.readFileSync(path.join(webRoot, 'stale-selection-guard.js'), 'utf8');
const html = fs.readFileSync(path.join(webRoot, 'index.html'), 'utf8');

function element() {
  return {
    value: 'old',
    disabled: false,
    className: '',
    textContent: '',
    children: [],
    replaceChildren(...children) { this.children = children; }
  };
}

function harness(result) {
  const ids = [
    'graphSeed','openRecordView','recordGraphButton','recordInvestigationButton',
    'quickDetail','recordDetail','graphResults','investigationGraph',
    'investigationPurpose','investigationConfidence','entityPivots'
  ];
  const elements = new Map(ids.map(id => [id, element()]));
  const document = { getElementById: id => elements.get(id) || null };
  let metricsReset = false;
  const context = {
    state: {
      currentRecordId: 'atlas:event:microsoft.windows.security:4688',
      currentRecord: { id: 'old' },
      currentMatch: { target_id: 'old' },
      currentInvestigation: { id: 'old-investigation' },
      currentTab: 'fields'
    },
    el: (tag, className, content) => ({ tag, className, textContent: content || '' }),
    updateMetrics: value => { if (value === null) metricsReset = true; },
    runSearchQuery: async () => result,
    window: {},
    Array,
    Object,
    Promise
  };
  vm.createContext(context);
  // The stale-selection guard itself does not require a browser DOM during install.
  // Keep the minimal document out of the VM until after evaluation so the separate
  // acceptance-remediation UI layer does not auto-install against an incomplete DOM.
  vm.runInContext(guardSource, context);
  context.document = document;
  return { context, elements, metricsReset: () => metricsReset };
}

test('empty search clears every stale record-dependent state surface', async () => {
  const h = harness([]);
  const result = await h.context.runSearchQuery('4624');
  assert.deepEqual(Array.from(result), []);
  assert.equal(h.context.state.currentRecordId, null);
  assert.equal(h.context.state.currentRecord, null);
  assert.equal(h.context.state.currentMatch, null);
  assert.equal(h.context.state.currentInvestigation, null);
  assert.equal(h.context.state.currentTab, 'overview');
  assert.equal(h.elements.get('graphSeed').value, '');
  for (const id of ['openRecordView','recordGraphButton','recordInvestigationButton']) assert.equal(h.elements.get(id).disabled, true);
  assert.equal(h.elements.get('quickDetail').className, 'quick-detail empty-answer');
  assert.equal(h.elements.get('recordDetail').textContent, 'No record selected.');
  assert.equal(h.elements.get('entityPivots').children.length, 0);
  assert.equal(h.metricsReset(), true);
});

test('successful search preserves the currently selected record context', async () => {
  const h = harness([{ target_id: 'atlas:event:microsoft.windows.security:4624' }]);
  const result = await h.context.runSearchQuery('4624');
  assert.equal(result.length, 1);
  assert.equal(h.context.state.currentRecordId, 'atlas:event:microsoft.windows.security:4688');
  assert.equal(h.context.state.currentTab, 'fields');
  assert.equal(h.metricsReset(), false);
});

test('record-resolution failure represented as an empty result clears Entity focus and pivots', async () => {
  const h = harness([]);
  await h.context.runSearchQuery('record.get failed closed');
  assert.equal(h.context.state.currentRecordId, null);
  assert.equal(h.context.state.currentMatch, null);
  assert.equal(h.elements.get('entityPivots').children.length, 0);
  assert.equal(h.elements.get('recordDetail').textContent, 'No record selected.');
});

test('guard is loaded after main workspace script so it wraps the final search function', () => {
  const mainAt = html.indexOf('<script src="main.js"></script>');
  const guardAt = html.indexOf('<script src="stale-selection-guard.js"></script>');
  assert.ok(mainAt >= 0);
  assert.ok(guardAt > mainAt);
});
