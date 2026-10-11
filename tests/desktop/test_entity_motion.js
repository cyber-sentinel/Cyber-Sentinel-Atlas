'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..', '..');
const entity = require(path.join(root, 'benchmarks', 'desktop', 'phase56', 'candidates', 'tauri', 'www', 'entity-state.js'));

function fakeDocument() {
  const nodes = new Map();
  return {
    head: {
      appendChild(node) { nodes.set(node.id, node); }
    },
    createElement(tag) { return { tagName: tag.toUpperCase(), id: '', textContent: '' }; },
    getElementById(id) { return nodes.get(id) || null; },
    nodes
  };
}

test('ATLAS Entity motion profiles are bounded and distinct for all six approved states', () => {
  assert.deepEqual(Object.keys(entity.MOTION_PROFILES), entity.MODES);
  const serialized = new Set();
  for (const mode of entity.MODES) {
    const profile = entity.MOTION_PROFILES[mode];
    assert.deepEqual(Object.keys(profile).sort(), ['core','cortex','evidence','hands','trust'].sort());
    serialized.add(JSON.stringify(profile));
    const state = entity.create(mode);
    assert.equal(state.motion, profile);
  }
  assert.equal(serialized.size, 6, 'each state must have a visually distinct motion profile');
});

test('correlation and reasoning use articulated hand fields while warning breaks trust state', () => {
  assert.equal(entity.MOTION_PROFILES.idle.hands, 'hidden');
  assert.equal(entity.MOTION_PROFILES.searching.hands, 'hidden');
  assert.equal(entity.MOTION_PROFILES.correlating.hands, 'group');
  assert.equal(entity.MOTION_PROFILES.reasoning.hands, 'balance');
  assert.equal(entity.MOTION_PROFILES.finding.hands, 'release');
  assert.equal(entity.MOTION_PROFILES.warning.hands, 'hidden');
  assert.equal(entity.MOTION_PROFILES.reasoning.trust, 'segmented');
  assert.equal(entity.MOTION_PROFILES.warning.trust, 'broken');
});

test('visual layer installs once and carries state-driven and reduced-motion contracts', () => {
  const doc = fakeDocument();
  assert.equal(entity.installVisualLayer(doc), true);
  assert.equal(entity.installVisualLayer(doc), true);
  assert.equal(doc.nodes.size, 1);
  const css = [...doc.nodes.values()][0].textContent;
  for (const mode of entity.MODES) assert.ok(css.includes(`body[data-entity-mode="${mode}"]`), `missing ${mode} visual selector`);
  assert.ok(css.includes('#entityVisual::before'));
  assert.ok(css.includes('#entityVisual::after'));
  assert.ok(css.includes('@media(prefers-reduced-motion:reduce)'));
  assert.ok(css.includes('entityHandLeft'));
  assert.ok(css.includes('entityHandRight'));
  assert.ok(css.includes('entityWarnRing'));
  assert.ok(css.includes('entityResolve'));
});

test('visual layer renderer failure is isolated from the state adapter', () => {
  assert.equal(entity.installVisualLayer(null), false);
  assert.doesNotThrow(() => entity.create('searching'));
  assert.equal(entity.create('unknown').mode, 'warning');
});
