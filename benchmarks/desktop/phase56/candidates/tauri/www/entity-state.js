(function exposeAtlasEntityState(root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.AtlasEntityState = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function buildAtlasEntityState() {
  'use strict';

  const MODES = Object.freeze([
    'idle',
    'searching',
    'correlating',
    'reasoning',
    'finding',
    'warning'
  ]);

  const DEFAULT_DETAILS = Object.freeze({
    idle: 'Awaiting a verified analyst action.',
    searching: 'Resolving a bounded query against the active local pack.',
    correlating: 'Loading canonical facts, claims and source lineage.',
    reasoning: 'Evaluating explicit relationship and evidence structures.',
    finding: 'Verified evidence is ready for analyst review.',
    warning: 'A trust, integrity or runtime boundary requires attention.'
  });

  function normalizeMode(mode) {
    return MODES.includes(mode) ? mode : 'warning';
  }

  function create(mode, detail) {
    const normalized = normalizeMode(mode);
    const safeDetail = typeof detail === 'string' && detail.trim()
      ? detail.trim().slice(0, 240)
      : DEFAULT_DETAILS[normalized];
    return Object.freeze({
      mode: normalized,
      label: normalized.toUpperCase(),
      detail: safeDetail,
      warning: normalized === 'warning'
    });
  }

  function fromOperation(operation) {
    if (!operation || typeof operation !== 'object') return create('warning');
    if (operation.error) return create('warning', operation.detail);
    switch (operation.phase) {
      case 'search': return create('searching', operation.detail);
      case 'record': return create('correlating', operation.detail);
      case 'graph': return create('reasoning', operation.detail);
      case 'result': return create('finding', operation.detail);
      case 'ready':
      case 'idle': return create('idle', operation.detail);
      default: return create('warning', operation.detail);
    }
  }

  return Object.freeze({ MODES, DEFAULT_DETAILS, normalizeMode, create, fromOperation });
}));
