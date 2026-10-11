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

  function installVisualMotion(doc) {
    if (!doc || typeof doc.querySelector !== 'function') return false;
    const visual = doc.querySelector('#entityVisual');
    const svg = visual && visual.querySelector('svg');
    if (!visual || !svg) return false;
    if (visual.dataset.motionInstalled === 'true') return true;
    visual.dataset.motionInstalled = 'true';

    const ns = 'http://www.w3.org/2000/svg';
    const make = (tag, attrs) => {
      const node = doc.createElementNS(ns, tag);
      Object.entries(attrs || {}).forEach(([key, value]) => node.setAttribute(key, String(value)));
      return node;
    };

    // Abstract, non-human gesture field: five light filaments behaving like a
    // synthetic hand that gathers and organizes evidence around the core.
    const gesture = make('g', { class: 'entity-gesture-field', 'aria-hidden': 'true' });
    [
      'M146 157 C176 143 202 120 230 92',
      'M149 158 C184 154 218 142 251 126',
      'M150 160 C190 165 221 169 257 168',
      'M148 162 C180 177 208 195 233 218',
      'M145 164 C167 187 181 215 190 245'
    ].forEach((d, index) => {
      gesture.appendChild(make('path', { d, class: `entity-finger finger-${index + 1}` }));
    });
    gesture.appendChild(make('path', {
      d: 'M137 151 C159 143 174 148 183 161 C170 181 152 188 132 176 C126 166 128 157 137 151Z',
      class: 'entity-palm'
    }));
    svg.appendChild(gesture);

    const style = doc.createElement('style');
    style.id = 'atlas-entity-motion-style';
    style.textContent = `
      #entityVisual svg{overflow:visible}
      #entityVisual .entity-gesture-field{transform-origin:150px 160px;opacity:.38;filter:drop-shadow(0 0 5px rgba(85,210,255,.35))}
      #entityVisual .entity-finger,#entityVisual .entity-palm{fill:none;stroke:var(--blue);stroke-width:1.4;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:5 7;vector-effect:non-scaling-stroke}
      #entityVisual .entity-palm{stroke-width:1.1;opacity:.7}
      #entityVisual .entity-particles circle{transform-box:fill-box;transform-origin:center}
      body[data-entity-mode="idle"] #entityVisual .entity-core{animation:atlasCoreBreathe 4.8s ease-in-out infinite}
      body[data-entity-mode="idle"] #entityVisual .entity-gesture-field{animation:atlasGestureIdle 6.5s ease-in-out infinite}
      body[data-entity-mode="searching"] #entityVisual .orbit-a{animation:atlasOrbitFast 1.6s linear infinite;transform-origin:150px 150px}
      body[data-entity-mode="searching"] #entityVisual .orbit-b{animation:atlasOrbitReverse 2.1s linear infinite;transform-origin:150px 150px}
      body[data-entity-mode="searching"] #entityVisual .entity-gesture-field{opacity:.8;animation:atlasGestureSearch 1.8s ease-in-out infinite}
      body[data-entity-mode="searching"] #entityVisual .entity-finger{animation:atlasDash .8s linear infinite}
      body[data-entity-mode="correlating"] #entityVisual .entity-particles circle{animation:atlasGather 1.6s ease-in-out infinite alternate}
      body[data-entity-mode="correlating"] #entityVisual .entity-gesture-field{opacity:.88;animation:atlasGestureCorrelate 2.2s cubic-bezier(.55,.06,.68,.19) infinite alternate}
      body[data-entity-mode="reasoning"] #entityVisual .entity-core{animation:atlasCoreReason 1.35s ease-in-out infinite alternate}
      body[data-entity-mode="reasoning"] #entityVisual .orbit-c{animation:atlasOrbitFast 1.15s linear infinite;transform-origin:150px 150px}
      body[data-entity-mode="reasoning"] #entityVisual .entity-gesture-field{opacity:.95;animation:atlasGestureReason 1.4s ease-in-out infinite alternate}
      body[data-entity-mode="reasoning"] #entityVisual .entity-finger{animation:atlasDash .55s linear infinite}
      body[data-entity-mode="finding"] #entityVisual .entity-core{animation:atlasFindingPulse 1.8s ease-out 2}
      body[data-entity-mode="finding"] #entityVisual .entity-gesture-field{opacity:.72;animation:atlasGestureFind 1.8s ease-out 1 forwards}
      body[data-entity-mode="warning"] #entityVisual .entity-core{animation:atlasWarning 1s ease-in-out infinite}
      body[data-entity-mode="warning"] #entityVisual .entity-gesture-field{opacity:.72;animation:atlasWarningGesture .8s steps(2,end) infinite}
      @keyframes atlasCoreBreathe{0%,100%{transform:scale(.98);opacity:.84}50%{transform:scale(1.06);opacity:1}}
      @keyframes atlasOrbitFast{to{transform:rotate(360deg)}}
      @keyframes atlasOrbitReverse{to{transform:rotate(-360deg)}}
      @keyframes atlasDash{to{stroke-dashoffset:-24}}
      @keyframes atlasGestureIdle{0%,100%{transform:translate(-2px,2px) rotate(-4deg)}50%{transform:translate(4px,-5px) rotate(5deg)}}
      @keyframes atlasGestureSearch{0%,100%{transform:translate(-13px,9px) rotate(-14deg) scale(.94)}50%{transform:translate(9px,-8px) rotate(11deg) scale(1.07)}}
      @keyframes atlasGestureCorrelate{0%{transform:translate(13px,-12px) rotate(16deg) scale(1.08)}100%{transform:translate(-5px,5px) rotate(-7deg) scale(.9)}}
      @keyframes atlasGestureReason{0%{transform:translate(-7px,5px) rotate(-9deg) skewX(-3deg)}100%{transform:translate(5px,-4px) rotate(8deg) skewX(4deg)}}
      @keyframes atlasGestureFind{0%{transform:translate(8px,-9px) rotate(10deg) scale(1.08)}100%{transform:translate(0,0) rotate(0) scale(1)}}
      @keyframes atlasGather{0%{transform:scale(.75);opacity:.45}100%{transform:scale(1.4);opacity:1}}
      @keyframes atlasCoreReason{0%{transform:scale(.95);filter:brightness(.9)}100%{transform:scale(1.1);filter:brightness(1.35)}}
      @keyframes atlasFindingPulse{0%{transform:scale(.96)}45%{transform:scale(1.14)}100%{transform:scale(1)}}
      @keyframes atlasWarning{0%,100%{transform:scale(.98);opacity:.72}50%{transform:scale(1.05);opacity:1}}
      @keyframes atlasWarningGesture{0%{transform:translateX(-3px)}100%{transform:translateX(3px)}}
      @media (prefers-reduced-motion:reduce){
        #entityVisual *,#entityVisual .entity-gesture-field{animation:none!important;transition:none!important}
        #entityVisual .entity-gesture-field{transform:none!important;opacity:.5}
      }
    `;
    if (!doc.getElementById(style.id)) doc.head.appendChild(style);
    return true;
  }

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => installVisualMotion(document), { once: true });
    } else {
      installVisualMotion(document);
    }
  }

  return Object.freeze({ MODES, DEFAULT_DETAILS, normalizeMode, create, fromOperation, installVisualMotion });
}));
