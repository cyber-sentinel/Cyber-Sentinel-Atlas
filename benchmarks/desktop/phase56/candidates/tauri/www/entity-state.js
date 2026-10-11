(function exposeAtlasEntityState(root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.AtlasEntityState = api;
  if (root && root.document) api.installVisualLayer(root.document);
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

  const MOTION_PROFILES = Object.freeze({
    idle: Object.freeze({ core: 'breathe', cortex: 'drift', evidence: 'orbit', hands: 'hidden', trust: 'stable' }),
    searching: Object.freeze({ core: 'scan-pulse', cortex: 'scan', evidence: 'ingress', hands: 'hidden', trust: 'stable' }),
    correlating: Object.freeze({ core: 'steady', cortex: 'link', evidence: 'align', hands: 'group', trust: 'stable' }),
    reasoning: Object.freeze({ core: 'reason-pulse', cortex: 'counter-rotate', evidence: 'cluster', hands: 'balance', trust: 'segmented' }),
    finding: Object.freeze({ core: 'resolve-pulse', cortex: 'settle', evidence: 'motif', hands: 'release', trust: 'stable' }),
    warning: Object.freeze({ core: 'asymmetric-pulse', cortex: 'bounded-jitter', evidence: 'detach', hands: 'hidden', trust: 'broken' })
  });

  const DEFAULT_DETAILS = Object.freeze({
    idle: 'Awaiting a verified analyst action.',
    searching: 'Resolving a bounded query against the active local pack.',
    correlating: 'Loading canonical facts, claims and source lineage.',
    reasoning: 'Evaluating explicit relationship and evidence structures.',
    finding: 'Verified evidence is ready for analyst review.',
    warning: 'A trust, integrity or runtime boundary requires attention.'
  });

  const VISUAL_LAYER_ID = 'atlas-entity-motion-v1';
  const VISUAL_CSS = `
#entityVisual{position:relative;isolation:isolate;--entity-accent:var(--blue);--entity-trust:var(--green);--entity-hand-opacity:0;--entity-motion-scale:1}
#entityVisual::before,#entityVisual::after{content:"";position:absolute;z-index:0;top:82px;width:66px;height:102px;opacity:var(--entity-hand-opacity);pointer-events:none;border:1px solid color-mix(in srgb,var(--entity-accent) 54%,transparent);background:linear-gradient(145deg,color-mix(in srgb,var(--entity-accent) 13%,transparent),transparent 72%);filter:drop-shadow(0 0 12px color-mix(in srgb,var(--entity-accent) 22%,transparent));clip-path:polygon(48% 0,61% 28%,76% 9%,80% 40%,97% 28%,88% 58%,100% 67%,72% 72%,63% 100%,43% 77%,13% 88%,28% 63%,0 51%,31% 43%);transform-origin:50% 72%;transition:opacity .22s ease,transform .35s ease}
#entityVisual::before{left:8px;transform:rotate(-22deg) translateX(-8px)}
#entityVisual::after{right:8px;transform:scaleX(-1) rotate(-22deg) translateX(-8px)}
#entityVisual svg{position:relative;z-index:1}
.entity-orbit,.entity-halo,.entity-links line,.entity-particles circle,.entity-core,.entity-eye,.entity-pupil{will-change:transform,opacity,filter,stroke-dashoffset}
body[data-entity-mode="idle"] .entity-core{animation:entityBreathe 4.8s ease-in-out infinite}
body[data-entity-mode="idle"] .orbit-a{animation:entitySpin 18s linear infinite}
body[data-entity-mode="idle"] .orbit-b{animation:entitySpinReverse 24s linear infinite}
body[data-entity-mode="idle"] .entity-particles{animation:entityFloat 7s ease-in-out infinite}
body[data-entity-mode="searching"] #entityVisual{--entity-motion-scale:1.08}
body[data-entity-mode="searching"] .orbit-a{stroke-width:1.7;stroke-dasharray:22 10;animation:entitySpin 1.35s linear infinite,entityScanGlow 1.1s ease-in-out infinite}
body[data-entity-mode="searching"] .orbit-b{animation:entitySpinReverse 2.2s linear infinite}
body[data-entity-mode="searching"] .entity-core{animation:entitySearchPulse .92s ease-in-out infinite}
body[data-entity-mode="searching"] .entity-links line{stroke-dasharray:10 8;animation:entityTrail .72s linear infinite}
body[data-entity-mode="searching"] .entity-particles circle:nth-child(odd){animation:entityIngressOdd 1.45s ease-in-out infinite}
body[data-entity-mode="searching"] .entity-particles circle:nth-child(even){animation:entityIngressEven 1.7s ease-in-out infinite}
body[data-entity-mode="correlating"] #entityVisual{--entity-hand-opacity:.72}
body[data-entity-mode="correlating"] #entityVisual::before{animation:entityHandLeft 2.3s ease-in-out infinite}
body[data-entity-mode="correlating"] #entityVisual::after{animation:entityHandRight 2.3s ease-in-out infinite}
body[data-entity-mode="correlating"] .orbit-c{animation:entitySpin 2.25s linear infinite}
body[data-entity-mode="correlating"] .entity-links line{stroke:color-mix(in srgb,var(--entity-accent) 55%,transparent);stroke-width:1.5;stroke-dasharray:4 4;animation:entityTrail 1s linear infinite}
body[data-entity-mode="correlating"] .entity-particles circle{animation:entityNodeAlign 1.8s ease-in-out infinite alternate}
body[data-entity-mode="reasoning"] #entityVisual{--entity-hand-opacity:.38}
body[data-entity-mode="reasoning"] #entityVisual::before{transform:rotate(-8deg) translate(12px,-4px)}
body[data-entity-mode="reasoning"] #entityVisual::after{transform:scaleX(-1) rotate(-8deg) translate(12px,-4px)}
body[data-entity-mode="reasoning"] .entity-core{animation:entityReasonPulse 1.55s ease-in-out infinite}
body[data-entity-mode="reasoning"] .orbit-a{animation:entitySpin 4.2s linear infinite}
body[data-entity-mode="reasoning"] .orbit-b{animation:entitySpinReverse 3.3s linear infinite}
body[data-entity-mode="reasoning"] .entity-halo{stroke-dasharray:18 7 3 7;stroke-width:1.8;animation:entitySpin 6s linear infinite}
body[data-entity-mode="reasoning"] .entity-particles circle:nth-child(1),body[data-entity-mode="reasoning"] .entity-particles circle:nth-child(4){animation:entityClusterA 1.9s ease-in-out infinite alternate}
body[data-entity-mode="reasoning"] .entity-particles circle:nth-child(2),body[data-entity-mode="reasoning"] .entity-particles circle:nth-child(5){animation:entityClusterB 2.1s ease-in-out infinite alternate}
body[data-entity-mode="reasoning"] .entity-particles circle:nth-child(3),body[data-entity-mode="reasoning"] .entity-particles circle:nth-child(6){animation:entityClusterC 2.3s ease-in-out infinite alternate}
body[data-entity-mode="finding"] #entityVisual{--entity-hand-opacity:.18}
body[data-entity-mode="finding"] .entity-core{animation:entityResolve 1.45s cubic-bezier(.2,.7,.2,1) 2}
body[data-entity-mode="finding"] .entity-halo{stroke:var(--entity-trust);stroke-width:2;animation:entityOutward 1.45s ease-out 2}
body[data-entity-mode="finding"] .entity-links line{stroke:color-mix(in srgb,var(--entity-trust) 58%,transparent);stroke-width:1.5}
body[data-entity-mode="finding"] .entity-particles circle{filter:drop-shadow(0 0 9px var(--entity-trust));animation:entityMotif 1.45s ease-out 2}
body[data-entity-mode="warning"] #entityVisual{--entity-accent:var(--amber);--entity-trust:var(--amber)}
body[data-entity-mode="warning"] .entity-core{animation:entityWarnCore .72s ease-in-out infinite alternate}
body[data-entity-mode="warning"] .entity-halo{stroke:var(--amber);stroke-width:2.2;stroke-dasharray:28 18 4 24;animation:entityWarnRing 2.1s linear infinite}
body[data-entity-mode="warning"] .entity-orbit{stroke:color-mix(in srgb,var(--amber) 34%,transparent)}
body[data-entity-mode="warning"] .entity-links line{stroke:color-mix(in srgb,var(--amber) 42%,transparent);stroke-dasharray:2 7}
body[data-entity-mode="warning"] .entity-particles circle{fill:var(--amber);animation:entityJitter .55s steps(2,end) infinite}
@keyframes entitySpin{to{transform:rotate(360deg)}}
@keyframes entitySpinReverse{to{transform:rotate(-360deg)}}
@keyframes entityBreathe{0%,100%{transform:scale(.97);opacity:.9}50%{transform:scale(1.045);opacity:1}}
@keyframes entityFloat{0%,100%{transform:translateY(-2px)}50%{transform:translateY(3px)}}
@keyframes entityScanGlow{50%{stroke:var(--entity-accent);filter:drop-shadow(0 0 8px var(--entity-accent))}}
@keyframes entitySearchPulse{0%,100%{transform:scale(.96)}50%{transform:scale(1.09);filter:brightness(1.28)}}
@keyframes entityTrail{to{stroke-dashoffset:-36}}
@keyframes entityIngressOdd{0%,100%{transform:translate(0,0);opacity:.66}50%{transform:translate(16px,10px);opacity:1}}
@keyframes entityIngressEven{0%,100%{transform:translate(0,0);opacity:.58}50%{transform:translate(-14px,12px);opacity:1}}
@keyframes entityHandLeft{0%,100%{transform:rotate(-24deg) translateX(-9px)}50%{transform:rotate(-8deg) translate(13px,-3px)}}
@keyframes entityHandRight{0%,100%{transform:scaleX(-1) rotate(-24deg) translateX(-9px)}50%{transform:scaleX(-1) rotate(-8deg) translate(13px,-3px)}}
@keyframes entityNodeAlign{to{filter:drop-shadow(0 0 11px var(--entity-accent));opacity:1}}
@keyframes entityReasonPulse{0%,100%{transform:scale(.98)}50%{transform:scale(1.075);filter:brightness(1.2)}}
@keyframes entityClusterA{to{transform:translate(11px,8px);opacity:1}}
@keyframes entityClusterB{to{transform:translate(-10px,10px);opacity:.84}}
@keyframes entityClusterC{to{transform:translate(3px,-9px);opacity:.7}}
@keyframes entityResolve{0%{transform:scale(1)}28%{transform:scale(.9)}58%{transform:scale(1.14);filter:brightness(1.4)}100%{transform:scale(1)}}
@keyframes entityOutward{0%{transform:scale(.76);opacity:.95}100%{transform:scale(1.5);opacity:0}}
@keyframes entityMotif{0%{opacity:.62}55%,100%{opacity:1;filter:drop-shadow(0 0 10px var(--entity-trust))}}
@keyframes entityWarnCore{from{transform:translate(-2px,1px) scale(.98)}to{transform:translate(3px,-2px) scale(1.045);filter:brightness(1.18)}}
@keyframes entityWarnRing{to{stroke-dashoffset:-74;transform:rotate(18deg)}}
@keyframes entityJitter{0%{transform:translate(-2px,1px)}50%{transform:translate(2px,-1px)}100%{transform:translate(-1px,-2px)}}
@media(prefers-reduced-motion:reduce){#entityVisual::before,#entityVisual::after,.entity-orbit,.entity-halo,.entity-links line,.entity-particles circle,.entity-particles,.entity-core{animation:none!important;transition:none!important}body[data-entity-mode="correlating"] #entityVisual::before{transform:rotate(-8deg) translate(12px,-4px)}body[data-entity-mode="correlating"] #entityVisual::after{transform:scaleX(-1) rotate(-8deg) translate(12px,-4px)}body[data-entity-mode="warning"] .entity-halo{stroke-dasharray:28 18 4 24}body[data-entity-mode="reasoning"] .entity-halo{stroke-dasharray:18 7 3 7}}
`;

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
      warning: normalized === 'warning',
      motion: MOTION_PROFILES[normalized]
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

  function installVisualLayer(doc) {
    try {
      if (!doc || typeof doc.createElement !== 'function' || !doc.head) return false;
      if (doc.getElementById(VISUAL_LAYER_ID)) return true;
      const style = doc.createElement('style');
      style.id = VISUAL_LAYER_ID;
      style.textContent = VISUAL_CSS;
      doc.head.appendChild(style);
      return true;
    } catch (_) {
      return false;
    }
  }

  return Object.freeze({ MODES, MOTION_PROFILES, DEFAULT_DETAILS, normalizeMode, create, fromOperation, installVisualLayer });
}));
