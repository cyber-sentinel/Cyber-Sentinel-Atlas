'use strict';

const invoke = window.__TAURI__.core.invoke;
const atlas = Object.freeze({
  status: () => invoke('core_status'),
  search: (query, limit) => invoke('search_records', { query, limit }),
  record: id => invoke('get_record', { id }),
  graph: (seedId, depth) => invoke('expand_graph', { seedId, depth }),
  packStatus: () => invoke('pack_status'),
  packUpdate: () => invoke('pack_update'),
  packRollback: () => invoke('pack_rollback')
});

const state = {
  currentRecordId: null,
  currentRecord: null,
  lastStatus: null,
  lastPack: null
};

const $ = id => document.getElementById(id);

function text(value) {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

function setNotice(message, kind = 'info') {
  const node = $('globalNotice');
  node.className = `notice ${kind}`;
  node.textContent = message;
}

function setBadge(node, label, kind = 'neutral') {
  node.className = `status-pill ${kind}`;
  node.textContent = label;
}

function clear(node) {
  node.replaceChildren();
}

function el(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content !== undefined) node.textContent = content;
  return node;
}

function jsonBlock(value) {
  const pre = el('pre', 'json-block');
  pre.textContent = JSON.stringify(value, null, 2);
  return pre;
}

function showView(name) {
  document.querySelectorAll('.view').forEach(panel => {
    panel.classList.toggle('active', panel.dataset.viewPanel === name);
  });
  document.querySelectorAll('.nav-item').forEach(button => {
    const active = button.dataset.view === name;
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
  $('workspace').focus({ preventScroll: true });
}

function compactValue(value) {
  if (Array.isArray(value)) return value.slice(0, 4).map(text).join(', ');
  if (value && typeof value === 'object') return JSON.stringify(value);
  return text(value);
}

function renderFacts(container, object, preferredKeys = []) {
  clear(container);
  const keys = [];
  preferredKeys.forEach(key => {
    if (Object.prototype.hasOwnProperty.call(object || {}, key)) keys.push(key);
  });
  Object.keys(object || {}).forEach(key => {
    if (!keys.includes(key) && !['claims', 'sources', 'provenance', 'relationships'].includes(key)) keys.push(key);
  });
  keys.slice(0, 18).forEach(key => {
    const row = document.createElement('div');
    const dt = el('dt', '', key.replaceAll('_', ' '));
    const dd = el('dd', '', compactValue(object[key]));
    row.append(dt, dd);
    container.append(row);
  });
  if (!keys.length) {
    const row = document.createElement('div');
    row.append(el('dt', '', 'Status'), el('dd', '', 'No fields returned'));
    container.append(row);
  }
}

function collectEvidenceSections(value, path = '', out = []) {
  if (!value || typeof value !== 'object') return out;
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectEvidenceSections(item, `${path}[${index}]`, out));
    return out;
  }
  Object.entries(value).forEach(([key, child]) => {
    const nextPath = path ? `${path}.${key}` : key;
    if (/(claim|source|provenance|evidence|reference)/i.test(key)) {
      out.push({ path: nextPath, value: child });
    }
    collectEvidenceSections(child, nextPath, out);
  });
  return out;
}

function claimValue(claim) {
  const object = claim?.object;
  if (!object || typeof object !== 'object') return null;
  return object.value ?? null;
}

function renderFieldDictionary(detail, container) {
  const fields = Array.isArray(detail?.fields) ? detail.fields : [];
  const claims = Array.isArray(detail?.claims) ? detail.claims : [];
  if (!fields.length) return;

  const section = el('section', 'detail-section field-dictionary');
  const heading = el('div', 'detail-section-heading');
  heading.append(el('strong', '', 'Field Dictionary'));
  heading.append(el('span', 'muted', `${fields.length} structured field${fields.length === 1 ? '' : 's'}`));
  section.append(heading);

  const claimsBySubject = new Map();
  claims.forEach(claim => {
    const subject = claim?.subject_id;
    if (!subject) return;
    if (!claimsBySubject.has(subject)) claimsBySubject.set(subject, []);
    claimsBySubject.get(subject).push(claim);
  });

  fields.forEach(field => {
    const card = el('article', 'field-card');
    card.append(el('div', 'field-name', field?.title || field?.canonical_key || field?.id || 'Field'));
    if (field?.id) card.append(el('div', 'field-id', field.id));

    const fieldClaims = claimsBySubject.get(field?.id) || [];
    fieldClaims.forEach(claim => {
      const value = claimValue(claim);
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        const facts = el('dl', 'facts compact-facts');
        renderFacts(facts, value, [
          'section', 'native_name', 'data_type', 'meaning', 'version_applicability',
          'optional', 'conditional', 'collection_requirement', 'security_relevance'
        ]);
        card.append(facts);
      } else if (value !== null) {
        card.append(el('div', 'field-meaning', compactValue(value)));
      }

      const evidence = Array.isArray(claim?.evidence) ? claim.evidence : [];
      evidence.slice(0, 3).forEach(item => {
        const source = item?.source_id || 'source';
        const locator = item?.locator?.heading || item?.locator?.section || '';
        card.append(el('div', 'field-source', locator ? `${source} · ${locator}` : source));
      });
    });

    section.append(card);
  });
  container.append(section);
}

function renderReferenceSources(detail, container) {
  const sources = Array.isArray(detail?.sources) ? detail.sources : [];
  if (!sources.length) return;
  const section = el('section', 'detail-section');
  section.append(el('strong', '', 'Sources / Provenance'));
  sources.slice(0, 8).forEach(source => {
    const row = el('div', 'source-row');
    row.append(el('span', 'source-title', source?.title || source?.canonical_key || source?.id || 'Source'));
    if (source?.id) row.append(el('span', 'source-id', source.id));
    section.append(row);
  });
  container.append(section);
}

function renderRecord(record, target) {
  clear(target);
  target.classList.remove('empty-state');

  const detail = record?.detail_version ? record : null;
  const baseRecord = detail?.record || record || {};
  const summary = el('div', 'record-summary');
  const title = baseRecord?.title || baseRecord?.name || state.currentRecordId || 'Canonical record';
  summary.append(el('div', 'record-title', title));
  if (state.currentRecordId) summary.append(el('div', 'record-id', state.currentRecordId));

  const facts = el('dl', 'facts');
  renderFacts(facts, baseRecord, [
    'entity_type', 'namespace', 'platform', 'product', 'provider', 'channel', 'lifecycle', 'version'
  ]);
  summary.append(facts);

  if (detail) {
    renderFieldDictionary(detail, summary);

    const recordClaims = (Array.isArray(detail.claims) ? detail.claims : [])
      .filter(claim => claim?.subject_id === baseRecord?.id);
    if (recordClaims.length) {
      const box = el('section', 'provenance-box');
      box.append(el('strong', '', 'Record Claims'));
      recordClaims.slice(0, 16).forEach(claim => {
        const item = document.createElement('details');
        const heading = document.createElement('summary');
        heading.textContent = claim?.predicate || claim?.id || 'Claim';
        item.append(heading, jsonBlock(claimValue(claim) ?? claim));
        box.append(item);
      });
      summary.append(box);
    }

    renderReferenceSources(detail, summary);

    const relationCount = Array.isArray(detail.relationships) ? detail.relationships.length : 0;
    if (relationCount) {
      summary.append(el('div', 'detail-count-note', `${relationCount} direct relationship${relationCount === 1 ? '' : 's'} available in this bounded detail projection.`));
    }
  } else {
    const evidence = collectEvidenceSections(baseRecord).slice(0, 12);
    if (evidence.length) {
      const box = el('section', 'provenance-box');
      box.append(el('strong', '', 'Claims / Sources / Provenance'));
      evidence.forEach(item => {
        const detailNode = document.createElement('details');
        const heading = document.createElement('summary');
        heading.textContent = item.path;
        detailNode.append(heading, jsonBlock(item.value));
        box.append(detailNode);
      });
      summary.append(box);
    }
  }

  const raw = document.createElement('details');
  const rawHeading = document.createElement('summary');
  rawHeading.textContent = detail ? 'Detail Projection JSON' : 'Canonical JSON';
  raw.append(rawHeading, jsonBlock(record));
  summary.append(raw);
  target.append(summary);
}

async function loadRecord(id, openRecordView = false) {
  if (!id) return;
  setNotice(`Loading canonical record ${id}…`, 'info');
  try {
    const record = await atlas.record(id);
    state.currentRecordId = id;
    state.currentRecord = record;
    $('graphSeed').value = id;
    $('openRecordView').disabled = false;
    $('recordGraphButton').disabled = false;
    renderRecord(record, $('quickDetail'));
    renderRecord(record, $('recordDetail'));
    setNotice('Canonical record loaded from the verified active pack.', 'success');
    if (openRecordView) showView('record');
  } catch (error) {
    setNotice(`Record load failed closed: ${String(error)}`, 'danger');
  }
}

function renderSearchResults(result) {
  const container = $('searchResults');
  clear(container);
  container.classList.remove('empty-state');
  const matches = Array.isArray(result?.matches) ? result.matches : [];
  $('resultCount').textContent = String(matches.length);
  $('searchMeta').textContent = `${text(result?.status)} · ${text(result?.match_stage)}`;
  if (!matches.length) {
    container.classList.add('empty-state');
    container.textContent = 'No matching canonical records.';
    return;
  }
  matches.forEach(match => {
    const button = el('button', 'result-card');
    button.type = 'button';
    button.dataset.recordId = match.target_id || '';
    button.append(el('span', 'result-title', match.title || match.target_id || 'Untitled record'));
    const meta = el('span', 'result-meta');
    [match.entity_type, match.platform, match.product, match.provider, match.match_reason]
      .filter(Boolean)
      .forEach(value => meta.append(el('span', 'token', String(value))));
    button.append(meta);
    button.addEventListener('click', async () => {
      document.querySelectorAll('.result-card').forEach(card => card.classList.remove('selected'));
      button.classList.add('selected');
      await loadRecord(match.target_id, false);
    });
    container.append(button);
  });
}

async function runSearch(event) {
  event.preventDefault();
  const query = $('searchInput').value.trim();
  const limit = Number($('searchLimit').value);
  if (!query) return;
  setNotice('Running bounded offline search…', 'info');
  $('searchMeta').textContent = 'Searching…';
  try {
    const result = await atlas.search(query, limit);
    renderSearchResults(result);
    setNotice('Search completed locally against the active verified pack.', 'success');
  } catch (error) {
    $('searchMeta').textContent = 'Search failed';
    setNotice(`Search failed closed: ${String(error)}`, 'danger');
  }
}

function findPivotId(pivot) {
  if (!pivot || typeof pivot !== 'object') return null;
  for (const key of ['target_id', 'id', 'to_id', 'from_id', 'source_id']) {
    if (typeof pivot[key] === 'string' && pivot[key]) return pivot[key];
  }
  return null;
}

function renderGraph(result) {
  const container = $('graphResults');
  clear(container);
  container.classList.remove('empty-state');
  const pivots = Array.isArray(result?.pivots) ? result.pivots : [];
  if (!pivots.length) {
    container.classList.add('empty-state');
    container.textContent = 'No relationship pivots returned for this bounded expansion.';
    return;
  }
  const list = el('div', 'pivot-list');
  pivots.forEach((pivot, index) => {
    const card = el('article', 'pivot-card');
    const pivotId = findPivotId(pivot);
    card.append(el('strong', '', pivot?.relationship_type || pivot?.type || `Pivot ${index + 1}`));
    card.append(jsonBlock(pivot));
    if (pivotId) {
      const button = el('button', 'text-button', `Open ${pivotId}`);
      button.type = 'button';
      button.addEventListener('click', () => loadRecord(pivotId, true));
      card.append(button);
    }
    list.append(card);
  });
  container.append(list);
}

async function runGraph(event) {
  event.preventDefault();
  const seedId = $('graphSeed').value.trim();
  const depth = Number($('graphDepth').value);
  if (!seedId) return;
  setNotice('Expanding bounded relationships in Shared Core…', 'info');
  try {
    const result = await atlas.graph(seedId, depth);
    renderGraph(result);
    setNotice('Relationship expansion completed locally.', 'success');
  } catch (error) {
    setNotice(`Graph expansion failed closed: ${String(error)}`, 'danger');
  }
}

function renderPack(pack) {
  state.lastPack = pack;
  renderFacts($('packFacts'), pack || {}, [
    'ready', 'state', 'pack_id', 'pack_version', 'generation_id', 'manifest_digest', 'pending_update', 'rollback_available'
  ]);
  if (pack?.ready) setBadge($('packBadge'), `Pack ${pack.pack_version || 'ready'}`, 'success');
  else setBadge($('packBadge'), 'Pack not ready', 'warning');
  $('applyUpdate').disabled = pack?.pending_update !== true;
  $('rollbackPack').disabled = pack?.rollback_available !== true;
}

async function refreshPack() {
  try {
    const pack = await atlas.packStatus();
    renderPack(pack);
    return pack;
  } catch (error) {
    setBadge($('packBadge'), 'Pack error', 'danger');
    setNotice(`Pack state failed closed: ${String(error)}`, 'danger');
    throw error;
  }
}

async function runPackAction(kind) {
  const isUpdate = kind === 'update';
  const prompt = isUpdate
    ? 'Apply the already-verified pending pack update? Shared Core trust checks remain authoritative.'
    : 'Rollback to the safe Last Known Good pack generation?';
  if (!window.confirm(prompt)) return;
  const output = $('packActionResult');
  output.textContent = isUpdate ? 'Applying verified update…' : 'Executing safe rollback…';
  try {
    const result = isUpdate ? await atlas.packUpdate() : await atlas.packRollback();
    output.textContent = JSON.stringify(result, null, 2);
    await refreshPack();
    setNotice(isUpdate ? 'Verified pack update completed.' : 'Safe rollback completed.', 'success');
  } catch (error) {
    output.textContent = `FAIL-CLOSED: ${String(error)}`;
    setNotice(`Pack control failed closed: ${String(error)}`, 'danger');
  }
}

function renderDiagnostics(status) {
  $('diagnosticsOutput').textContent = JSON.stringify(status, null, 2);
  const core = status?.status_result || {};
  const offline = core?.offline_capable === true && core?.network_listener === false;
  if (offline) {
    setBadge($('offlineBadge'), 'Offline boundary verified', 'success');
    $('footerState').textContent = `Verified sidecar · ${String(status.sidecar_sha256 || '').slice(0, 12)}…`;
  } else {
    setBadge($('offlineBadge'), 'Boundary check failed', 'danger');
    $('footerState').textContent = 'Runtime boundary not verified';
  }
}

async function refreshDiagnostics() {
  try {
    const status = await atlas.status();
    state.lastStatus = status;
    renderDiagnostics(status);
    return status;
  } catch (error) {
    setBadge($('offlineBadge'), 'Core unavailable', 'danger');
    $('diagnosticsOutput').textContent = `FAIL-CLOSED\n${String(error)}`;
    $('footerState').textContent = 'Fail-closed: Shared Core validation failed';
    throw error;
  }
}

function formatClock(date, timeZone, locale = 'en-GB') {
  const options = {
    dateStyle: 'medium',
    timeStyle: 'medium',
    hour12: false
  };
  if (timeZone) options.timeZone = timeZone;
  return new Intl.DateTimeFormat(locale, options).format(date);
}

function updateClocks() {
  const now = new Date();
  $('utcClock').textContent = formatClock(now, 'UTC');
  $('systemClock').textContent = formatClock(now, undefined);
  const selected = $('timezoneSelect').value;
  $('selectedClock').textContent = selected === 'system' ? formatClock(now, undefined) : formatClock(now, selected);
  $('tehranClock').textContent = formatClock(now, 'Asia/Tehran', 'fa-IR-u-ca-persian');
}

function bindEvents() {
  document.querySelectorAll('.nav-item').forEach(button => {
    button.addEventListener('click', () => showView(button.dataset.view));
  });
  $('searchForm').addEventListener('submit', runSearch);
  $('graphForm').addEventListener('submit', runGraph);
  $('openRecordView').addEventListener('click', () => showView('record'));
  $('recordGraphButton').addEventListener('click', () => {
    if (state.currentRecordId) $('graphSeed').value = state.currentRecordId;
    showView('graph');
  });
  $('refreshPack').addEventListener('click', refreshPack);
  $('applyUpdate').addEventListener('click', () => runPackAction('update'));
  $('rollbackPack').addEventListener('click', () => runPackAction('rollback'));
  $('refreshDiagnostics').addEventListener('click', refreshDiagnostics);
  $('refreshStatus').addEventListener('click', async () => {
    await refreshDiagnostics();
    await refreshPack();
  });
  $('timezoneSelect').addEventListener('change', updateClocks);
  $('themeSelect').addEventListener('change', event => {
    document.body.dataset.theme = event.target.value;
    try { localStorage.setItem('atlas-theme', event.target.value); } catch (_) { /* local preference only */ }
  });
}

async function bootstrap() {
  bindEvents();
  try {
    const savedTheme = localStorage.getItem('atlas-theme');
    if (savedTheme === 'high-contrast' || savedTheme === 'atlas-dark') {
      document.body.dataset.theme = savedTheme;
      $('themeSelect').value = savedTheme;
    }
  } catch (_) { /* local preference is optional */ }
  updateClocks();
  window.setInterval(updateClocks, 1000);

  try {
    const [status, pack] = await Promise.all([refreshDiagnostics(), refreshPack()]);
    const core = status?.status_result || {};
    if (core.offline_capable === true && core.network_listener === false) {
      if (pack?.ready) setNotice('ATLAS is ready: verified Shared Core, offline boundary and active knowledge pack confirmed.', 'success');
      else setNotice('Shared Core is verified and offline; activate a verified knowledge pack to enable investigation.', 'warning');
    } else {
      setNotice('ATLAS startup validation did not prove the frozen offline boundary.', 'danger');
    }
  } catch (error) {
    setNotice(`ATLAS startup failed closed: ${String(error)}`, 'danger');
  }
}

bootstrap();
