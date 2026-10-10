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
  lastPack: null,
  activitySequence: 0
};

const $ = id => document.getElementById(id);
const entityAdapter = window.AtlasEntityState;

function text(value) {
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
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

function setNotice(message, kind = 'info') {
  const node = $('globalNotice');
  node.className = `notice ${kind}`;
  node.textContent = message;
}

function setBadge(node, label, kind = 'neutral') {
  node.className = `status-pill ${kind}`;
  node.textContent = label;
}

function addActivity(label, detail) {
  const trail = $('activityTrail');
  const item = document.createElement('li');
  const sequence = String(++state.activitySequence).padStart(2, '0');
  item.append(el('time', '', `${sequence} · ${label}`), el('span', '', detail));
  trail.prepend(item);
  while (trail.children.length > 6) trail.lastElementChild.remove();
}

function setEntity(mode, detail) {
  let next;
  try {
    next = entityAdapter && typeof entityAdapter.create === 'function'
      ? entityAdapter.create(mode, detail)
      : { mode: 'warning', label: 'WARNING', detail: 'Entity state adapter unavailable.' };
  } catch (_) {
    next = { mode: 'warning', label: 'WARNING', detail: 'Entity visualization isolated after a state adapter failure.' };
  }
  document.body.dataset.entityMode = next.mode;
  $('entityStateLabel').textContent = next.label;
  $('entityStateDetail').textContent = next.detail;
  $('entityVisual').setAttribute('aria-label', `ATLAS Entity is ${next.mode}`);
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
    if (!keys.includes(key) && !['claims', 'sources', 'provenance', 'relationships', 'fields'].includes(key)) keys.push(key);
  });
  keys.slice(0, 18).forEach(key => {
    const row = document.createElement('div');
    row.append(el('dt', '', key.replaceAll('_', ' ')), el('dd', '', compactValue(object[key])));
    container.append(row);
  });
  if (!keys.length) {
    const row = document.createElement('div');
    row.append(el('dt', '', 'Status'), el('dd', '', 'No fields returned'));
    container.append(row);
  }
}

function claimValue(claim) {
  const object = claim?.object;
  return object && typeof object === 'object' ? object.value ?? null : null;
}

function updateEvidenceMetrics(detail) {
  const metrics = {
    Fields: Array.isArray(detail?.fields) ? detail.fields.length : 0,
    Claims: Array.isArray(detail?.claims) ? detail.claims.length : 0,
    Sources: Array.isArray(detail?.sources) ? detail.sources.length : 0,
    Relations: Array.isArray(detail?.relationships) ? detail.relationships.length : 0
  };
  $('metricFields').textContent = String(metrics.Fields);
  $('metricClaims').textContent = String(metrics.Claims);
  $('metricSources').textContent = String(metrics.Sources);
  $('metricRelations').textContent = String(metrics.Relations);
  $('evidenceStatus').textContent = Object.values(metrics).some(Boolean) ? 'VERIFIED DATA' : 'NO PROJECTION';
}

function renderFieldDictionary(detail, container) {
  const fields = Array.isArray(detail?.fields) ? detail.fields : [];
  const claims = Array.isArray(detail?.claims) ? detail.claims : [];
  if (!fields.length) return;

  const section = el('section', 'detail-section field-dictionary');
  const heading = el('div', 'detail-section-heading');
  heading.append(el('strong', '', 'Field Dictionary'), el('span', 'muted small', `${fields.length} structured field${fields.length === 1 ? '' : 's'}`));
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
        renderFacts(facts, value, ['section', 'native_name', 'data_type', 'meaning', 'version_applicability', 'optional', 'conditional', 'collection_requirement', 'security_relevance']);
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
  const section = el('section', 'detail-section provenance-box');
  const heading = el('div', 'detail-section-heading');
  heading.append(el('strong', '', 'Sources / Provenance'), el('span', 'source-status', 'CLAIM-LINKED'));
  section.append(heading);
  sources.slice(0, 12).forEach(source => {
    const row = el('div', 'source-row');
    const label = el('span', 'source-title', source?.title || source?.canonical_key || source?.id || 'Source');
    const identity = el('span', 'source-id', source?.id || 'source identity unavailable');
    row.append(label, identity);
    section.append(row);
  });
  container.append(section);
}

function collectTimeline(detail, baseRecord) {
  const entries = [];
  const add = (timestamp, kind, label) => {
    if (typeof timestamp !== 'string' || !timestamp.trim()) return;
    const parsed = Date.parse(timestamp);
    entries.push({ timestamp, parsed: Number.isNaN(parsed) ? 0 : parsed, kind, label });
  };
  add(baseRecord?.created_at, 'RECORD', 'Canonical record created');
  add(baseRecord?.updated_at, 'RECORD', 'Canonical record updated');
  (Array.isArray(detail?.claims) ? detail.claims : []).forEach(claim => {
    (Array.isArray(claim?.evidence) ? claim.evidence : []).forEach(evidence => {
      add(evidence?.retrieved_at, 'SOURCE', `Evidence retrieved · ${evidence?.source_id || 'source'}`);
    });
  });
  return entries.sort((a, b) => a.parsed - b.parsed || a.label.localeCompare(b.label));
}

function renderTimeline(detail, baseRecord, container) {
  const entries = collectTimeline(detail, baseRecord);
  if (!entries.length) return;
  const section = el('section', 'detail-section');
  const heading = el('div', 'detail-section-heading');
  heading.append(el('strong', '', 'Evidence Timeline'), el('span', 'muted small', `${entries.length} durable timestamp${entries.length === 1 ? '' : 's'}`));
  section.append(heading);
  const list = el('ol', 'activity-trail');
  entries.slice(0, 12).forEach(entry => {
    const item = document.createElement('li');
    item.append(el('time', '', entry.kind), el('span', '', `${entry.timestamp} · ${entry.label}`));
    list.append(item);
  });
  section.append(list);
  container.append(section);
}

function renderRelationshipSummary(detail, container) {
  const relationships = Array.isArray(detail?.relationships) ? detail.relationships : [];
  if (!relationships.length) return;
  const section = el('section', 'detail-section');
  const heading = el('div', 'detail-section-heading');
  heading.append(el('strong', '', 'Direct Relationships'), el('span', 'muted small', `${relationships.length} bounded edge${relationships.length === 1 ? '' : 's'}`));
  section.append(heading);
  relationships.slice(0, 10).forEach(relationship => {
    const card = el('div', 'pivot-card');
    card.append(el('strong', '', relationship?.relationship_type || 'RELATED'));
    card.append(el('div', 'source-id', `${relationship?.from || relationship?.source_id || '—'} → ${relationship?.to || relationship?.target_id || '—'}`));
    section.append(card);
  });
  container.append(section);
}

function renderRecord(record, target) {
  clear(target);
  target.classList.remove('empty-state');
  const detail = record?.detail_version ? record : null;
  const baseRecord = detail?.record || record || {};
  const summary = el('div', 'record-summary');
  const hero = el('header', 'record-hero');
  hero.append(el('div', 'record-title', baseRecord?.title || baseRecord?.name || state.currentRecordId || 'Canonical record'));
  if (state.currentRecordId) hero.append(el('div', 'record-id', state.currentRecordId));
  summary.append(hero);

  const facts = el('dl', 'facts');
  renderFacts(facts, baseRecord, ['entity_type', 'namespace', 'platform', 'product', 'provider', 'channel', 'lifecycle', 'version', 'curation_status']);
  summary.append(facts);

  if (detail) {
    const recordClaims = (Array.isArray(detail.claims) ? detail.claims : []).filter(claim => claim?.subject_id === baseRecord?.id);
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
    renderRelationshipSummary(detail, summary);
    renderTimeline(detail, baseRecord, summary);
    renderFieldDictionary(detail, summary);
  }

  const raw = document.createElement('details');
  const rawHeading = document.createElement('summary');
  rawHeading.textContent = detail ? 'Detail Projection JSON' : 'Canonical JSON';
  raw.append(rawHeading, jsonBlock(record));
  summary.append(raw);
  target.append(summary);
}

async function loadRecord(id, openRecordView = false) {
  if (!id) return false;
  setEntity('correlating', `Loading canonical facts and provenance for ${id}.`);
  setNotice(`Loading canonical record ${id}…`, 'info');
  addActivity('RECORD', `Requested ${id}`);
  try {
    const record = await atlas.record(id);
    state.currentRecordId = id;
    state.currentRecord = record;
    $('graphSeed').value = id;
    $('openRecordView').disabled = false;
    $('recordGraphButton').disabled = false;
    renderRecord(record, $('quickDetail'));
    renderRecord(record, $('recordDetail'));
    updateEvidenceMetrics(record?.detail_version ? record : null);
    const sources = Array.isArray(record?.sources) ? record.sources.length : 0;
    setEntity('finding', `Canonical record resolved with ${sources} linked source${sources === 1 ? '' : 's'}.`);
    setNotice('Canonical record and provenance loaded from the verified active pack.', 'success');
    addActivity('FINDING', `Resolved ${id}`);
    if (openRecordView) showView('record');
    return true;
  } catch (error) {
    setEntity('warning', `Record resolution failed closed for ${id}.`);
    setNotice(`Record load failed closed: ${String(error)}`, 'danger');
    addActivity('WARNING', 'Record load failed closed');
    return false;
  }
}

function renderSearchResults(result) {
  const container = $('searchResults');
  clear(container);
  container.classList.remove('empty-state');
  const matches = Array.isArray(result?.matches) ? result.matches : [];
  $('resultCount').textContent = String(matches.length);
  $('searchMeta').textContent = `${text(result?.status)} · ${text(result?.match_stage)}`.toUpperCase();
  if (!matches.length) {
    container.classList.add('empty-state');
    container.append(el('div', 'empty-mark', '∅'), el('strong', '', 'No canonical match'), el('span', '', 'The bounded query returned no records from the active pack.'));
    return matches;
  }
  matches.forEach(match => {
    const button = el('button', 'result-card');
    button.type = 'button';
    button.dataset.recordId = match.target_id || '';
    button.append(el('span', 'result-title', match.title || match.target_id || 'Untitled record'));
    const meta = el('span', 'result-meta');
    [match.entity_type, match.platform, match.product, match.provider, match.match_reason].filter(Boolean).forEach(value => meta.append(el('span', 'token', String(value))));
    button.append(meta);
    button.addEventListener('click', async () => {
      document.querySelectorAll('.result-card').forEach(card => card.classList.remove('selected'));
      button.classList.add('selected');
      await loadRecord(match.target_id, false);
    });
    container.append(button);
  });
  return matches;
}

async function runSearchQuery(query, canaryId = null) {
  const limit = Number($('searchLimit').value);
  setEntity('searching', `Resolving “${query.slice(0, 80)}” against the active verified pack.`);
  setNotice('Running bounded offline search…', 'info');
  $('searchMeta').textContent = 'SEARCHING';
  addActivity('SEARCH', query.slice(0, 96));
  try {
    const result = await atlas.search(query, limit);
    const matches = renderSearchResults(result);
    if (!matches.length) {
      setEntity('idle', 'No matching record found. Awaiting the next analyst action.');
      setNotice('Search completed locally with no canonical matches.', 'warning');
      return matches;
    }
    setEntity('finding', `${matches.length} canonical result${matches.length === 1 ? '' : 's'} resolved.`);
    setNotice('Search completed locally against the active verified pack.', 'success');
    if (canaryId) {
      const exact = matches.find(match => match?.target_id === canaryId);
      if (!exact) {
        setEntity('warning', 'The canary query did not return its expected canonical identity.');
        setNotice(`Canary failed closed: expected ${canaryId} was not returned.`, 'danger');
        return matches;
      }
      const card = document.querySelector(`[data-record-id="${canaryId}"]`);
      if (card) card.classList.add('selected');
      await loadRecord(canaryId, false);
    }
    return matches;
  } catch (error) {
    $('searchMeta').textContent = 'SEARCH FAILED';
    setEntity('warning', 'Search failed closed at the Shared Core boundary.');
    setNotice(`Search failed closed: ${String(error)}`, 'danger');
    addActivity('WARNING', 'Search failed closed');
    return [];
  }
}

async function runSearch(event) {
  event.preventDefault();
  const query = $('searchInput').value.trim();
  if (query) await runSearchQuery(query);
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
    return pivots;
  }
  const list = el('div', 'pivot-list');
  pivots.forEach((pivot, index) => {
    const card = el('article', 'pivot-card');
    const pivotId = findPivotId(pivot);
    card.append(el('strong', '', pivot?.relationship_type || pivot?.type || `Pivot ${index + 1}`), jsonBlock(pivot));
    if (pivotId) {
      const button = el('button', 'text-button', `Open ${pivotId}`);
      button.type = 'button';
      button.addEventListener('click', () => loadRecord(pivotId, true));
      card.append(button);
    }
    list.append(card);
  });
  container.append(list);
  return pivots;
}

async function runGraph(event) {
  event.preventDefault();
  const seedId = $('graphSeed').value.trim();
  const depth = Number($('graphDepth').value);
  if (!seedId) return;
  setEntity('reasoning', `Evaluating bounded relationships for ${seedId}.`);
  setNotice('Expanding bounded relationships in Shared Core…', 'info');
  addActivity('GRAPH', `Depth ${depth} · ${seedId}`);
  try {
    const result = await atlas.graph(seedId, depth);
    const pivots = renderGraph(result);
    setEntity('finding', `${pivots.length} relationship pivot${pivots.length === 1 ? '' : 's'} available for review.`);
    setNotice('Relationship expansion completed locally.', 'success');
  } catch (error) {
    setEntity('warning', 'Relationship expansion failed closed.');
    setNotice(`Graph expansion failed closed: ${String(error)}`, 'danger');
  }
}

function renderPack(pack) {
  state.lastPack = pack;
  renderFacts($('packFacts'), pack || {}, ['ready', 'state', 'pack_id', 'pack_version', 'generation_id', 'manifest_digest', 'pending_update', 'rollback_available']);
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
    setEntity('warning', 'Pack integrity state is unavailable.');
    setNotice(`Pack state failed closed: ${String(error)}`, 'danger');
    throw error;
  }
}

async function runPackAction(kind) {
  const isUpdate = kind === 'update';
  const prompt = isUpdate ? 'Apply the already-verified pending pack update? Shared Core trust checks remain authoritative.' : 'Rollback to the safe Last Known Good pack generation?';
  if (!window.confirm(prompt)) return;
  const output = $('packActionResult');
  output.textContent = isUpdate ? 'Applying verified update…' : 'Executing safe rollback…';
  setEntity('reasoning', isUpdate ? 'Shared Core is validating the pending pack update.' : 'Shared Core is evaluating Last Known Good recovery.');
  try {
    const result = isUpdate ? await atlas.packUpdate() : await atlas.packRollback();
    output.textContent = JSON.stringify(result, null, 2);
    await refreshPack();
    setEntity('finding', isUpdate ? 'Verified pack update completed.' : 'Safe rollback completed.');
    setNotice(isUpdate ? 'Verified pack update completed.' : 'Safe rollback completed.', 'success');
  } catch (error) {
    output.textContent = `FAIL-CLOSED: ${String(error)}`;
    setEntity('warning', 'Pack control operation failed closed.');
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
    setEntity('warning', 'Shared Core validation failed closed.');
    throw error;
  }
}

function formatClock(date, timeZone, locale = 'en-GB') {
  const options = { dateStyle: 'medium', timeStyle: 'medium', hour12: false };
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
  document.querySelectorAll('.nav-item').forEach(button => button.addEventListener('click', () => showView(button.dataset.view)));
  document.querySelectorAll('.canary-button').forEach(button => button.addEventListener('click', async () => {
    const query = button.dataset.canaryQuery;
    const expectedId = button.dataset.canaryId;
    showView('investigate');
    $('searchInput').value = query;
    await runSearchQuery(query, expectedId);
  }));
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
    setEntity('correlating', 'Revalidating Shared Core and pack trust state.');
    try {
      await Promise.all([refreshDiagnostics(), refreshPack()]);
      setEntity('idle', 'Runtime and pack trust state revalidated.');
    } catch (_) { /* individual refresh methods render fail-closed state */ }
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
    if (['high-contrast', 'atlas-dark', 'tactical-green'].includes(savedTheme)) {
      document.body.dataset.theme = savedTheme;
      $('themeSelect').value = savedTheme;
    }
  } catch (_) { /* local preference is optional */ }
  updateClocks();
  window.setInterval(updateClocks, 1000);
  setEntity('correlating', 'Validating local runtime integrity and active pack state.');

  try {
    const [status, pack] = await Promise.all([refreshDiagnostics(), refreshPack()]);
    const core = status?.status_result || {};
    if (core.offline_capable === true && core.network_listener === false) {
      if (pack?.ready) {
        setEntity('idle', 'Verified runtime and active pack are ready for analysis.');
        setNotice('ATLAS is ready: verified Shared Core, offline boundary and active knowledge pack confirmed.', 'success');
        addActivity('VERIFIED', 'Runtime and active pack ready');
      } else {
        setEntity('warning', 'Shared Core is verified, but no active knowledge pack is ready.');
        setNotice('Shared Core is verified and offline; activate a verified knowledge pack to enable investigation.', 'warning');
      }
    } else {
      setEntity('warning', 'The frozen offline boundary was not proven.');
      setNotice('ATLAS startup validation did not prove the frozen offline boundary.', 'danger');
    }
  } catch (error) {
    setEntity('warning', 'Startup validation failed closed.');
    setNotice(`ATLAS startup failed closed: ${String(error)}`, 'danger');
  }
}

bootstrap();
