'use strict';

(function installStaleSelectionGuard() {
  function resetWorkspaceAfterSearchMiss() {
    try {
      state.currentRecordId = null;
      state.currentRecord = null;
      state.currentMatch = null;
      state.currentInvestigation = null;
      state.currentTab = 'overview';

      const graphSeed = document.getElementById('graphSeed');
      if (graphSeed) graphSeed.value = '';
      for (const id of ['openRecordView', 'recordGraphButton', 'recordInvestigationButton']) {
        const button = document.getElementById(id);
        if (button) button.disabled = true;
      }

      const quick = document.getElementById('quickDetail');
      if (quick) {
        quick.className = 'quick-detail empty-answer';
        quick.replaceChildren(
          el('div', 'empty-orb', '◇'),
          el('h3', '', 'No record selected'),
          el('p', '', 'The latest search returned no verified record. Previous record context was cleared to prevent analyst confusion.')
        );
      }

      const raw = document.getElementById('recordDetail');
      if (raw) {
        raw.className = 'raw-record empty-state';
        raw.textContent = 'No record selected.';
      }

      const graph = document.getElementById('graphResults');
      if (graph) {
        graph.className = 'graph-stage empty-state';
        graph.replaceChildren(
          el('div', 'empty-mark', '⌘'),
          el('strong', '', 'No relationship map selected'),
          el('span', '', 'Run a successful search and select a record first.')
        );
      }

      const investigation = document.getElementById('investigationGraph');
      if (investigation) {
        investigation.className = 'investigation-graph empty-state';
        investigation.replaceChildren(
          el('div', 'empty-mark', '⎔'),
          el('strong', '', 'No investigation selected'),
          el('span', '', 'Run a successful search and select an enriched record first.')
        );
      }
      const purpose = document.getElementById('investigationPurpose');
      if (purpose) purpose.textContent = 'No bounded investigation model is selected.';
      const confidence = document.getElementById('investigationConfidence');
      if (confidence) confidence.textContent = 'CONFIDENCE · N/A';

      const pivots = document.getElementById('entityPivots');
      if (pivots) pivots.replaceChildren();
      if (typeof updateMetrics === 'function') updateMetrics(null);
      return true;
    } catch (_) {
      return false;
    }
  }

  if (typeof runSearchQuery !== 'function') return;
  const originalRunSearchQuery = runSearchQuery;
  runSearchQuery = async function guardedRunSearchQuery(query) {
    const matches = await originalRunSearchQuery(query);
    if (!Array.isArray(matches) || matches.length === 0) resetWorkspaceAfterSearchMiss();
    return matches;
  };

  if (typeof window !== 'undefined') {
    window.AtlasStaleSelectionGuard = Object.freeze({ resetWorkspaceAfterSearchMiss });
  }
}());

(function installAcceptanceRemediation(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.AtlasAcceptanceRemediation = api;
  if (typeof document !== 'undefined') api.install();
}(typeof globalThis !== 'undefined' ? globalThis : this, function acceptanceRemediationFactory() {
  const ATTACK_ID_RE = /\b(?:T\d{4}(?:\.\d{3})?|TA\d{4}|DET\d{4}|AN\d{4}|M\d{4}|DC\d{4})\b/gi;
  const PROVIDER_GENERIC_MEANING_RE = /^Provider-rendered\s+[`'"]?[^`'"]+[`'"]?\s+field preserved from controlled Microsoft event metadata\.?$/i;
  const FIELD_NAME_OVERRIDES = Object.freeze({
    CRLNumber: 'CRL Number',
    IsBaseCRL: 'Is Base CRL',
    KeyContainer: 'Key Container',
    NextPublish: 'Next Publish',
    PublishURLs: 'Publish URLs'
  });
  const READING_AIDS_FA = Object.freeze({
    '4872': 'این رویداد زمانی ثبت می‌شود که Certificate Services یک فهرست ابطال گواهی (CRL) را منتشر می‌کند. نشانه‌های %1 تا %5 در پیام خام، جای‌نگهدارهای قالب Microsoft Provider هستند و هنگام ثبت رویداد با مقادیر واقعی جایگزین می‌شوند. متن مرجع انگلیسی بدون تغییر حفظ شده است.',
    T1059: 'این تکنیک بیان می‌کند که مهاجم ممکن است از مفسرهای فرمان و اسکریپت برای اجرای دستور، اسکریپت یا فایل اجرایی سوءاستفاده کند. نمونه‌های مرتبط شامل PowerShell، Windows Command Shell، Unix Shell، Python، JavaScript و Visual Basic هستند. متن مرجع MITRE به زبان اصلی حفظ شده است.'
  });
  const TAB_FA = Object.freeze({
    overview: 'مرور', fields: 'فیلدها', example: 'نمونه', analysis: 'تشخیص و شکار', capabilities: 'قابلیت‌ها',
    investigation: 'بررسی', attack: 'زمینه ATT&CK', relationships: 'روابط', sources: 'منابع', raw: 'خام / Canonical'
  });
  const STATIC_FA = Object.freeze({
    '[data-view="explore"] span:last-child': 'کاوش',
    '[data-view="library"] span:last-child': 'کتابخانه',
    '[data-view="investigation"] span:last-child': 'بررسی',
    '[data-view="mindmap"] span:last-child': 'نقشه ارتباطات',
    '[data-view="advanced"] span:last-child': 'تنظیمات',
    '#exploreTitle': 'چه چیزی را می‌خواهید بررسی کنید؟',
    '#libraryTitle': 'کتابخانه',
    '#investigationTitle': 'بررسی',
    '#mindmapTitle': 'نقشه ارتباطات',
    '#advancedTitle': 'تنظیمات و جزئیات فنی',
    '#entityTitle': 'موجودیت'
  });

  function normalizeSpaces(value) {
    return String(value == null ? '' : value).replace(/\s+/g, ' ').trim();
  }

  function cleanProviderTitle(value) {
    const text = normalizeSpaces(value);
    const tokenIndex = text.search(/%\d+/);
    if (tokenIndex < 0) return text;
    const prefix = text.slice(0, tokenIndex);
    const sentenceBreak = prefix.lastIndexOf('. ');
    if (sentenceBreak >= 0) return prefix.slice(0, sentenceBreak + 1).trim();
    const fieldStart = prefix.search(/\b(?:Base CRL|CRL Number|Key Container|Next Publish|Publish URLs)\s*:/i);
    if (fieldStart > 0) return prefix.slice(0, fieldStart).replace(/[,:;\s]+$/, '').trim();
    return prefix.replace(/[A-Za-z][A-Za-z0-9 /_-]{1,48}:\s*$/, '').replace(/[,:;\s]+$/, '').trim();
  }

  function parseProviderTemplate(value) {
    const text = normalizeSpaces(value);
    const tokenRe = /%\d+/g;
    const fields = [];
    let match;
    let previousEnd = 0;
    let lastEnd = 0;
    while ((match = tokenRe.exec(text)) !== null) {
      const before = text.slice(previousEnd, match.index);
      const labelMatch = before.match(/([A-Za-z][A-Za-z0-9 /_-]{1,48})\s*:\s*$/);
      if (labelMatch) fields.push({ label: labelMatch[1].trim(), token: match[0] });
      previousEnd = match.index + match[0].length;
      lastEnd = previousEnd;
    }
    return {
      lead: cleanProviderTitle(text).replace(/^Microsoft provider message:\s*/i, ''),
      fields,
      tail: lastEnd ? text.slice(lastEnd).trim().replace(/^[,;:.\s]+/, '') : ''
    };
  }

  function humanizeFieldName(value) {
    const source = String(value || '').trim();
    if (!source) return '';
    if (FIELD_NAME_OVERRIDES[source]) return FIELD_NAME_OVERRIDES[source];
    return source
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
      .replace(/([A-Z]{2,})([A-Z][a-z])/g, '$1 $2')
      .replace(/_/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  function humanizeFieldType(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    if (/^UnicodeString\d*$/i.test(raw)) return 'Text · Unicode string';
    if (/^AnsiString\d*$/i.test(raw)) return 'Text · ANSI string';
    const uint = raw.match(/^UInt(\d+)$/i);
    if (uint) return `Unsigned ${uint[1]}-bit integer`;
    const hex = raw.match(/^HexInt(\d+)$/i);
    if (hex) return `Hexadecimal · ${hex[1]}-bit integer`;
    if (/^GUID$/i.test(raw)) return 'GUID';
    if (/^SID$/i.test(raw)) return 'Windows SID';
    if (/^Boolean$/i.test(raw)) return 'Boolean';
    if (/^FileTime$/i.test(raw)) return 'Windows file time';
    return raw;
  }

  function extractCitations(value) {
    const out = [];
    for (const match of String(value || '').matchAll(/\(Citation:\s*([^)]+)\)/gi)) {
      const citation = normalizeSpaces(match[1]);
      if (citation && !out.includes(citation)) out.push(citation);
    }
    return out;
  }

  function stripMarkdownLinks(value) {
    let text = String(value || '').replace(/\\\(/g, '(').replace(/\\\)/g, ')');
    text = text.replace(/\[([^\]]+)\]\(\[https?:\/\/[^\]]+\]\(https?:\/\/[^)]+\)\)/gi, '$1');
    text = text.replace(/\[([^\]]+)\]\(https?:\/\/[^)]+\)/gi, '$1');
    text = text.replace(/\(Citation:\s*([^)]+)\)/gi, '');
    text = text.replace(/\(https?:\/\/[^)\s]+\)/gi, '');
    text = text.replace(/https?:\/\/[^\s)]+/gi, '');
    return text.replace(/\s+([.,;:])/g, '$1').replace(/\s{2,}/g, ' ').trim();
  }

  function paragraphize(value) {
    const text = normalizeSpaces(value);
    if (!text) return [];
    const sentences = text.match(/[^.!?]+[.!?]+(?:["')\]]+)?|[^.!?]+$/g) || [text];
    const paragraphs = [];
    for (let i = 0; i < sentences.length; i += 2) {
      const paragraph = sentences.slice(i, i + 2).map(normalizeSpaces).filter(Boolean).join(' ');
      if (paragraph) paragraphs.push(paragraph);
    }
    return paragraphs;
  }

  function primaryIdentifier(record) {
    const identifiers = Array.isArray(record?.native_identifiers) ? record.native_identifiers : [];
    const primary = identifiers.find(item => item?.primary) || identifiers[0];
    return primary?.value ? String(primary.value).toUpperCase() : '';
  }

  function attackNameMap(detail, base) {
    const map = new Map();
    const add = record => {
      if (!record || typeof record !== 'object') return;
      const identifier = primaryIdentifier(record);
      if (identifier && record.title) map.set(identifier.toUpperCase(), String(record.title));
    };
    add(base);
    for (const record of Array.isArray(detail?.related_entities) ? detail.related_entities : []) add(record);
    return map;
  }

  function formatAttackIdentifiers(value, names) {
    return String(value || '').replace(ATTACK_ID_RE, raw => {
      const id = raw.toUpperCase();
      const name = names?.get?.(id);
      return name && !String(value).includes(`${id} (${name})`) ? `${id} (${name})` : id;
    });
  }

  function reverseRelationship(type) {
    return ({
      HAS_SUBTECHNIQUE: 'SUBTECHNIQUE_OF',
      DETECTS: 'DETECTED_BY',
      HAS_ANALYTIC: 'ANALYTIC_OF',
      USES_DATA_COMPONENT: 'USED_BY_ANALYTIC',
      MITIGATES: 'MITIGATED_BY',
      BELONGS_TO_TACTIC: 'HAS_TECHNIQUE',
      MAPS_TO_ATTACK: 'HAS_MAPPED_TOOL'
    })[type] || type;
  }

  function relationshipLabel(id, relatedById) {
    const record = relatedById.get(String(id));
    if (record) return [primaryIdentifier(record), record.title].filter(Boolean).join(' · ');
    const parts = String(id || 'Related record').split(':');
    const tail = parts[parts.length - 1] || 'Related record';
    if (/^(?:ta|t|det|an|m|dc)\d/i.test(tail)) return tail.toUpperCase();
    if (/^\d+$/.test(tail)) return `Event ${tail}`;
    return tail.replace(/[.-]+/g, ' ');
  }

  function classifyRelationship(type) {
    const normalized = String(type || '').replaceAll('_', ' ').toUpperCase();
    if (normalized.includes('MAPPED TOOL')) return 'tools';
    if (/(SUBTECHNIQUE|TACTIC|TECHNIQUE)/.test(normalized)) return 'hierarchy';
    if (/(DETECT|ANALYTIC|MITIGAT|DATA COMPONENT)/.test(normalized)) return 'defensive';
    return 'other';
  }

  function buildRelationshipGroups(detail, base) {
    const groups = { hierarchy: [], defensive: [], tools: [], other: [] };
    const current = base?.id;
    const relatedById = new Map((Array.isArray(detail?.related_entities) ? detail.related_entities : []).map(item => [String(item?.id), item]));
    for (const row of Array.isArray(detail?.relationships) ? detail.relationships : []) {
      if (!row || typeof row !== 'object') continue;
      const outbound = row.from === current;
      const related = outbound ? row.to : row.from;
      if (!related || String(related).includes(':source:')) continue;
      const type = outbound ? String(row.relationship_type || 'RELATED_TO') : reverseRelationship(String(row.relationship_type || 'RELATED_TO'));
      const label = `${type.replaceAll('_', ' ')} · ${relationshipLabel(related, relatedById)}`;
      const bucket = classifyRelationship(type);
      if (!groups[bucket].includes(label)) groups[bucket].push(label);
    }
    return groups;
  }

  function isAttackIdentifier(value) {
    const match = String(value || '').toUpperCase().match(/\b(?:T\d{4}(?:\.\d{3})?|TA\d{4}|DET\d{4}|AN\d{4}|M\d{4}|DC\d{4})\b/);
    return match ? match[0] : '';
  }

  function recordParts() {
    if (typeof state === 'undefined' || !state.currentRecord) return { detail: null, base: null, kind: 'knowledge' };
    const detail = state.currentRecord?.detail_version ? state.currentRecord : null;
    const base = detail?.record || state.currentRecord || null;
    const type = String(base?.entity_type || '');
    let kind = 'knowledge';
    if (type === 'event') kind = 'event';
    else if (type === 'tool') kind = 'tool';
    else if (type.startsWith('attack-')) kind = 'attack';
    else if (type === 'activity' && (Array.isArray(base?.native_identifiers) ? base.native_identifiers : []).some(item => item?.type === 'hunt_profile')) kind = 'hunt';
    return { detail, base, kind };
  }

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined && text !== null) element.textContent = String(text);
    return element;
  }

  function setTextIfDifferent(element, text) {
    if (element && element.textContent !== text) element.textContent = text;
  }

  function injectStyles() {
    if (document.getElementById('atlas-acceptance-remediation-style')) return;
    const style = document.createElement('style');
    style.id = 'atlas-acceptance-remediation-style';
    style.textContent = `
      .language-toggle{min-width:42px;height:34px;border:1px solid var(--soft);border-radius:10px;background:var(--surface2);color:var(--blue2);font:800 10px ui-monospace,Consolas,monospace;letter-spacing:.08em;cursor:pointer}
      .language-toggle:hover{border-color:var(--blue);color:var(--text)}
      .answer-hero{position:relative;padding-right:82px}
      .record-symbol{position:absolute;right:18px;top:18px;width:52px;height:52px;border:1px solid var(--soft);border-radius:14px;display:grid;place-items:center;background:color-mix(in srgb,var(--surface2) 88%,transparent)}
      .record-symbol svg{width:34px;height:34px;fill:none;stroke:var(--blue2);stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
      .readable-prose{display:grid;gap:10px;line-height:1.72;max-width:84ch}
      .readable-prose p{margin:0;color:var(--text)}
      .source-citations{margin-top:2px;font-size:10px;color:var(--muted)}
      .source-citations summary,.provider-template summary,.relationship-tools summary{cursor:pointer;color:var(--blue2);font-weight:750}
      .provider-template{margin-top:11px;border:1px solid var(--soft);border-radius:10px;padding:9px 11px;background:color-mix(in srgb,var(--surface2) 82%,transparent);font-size:10px}
      .provider-template p{margin:8px 0;color:var(--muted);line-height:1.55}
      .provider-template-grid{display:grid;grid-template-columns:minmax(90px,1fr) auto;gap:5px 10px;margin-top:8px}
      .provider-template-grid code{color:var(--blue2);font-weight:800}
      .context-row{grid-template-columns:minmax(118px,.72fr) minmax(0,1.4fr);gap:12px;align-items:start}
      .context-row>span:last-child{min-width:0;overflow-wrap:anywhere;word-break:break-word}
      .version-definition-row>span:last-child{display:flex;flex-wrap:wrap;gap:5px}
      .metadata-chip{display:inline-block;max-width:100%;padding:4px 7px;border:1px solid var(--soft);border-radius:7px;background:var(--surface2);font:650 9px/1.4 ui-monospace,Consolas,monospace;overflow-wrap:anywhere}
      .field-row{grid-template-columns:minmax(130px,.7fr) minmax(0,1.7fr)}
      .field-name{display:grid;gap:4px;align-content:start}
      .native-field-name{font:600 9px ui-monospace,Consolas,monospace;color:var(--muted);overflow-wrap:anywhere}
      .field-tag[data-raw-type]{cursor:help}
      .field-meaning{line-height:1.55}
      .quick-tab.unavailable{opacity:.42;cursor:not-allowed;text-decoration:none}
      .relationship-groups{display:grid;gap:12px}
      .relationship-group{display:grid;gap:6px}
      .relationship-group h5{margin:0;color:var(--blue2);font-size:10px;text-transform:uppercase;letter-spacing:.08em}
      .relationship-group ul{margin:0;padding-left:18px;display:grid;gap:6px}
      .relationship-note{margin:0;color:var(--muted);font-size:10px;line-height:1.55}
      .relationship-tools{border:1px solid var(--soft);border-radius:9px;padding:8px 10px;background:color-mix(in srgb,var(--surface2) 75%,transparent)}
      .relationship-tools ul{margin-top:8px}
      .entity-kind-badge{display:inline-flex;align-items:center;gap:5px;margin-top:6px;padding:4px 7px;border:1px solid var(--soft);border-radius:999px;color:var(--blue2);font:750 8px ui-monospace,Consolas,monospace;letter-spacing:.07em;text-transform:uppercase}
      .entity-visual{min-height:190px;max-height:220px}
      .entity-visual svg{max-height:205px}
      .entity-pivots{display:flex;flex-wrap:wrap;gap:6px}
      .entity-pivot{max-width:100%;white-space:normal;text-align:left;line-height:1.25}
      .persian-reading-aid{margin-top:11px;border:1px solid var(--soft);border-radius:10px;padding:11px 13px;background:color-mix(in srgb,var(--surface2) 86%,transparent);direction:rtl;text-align:right;line-height:1.9;color:var(--text)}
      .persian-reading-aid strong{display:block;margin-bottom:4px;color:var(--blue2)}
      .persian-reading-aid[hidden]{display:none}
      body[data-theme="high-contrast"] .record-symbol,body[data-theme="high-contrast"] .provider-template,body[data-theme="high-contrast"] .persian-reading-aid{border-width:2px}
      @media(max-width:980px){.answer-hero{padding-right:18px}.record-symbol{position:static;margin-bottom:10px}.context-row,.field-row{grid-template-columns:1fr}}
    `;
    document.head.append(style);
  }

  function dedupeHeroBadges() {
    const seen = new Set();
    for (const badge of document.querySelectorAll('.answer-kicker .badge')) {
      const key = normalizeSpaces(badge.textContent).toLowerCase();
      if (seen.has(key)) badge.remove();
      else seen.add(key);
    }
  }

  function enhanceProviderNarrative() {
    const title = document.querySelector('.answer-title');
    const description = document.querySelector('.answer-description');
    if (!title || !description) return;
    const rawTitle = title.dataset.atlasRawText || title.textContent || '';
    if (!title.dataset.atlasRawText) title.dataset.atlasRawText = rawTitle;
    const rawDescription = description.dataset.atlasRawText || description.textContent || '';
    if (!description.dataset.atlasRawText) description.dataset.atlasRawText = rawDescription;
    const source = [rawDescription, rawTitle].map(parseProviderTemplate).find(item => item.fields.length);
    if (!source) return;
    setTextIfDifferent(title, cleanProviderTitle(rawTitle));
    if (!description.dataset.providerCleaned) {
      const parsed = parseProviderTemplate(rawDescription);
      const clean = [parsed.lead, parsed.tail].filter(Boolean).join(' ');
      description.textContent = clean || cleanProviderTitle(rawDescription);
      description.dataset.providerCleaned = 'true';
    }
    const hero = title.closest('.answer-hero');
    if (!hero || hero.querySelector('.provider-template')) return;
    const details = node('details', 'provider-template');
    details.append(node('summary', '', `Microsoft provider template placeholders (${source.fields.map(item => item.token).join('–')})`));
    details.append(node('p', '', 'These tokens are Microsoft Provider substitution placeholders. Windows replaces them with event values when the provider renders the message; they are not literal event data.'));
    const grid = node('div', 'provider-template-grid');
    for (const field of source.fields) {
      grid.append(node('span', '', field.label), node('code', '', field.token));
    }
    details.append(grid);
    hero.append(details);
  }

  function enhanceAttackProse(kind) {
    if (kind !== 'attack') return;
    const description = document.querySelector('.answer-description');
    if (!description || description.dataset.readable === 'true') return;
    const raw = description.textContent || '';
    const citations = extractCitations(raw);
    const clean = stripMarkdownLinks(raw);
    const replacement = node('div', 'answer-description readable-prose');
    replacement.dataset.readable = 'true';
    for (const paragraph of paragraphize(clean)) replacement.append(node('p', '', paragraph));
    if (citations.length) {
      const details = node('details', 'source-citations');
      details.append(node('summary', '', `Source citations (${citations.length})`));
      const list = document.createElement('ul');
      for (const citation of citations) list.append(node('li', '', citation));
      details.append(list);
      replacement.append(details);
    }
    description.replaceWith(replacement);
  }

  function enhanceFields() {
    for (const row of document.querySelectorAll('.field-row')) {
      if (row.dataset.acceptanceEnhanced === 'true') continue;
      row.dataset.acceptanceEnhanced = 'true';
      const name = row.querySelector('.field-name');
      if (name) {
        const raw = normalizeSpaces(name.textContent);
        const display = humanizeFieldName(raw);
        name.replaceChildren(node('span', '', display));
        if (display !== raw) name.append(node('code', 'native-field-name', raw));
      }
      const meaning = row.querySelector('.field-meaning');
      if (meaning && PROVIDER_GENERIC_MEANING_RE.test(normalizeSpaces(meaning.textContent))) {
        meaning.textContent = 'Microsoft provider field preserved from controlled event metadata. Detailed field semantics are not yet curated in this pack.';
      }
      for (const tag of row.querySelectorAll('.field-tag')) {
        const raw = normalizeSpaces(tag.textContent);
        const display = humanizeFieldType(raw);
        if (display !== raw) {
          tag.textContent = display;
          tag.dataset.rawType = raw;
          tag.title = `Provider type: ${raw}`;
        }
      }
    }
  }

  function enhanceVersionDefinitions() {
    for (const row of document.querySelectorAll('.context-row')) {
      const cells = row.querySelectorAll(':scope > span');
      if (cells.length < 2 || normalizeSpaces(cells[0].textContent).toLowerCase() !== 'version definitions') continue;
      row.classList.add('version-definition-row');
      const value = cells[1];
      if (value.dataset.formatted === 'true') continue;
      value.dataset.formatted = 'true';
      const raw = normalizeSpaces(value.textContent);
      const chunks = raw.split(/\s+·\s+/).map(normalizeSpaces).filter(Boolean);
      value.replaceChildren(...(chunks.length ? chunks : [raw]).map(chunk => node('span', 'metadata-chip', chunk)));
    }
  }

  function hideUncuratedEmptyCards() {
    for (const card of document.querySelectorAll('.info-card')) {
      const heading = normalizeSpaces(card.querySelector('h4')?.textContent).toLowerCase();
      const body = normalizeSpaces(card.querySelector('p')?.textContent).toLowerCase();
      if ((heading === 'correlations' || heading === 'detection / hunt pivots') && body.startsWith('no curated correlation')) card.hidden = true;
    }
    const examplePanel = document.querySelector('.tab-panel[data-tab-panel="example"]');
    const exampleTab = document.querySelector('.quick-tab[data-tab="example"]');
    if (examplePanel && exampleTab && /No accepted example is packaged/i.test(examplePanel.textContent || '')) {
      exampleTab.disabled = true;
      exampleTab.classList.add('unavailable');
      exampleTab.title = 'No governed example is packaged in the active pack.';
      if (exampleTab.classList.contains('active')) {
        const overview = document.querySelector('.quick-tab[data-tab="overview"]');
        if (overview) overview.click();
      }
    }
  }

  function enhanceAttackDetails(detail, base, kind) {
    if (kind !== 'attack') return;
    const names = attackNameMap(detail, base);
    for (const card of document.querySelectorAll('.info-card')) {
      const heading = normalizeSpaces(card.querySelector('h4')?.textContent);
      if (!['Enterprise ATT&CK Context', 'Versioned ATT&CK Object'].includes(heading)) continue;
      const list = card.querySelector('ul');
      if (!list) continue;
      for (const item of [...list.querySelectorAll(':scope > li')]) {
        const raw = normalizeSpaces(item.textContent);
        if (/^[^:]+:\s*$/.test(raw)) { item.remove(); continue; }
        const colon = raw.indexOf(':');
        if (colon < 0) continue;
        const label = raw.slice(0, colon + 1);
        let value = raw.slice(colon + 1).trim();
        value = value.replace(/^([A-Z]+\d+(?:\.\d+)?)\s*·\s*(.+)$/, '$1 ($2)');
        item.textContent = `${label} ${formatAttackIdentifiers(value, names)}`;
      }
    }
    for (const card of document.querySelectorAll('.info-card')) {
      if (normalizeSpaces(card.querySelector('h4')?.textContent) !== 'Lifecycle') continue;
      const list = card.querySelector('ul');
      if (!list) continue;
      const unique = [...new Set([...list.querySelectorAll('li')].map(item => normalizeSpaces(item.textContent)).filter(Boolean))];
      list.replaceChildren();
      for (const value of unique) {
        list.append(node('li', '', value.toLowerCase() === 'current' ? 'Current — active in the selected ATT&CK release; not deprecated or revoked.' : value));
      }
    }
  }

  function enhanceRelationships(detail, base, kind) {
    if (kind !== 'attack' || !detail || !base) return;
    const panel = document.querySelector('.tab-panel[data-tab-panel="relationships"]');
    const card = panel?.querySelector('.info-card');
    if (!card || card.dataset.grouped === 'true') return;
    card.dataset.grouped = 'true';
    const groups = buildRelationshipGroups(detail, base);
    card.replaceChildren(node('h4', '', 'Verified Relationships'));
    const host = node('div', 'relationship-groups');
    const addGroup = (title, values) => {
      if (!values.length) return;
      const section = node('section', 'relationship-group');
      section.append(node('h5', '', title));
      const list = document.createElement('ul');
      for (const value of values) list.append(node('li', '', value));
      section.append(list);
      host.append(section);
    };
    addGroup('ATT&CK hierarchy', groups.hierarchy);
    addGroup('Detection / mitigation context', groups.defensive);
    addGroup('Other verified links', groups.other);
    if (groups.tools.length) {
      const details = node('details', 'relationship-tools');
      details.append(node('summary', '', `Mapped tools (${groups.tools.length})`));
      details.append(node('p', 'relationship-note', 'Mapped tools are source-backed cross-references. They are collapsed by default so the ATT&CK hierarchy remains readable.'));
      const list = document.createElement('ul');
      for (const value of groups.tools) list.append(node('li', '', value));
      details.append(list);
      host.append(details);
    }
    if (!host.children.length) host.append(node('p', 'relationship-note', 'No source-backed relationships are packaged for this entity yet.'));
    card.append(host);
  }

  function createRecordSymbol(kind) {
    const box = node('div', 'record-symbol');
    box.setAttribute('aria-hidden', 'true');
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 40 40');
    const path = d => { const p = document.createElementNS(svg.namespaceURI, 'path'); p.setAttribute('d', d); svg.append(p); };
    const circle = (cx, cy, r) => { const c = document.createElementNS(svg.namespaceURI, 'circle'); c.setAttribute('cx', cx); c.setAttribute('cy', cy); c.setAttribute('r', r); svg.append(c); };
    if (kind === 'event') {
      path('M20 4 32 9v9c0 8-4.8 14-12 18C12.8 32 8 26 8 18V9Z'); path('M13 15h14M13 20h10M13 25h7');
    } else if (kind === 'attack') {
      circle(20, 20, 13); circle(20, 20, 7); circle(20, 20, 2); path('M20 3v7M20 30v7M3 20h7M30 20h7');
    } else if (kind === 'tool') {
      path('M5 8h30v24H5Z'); path('m10 15 5 5-5 5M19 25h10');
    } else if (kind === 'hunt') {
      circle(20, 20, 13); path('M20 20 32 12M20 7v26M7 20h26'); circle(29, 14, 2);
    } else {
      path('M20 4 33 12v16L20 36 7 28V12Z'); path('M13 25 20 10l7 15M16 20h8');
    }
    box.append(svg);
    return box;
  }

  function enhanceRecordSymbol(kind) {
    const hero = document.querySelector('.answer-hero');
    if (!hero || hero.querySelector('.record-symbol')) return;
    hero.append(createRecordSymbol(kind));
  }

  function enhanceEntityRail(detail, base, kind) {
    const heading = document.querySelector('.entity-heading > div');
    if (heading) {
      let badge = heading.querySelector('.entity-kind-badge');
      if (!badge) { badge = node('span', 'entity-kind-badge'); heading.append(badge); }
      const label = ({ event: 'Telemetry Event', attack: 'MITRE ATT&CK', tool: 'Tool Intelligence', hunt: 'Hunt Profile', knowledge: 'Knowledge Entity' })[kind];
      setTextIfDifferent(badge, label);
    }
    if (kind !== 'attack') return;
    const names = attackNameMap(detail, base);
    for (const pivot of document.querySelectorAll('#entityPivots .entity-pivot')) {
      const id = isAttackIdentifier(pivot.textContent);
      if (!id) continue;
      const name = names.get(id);
      if (name) {
        pivot.textContent = `${id} · ${name}`;
        pivot.title = `Open ${id} — ${name}`;
      } else pivot.title = `Open ${id}`;
    }
    const detailText = document.getElementById('entityStateDetail');
    if (detailText) detailText.textContent = 'Select an ATT&CK identifier below to open that object. Use ATT&CK Context for hierarchy, detection and mitigation mappings.';
  }

  function recordReadingAidKey(base) {
    const id = primaryIdentifier(base);
    if (READING_AIDS_FA[id]) return id;
    const identifiers = Array.isArray(base?.native_identifiers) ? base.native_identifiers : [];
    for (const item of identifiers) {
      const value = String(item?.value || '').toUpperCase();
      if (READING_AIDS_FA[value]) return value;
    }
    return '';
  }

  function ensurePersianReadingAid(base) {
    const hero = document.querySelector('.answer-hero');
    if (!hero) return;
    let aid = hero.querySelector('.persian-reading-aid');
    const key = recordReadingAidKey(base);
    const body = key ? READING_AIDS_FA[key] : 'ترجمه کامل این رکورد هنوز در knowledge pack بسته‌بندی نشده است؛ متن مرجع انگلیسی بدون تغییر نمایش داده می‌شود.';
    if (!aid) {
      aid = node('section', 'persian-reading-aid');
      aid.setAttribute('dir', 'rtl');
      hero.append(aid);
    }
    if (aid.dataset.key !== (key || 'generic')) {
      aid.dataset.key = key || 'generic';
      aid.replaceChildren(node('strong', '', 'راهنمای فارسی (غیرمرجع)'), node('span', '', body));
    }
    aid.hidden = currentLanguage() !== 'fa';
  }

  function currentLanguage() {
    try { return localStorage.getItem('atlas-language') === 'fa' ? 'fa' : 'en'; } catch (_) { return 'en'; }
  }

  function setLanguage(language) {
    const next = language === 'fa' ? 'fa' : 'en';
    try { localStorage.setItem('atlas-language', next); } catch (_) {}
    applyLanguage(next);
  }

  function translateStatic(selector, fa, language) {
    const element = document.querySelector(selector);
    if (!element) return;
    if (!element.dataset.atlasEn) element.dataset.atlasEn = element.textContent;
    const value = language === 'fa' ? fa : element.dataset.atlasEn;
    setTextIfDifferent(element, value);
  }

  function applyLanguage(language = currentLanguage()) {
    document.documentElement.lang = language === 'fa' ? 'fa' : 'en';
    for (const [selector, fa] of Object.entries(STATIC_FA)) translateStatic(selector, fa, language);
    for (const tab of document.querySelectorAll('.quick-tab[data-tab]')) {
      if (!tab.dataset.atlasEn) tab.dataset.atlasEn = tab.textContent;
      const fa = TAB_FA[tab.dataset.tab];
      setTextIfDifferent(tab, language === 'fa' && fa ? fa : tab.dataset.atlasEn);
    }
    const toggle = document.getElementById('languageToggle');
    if (toggle) {
      toggle.textContent = language === 'fa' ? 'EN' : 'FA';
      toggle.title = language === 'fa' ? 'Switch interface to English' : 'نمایش راهنمای فارسی و رابط فارسی';
      toggle.setAttribute('aria-label', toggle.title);
    }
    const entityToggle = document.getElementById('toggleEntity');
    if (entityToggle) {
      const collapsed = document.querySelector('.entity-card')?.classList.contains('collapsed');
      entityToggle.textContent = language === 'fa' ? (collapsed ? 'بازکردن' : 'کوچک‌سازی') : (collapsed ? 'Expand' : 'Minimize');
    }
    for (const aid of document.querySelectorAll('.persian-reading-aid')) aid.hidden = language !== 'fa';
  }

  function installLanguageToggle() {
    if (document.getElementById('languageToggle')) return;
    const status = document.querySelector('.topbar-status');
    if (!status) return;
    const button = node('button', 'language-toggle');
    button.id = 'languageToggle';
    button.type = 'button';
    const refresh = document.getElementById('refreshStatus');
    status.insertBefore(button, refresh || null);
    button.addEventListener('click', () => setLanguage(currentLanguage() === 'fa' ? 'en' : 'fa'));
    applyLanguage();
  }

  function installPivotNavigation() {
    const pivots = document.getElementById('entityPivots');
    if (!pivots || pivots.dataset.navigationFixed === 'true') return;
    pivots.dataset.navigationFixed = 'true';
    pivots.addEventListener('click', event => {
      const button = event.target.closest('.entity-pivot');
      if (!button) return;
      const { kind } = recordParts();
      if (kind !== 'attack') return;
      event.preventDefault();
      event.stopImmediatePropagation();
      const identifier = isAttackIdentifier(button.textContent);
      if (identifier) {
        const input = document.getElementById('searchInput');
        if (input) input.value = identifier;
        if (typeof showView === 'function') showView('explore');
        if (typeof runSearchQuery === 'function') void runSearchQuery(identifier);
        return;
      }
      if (typeof showView === 'function') showView('explore');
      if (typeof activateTab === 'function') activateTab('attack');
    }, true);
  }

  function enhanceDocument() {
    const { detail, base, kind } = recordParts();
    injectStyles();
    installLanguageToggle();
    installPivotNavigation();
    if (!base) { applyLanguage(); return; }
    dedupeHeroBadges();
    enhanceProviderNarrative();
    enhanceAttackProse(kind);
    enhanceFields();
    enhanceVersionDefinitions();
    hideUncuratedEmptyCards();
    enhanceAttackDetails(detail, base, kind);
    enhanceRelationships(detail, base, kind);
    enhanceRecordSymbol(kind);
    enhanceEntityRail(detail, base, kind);
    ensurePersianReadingAid(base);
    applyLanguage();
  }

  function install() {
    injectStyles();
    installLanguageToggle();
    installPivotNavigation();
    if (typeof loadRecord === 'function' && !loadRecord.__atlasAcceptanceWrapped) {
      const originalLoadRecord = loadRecord;
      const wrapped = async function acceptanceAwareLoadRecord(...args) {
        const result = await originalLoadRecord(...args);
        if (result) enhanceDocument();
        return result;
      };
      wrapped.__atlasAcceptanceWrapped = true;
      loadRecord = wrapped;
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', enhanceDocument, { once: true });
    else enhanceDocument();
  }

  return Object.freeze({
    cleanProviderTitle,
    parseProviderTemplate,
    humanizeFieldName,
    humanizeFieldType,
    stripMarkdownLinks,
    extractCitations,
    paragraphize,
    formatAttackIdentifiers,
    classifyRelationship,
    buildRelationshipGroups,
    isAttackIdentifier,
    READING_AIDS_FA,
    install
  });
}));
