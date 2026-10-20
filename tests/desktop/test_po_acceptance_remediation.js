'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..', '..');
const tauriRoot = path.join(root, 'benchmarks', 'desktop', 'phase56', 'candidates', 'tauri');
const remediationPath = path.join(tauriRoot, 'www', 'stale-selection-guard.js');
const remediationSource = fs.readFileSync(remediationPath, 'utf8');
const mainSource = fs.readFileSync(path.join(tauriRoot, 'www', 'main.js'), 'utf8');
const htmlSource = fs.readFileSync(path.join(tauriRoot, 'www', 'index.html'), 'utf8');
const visualSource = fs.readFileSync(path.join(tauriRoot, 'www', 'acceptance-remediation.css'), 'utf8');
const projection = require(path.join(tauriRoot, 'www', 'entity-projection.js'));
const buildRs = fs.readFileSync(path.join(tauriRoot, 'build.rs'), 'utf8');
const remediation = require(remediationPath);

test('provider template placeholders are removed from the analyst title but preserved as explicit metadata', () => {
  const input = 'Windows Security Event 4872 — Certificate Services published the certificate revocation list (CRL). Base CRL: %1 CRL Number: %2 Key Container: %3 Next Publish: %4 Publish URLs: %5';
  assert.equal(remediation.cleanProviderTitle(input), 'Windows Security Event 4872 — Certificate Services published the certificate revocation list (CRL).');
  const parsed = remediation.parseProviderTemplate(input);
  assert.deepEqual(parsed.fields, [
    { label: 'Base CRL', token: '%1' },
    { label: 'CRL Number', token: '%2' },
    { label: 'Key Container', token: '%3' },
    { label: 'Next Publish', token: '%4' },
    { label: 'Publish URLs', token: '%5' }
  ]);
});

test('provider placeholders are removed from search, hero and Entity projections generically', () => {
  const input = 'Windows Security Event 4872 — Certificate Services published the certificate revocation list (CRL). Base CRL: %1 CRL Number: %2';
  assert.equal(projection.cleanProviderTitle(input), 'Windows Security Event 4872 — Certificate Services published the certificate revocation list (CRL).');
  assert.deepEqual(projection.eventTitleParts('4872', input), {
    prefix: 'Windows Security Event ID (4872) :',
    semantic: 'Certificate Services published the certificate revocation list (CRL).'
  });
  assert.ok(mainSource.includes('entityProjection.cleanProviderTitle(m.title'));
  assert.ok(mainSource.includes('event-title-prefix'));
  assert.ok(mainSource.includes('event-title-name'));
});

test('ATT&CK breadcrumb projects tactic, parent technique and current sub-technique', () => {
  const base={entity_type:'attack-subtechnique',title:'Command and Scripting Interpreter: PowerShell',native_identifiers:[{type:'attack_id',value:'T1059.001',primary:true}]};
  const detail={related_entities:[
    {title:'Execution',native_identifiers:[{type:'attack_id',value:'TA0002',primary:true}]},
    {title:'Command and Scripting Interpreter',native_identifiers:[{type:'attack_id',value:'T1059',primary:true}]}
  ]};
  assert.deepEqual(projection.attackBreadcrumb(detail,base,{attack_id:'T1059.001',parent_technique:'T1059',tactics:['TA0002']}),[
    {id:'TA0002',name:'Execution',current:false},
    {id:'T1059',name:'Command and Scripting Interpreter',current:false},
    {id:'T1059.001',name:'Command and Scripting Interpreter: PowerShell',current:true}
  ]);
});

test('ATT&CK mitigations project named mitigated Techniques from source-backed relationships', () => {
  const base={id:'atlas:attack-mitigation:mitre.attack:m1042',entity_type:'attack-mitigation',title:'Disable or Remove Feature or Program',native_identifiers:[{type:'attack_id',value:'M1042',primary:true}]};
  const detail={relationships:[
    {from:base.id,to:'atlas:attack-technique:mitre.attack:t1059',relationship_type:'MITIGATES'},
    {from:base.id,to:'atlas:attack-subtechnique:mitre.attack:t1059.001',relationship_type:'MITIGATES'}
  ],related_entities:[
    {id:'atlas:attack-technique:mitre.attack:t1059',title:'Command and Scripting Interpreter',native_identifiers:[{type:'attack_id',value:'T1059',primary:true}]},
    {id:'atlas:attack-subtechnique:mitre.attack:t1059.001',title:'Command and Scripting Interpreter: PowerShell',native_identifiers:[{type:'attack_id',value:'T1059.001',primary:true}]}
  ]};
  assert.equal(projection.attackObjectType(base,{object_type:'course-of-action'}),'attack-mitigation');
  assert.deepEqual(projection.mitigatedTechniques(detail,base,{mitigated_techniques:['T1059','T1059.001']}),[
    {id:'T1059',name:'Command and Scripting Interpreter',record_id:'atlas:attack-technique:mitre.attack:t1059',label:'T1059 · Command and Scripting Interpreter'},
    {id:'T1059.001',name:'Command and Scripting Interpreter: PowerShell',record_id:'atlas:attack-subtechnique:mitre.attack:t1059.001',label:'T1059.001 · Command and Scripting Interpreter: PowerShell'}
  ]);
  assert.ok(projection.attackDetails({mitigated_techniques:['T1059']}).includes('Mitigated techniques: T1059'));
  assert.ok(projection.entityPivots(base,{}, {attack_id:'M1042',mitigated_techniques:['T1059']},{}).includes('T1059'));
});

test('event value dictionaries are projected into matching field rows', () => {
  assert.ok(mainSource.includes('event_value_dictionaries'));
  assert.ok(mainSource.includes('eventDictionaries[valuesRef]'));
});

test('provider field labels and raw provider types are rendered as analyst-facing text', () => {
  assert.equal(remediation.humanizeFieldName('CRLNumber'), 'CRL Number');
  assert.equal(remediation.humanizeFieldName('IsBaseCRL'), 'Is Base CRL');
  assert.equal(remediation.humanizeFieldName('PublishURLs'), 'Publish URLs');
  assert.equal(remediation.humanizeFieldType('UnicodeString0'), 'Text · Unicode string');
  assert.equal(remediation.humanizeFieldType('UInt32'), 'Unsigned 32-bit integer');
});

test('MITRE prose removes raw Markdown URLs while retaining readable link labels and citations separately', () => {
  const input = 'Linux includes [Unix Shell]([https://attack.mitre.org/techniques/T1059/004](https://attack.mitre.org/techniques/T1059/004)) while Windows includes [PowerShell](https://attack.mitre.org/techniques/T1059/001). (Citation: Powershell Remote Commands)';
  const clean = remediation.stripMarkdownLinks(input);
  assert.match(clean, /Unix Shell/);
  assert.match(clean, /PowerShell/);
  assert.equal(clean.includes('https://'), false);
  assert.deepEqual(remediation.extractCitations(input), ['Powershell Remote Commands']);
});

test('ATT&CK identifiers gain source-backed names only when a name map contains them', () => {
  const names = new Map([['TA0002', 'Execution'], ['T1059.004', 'Unix Shell']]);
  assert.equal(remediation.formatAttackIdentifiers('Tactics: TA0002', names), 'Tactics: TA0002 (Execution)');
  assert.equal(remediation.formatAttackIdentifiers('T1059.004, T1059.999', names), 'T1059.004 (Unix Shell), T1059.999');
});

test('relationship grouping keeps mapped tools source-backed but separates them from ATT&CK hierarchy', () => {
  assert.equal(remediation.classifyRelationship('HAS_MAPPED_TOOL'), 'tools');
  assert.equal(remediation.classifyRelationship('HAS_SUBTECHNIQUE'), 'hierarchy');
  assert.equal(remediation.classifyRelationship('DETECTED_BY'), 'defensive');
});

test('Persian reading aids are bounded and explicitly available for the Product Owner acceptance canaries', () => {
  assert.ok(remediation.READING_AIDS_FA['4872'].includes('%1'));
  assert.ok(remediation.READING_AIDS_FA.T1059.includes('PowerShell'));
  assert.ok(remediation.READING_AIDS_FA['T1059.001'].includes('Script Block Logging'));
  assert.ok(remediation.READING_AIDS_FA.M1042.includes('rollback plan'));
  assert.ok(remediation.READING_AIDS_FA.M1042.includes('Mitigated Techniques'));
  assert.ok(remediationSource.includes('خلاصه فارسی ATLAS'));
  assert.ok(remediationSource.includes("id = 'languageToggle'"));
});

test('acceptance presentation includes hierarchy, split event title and restrained lime headings', () => {
  assert.ok(htmlSource.includes('acceptance-remediation.css'));
  assert.ok(visualSource.includes('.attack-breadcrumb'));
  assert.ok(visualSource.includes('.event-title-prefix'));
  assert.ok(visualSource.includes('#b8ff75'));
  assert.ok(visualSource.includes('.attack-entity-link'));
  assert.ok(mainSource.includes("attackType==='attack-mitigation'"));
  assert.ok(mainSource.includes("attackEntityCard('Mitigated Techniques'"));
});

test('acceptance remediation remains offline and does not add a network path', () => {
  assert.equal(/\bfetch\s*\(/.test(remediationSource), false);
  assert.equal(/XMLHttpRequest/.test(remediationSource), false);
  assert.equal(/WebSocket/.test(remediationSource), false);
});

test('Windows host builds a deterministic branded 32x32 ATLAS icon instead of the prior solid placeholder', () => {
  assert.ok(buildRs.includes('const ICON_WIDTH: u32 = 32;'));
  assert.ok(buildRs.includes('const ICON_HEIGHT: u32 = 32;'));
  assert.ok(buildRs.includes('fn draw_line('));
  assert.ok(buildRs.includes('cyan hex shell and a high-contrast A glyph'));
  assert.equal(buildRs.includes('for _ in 0..(WIDTH * HEIGHT)'), false);
  assert.ok(buildRs.includes('window_icon_path(icon_path)'));
});
