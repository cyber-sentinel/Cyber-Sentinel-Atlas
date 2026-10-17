'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..', '..');
const tauriRoot = path.join(root, 'benchmarks', 'desktop', 'phase56', 'candidates', 'tauri');
const remediationPath = path.join(tauriRoot, 'www', 'stale-selection-guard.js');
const remediationSource = fs.readFileSync(remediationPath, 'utf8');
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
  assert.ok(remediationSource.includes('راهنمای فارسی (غیرمرجع)'));
  assert.ok(remediationSource.includes("id = 'languageToggle'"));
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
