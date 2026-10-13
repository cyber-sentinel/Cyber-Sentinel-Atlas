'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..', '..');
const webRoot = path.join(root, 'benchmarks', 'desktop', 'phase56', 'candidates', 'tauri', 'www');
const html = fs.readFileSync(path.join(webRoot, 'index.html'), 'utf8');
const main = fs.readFileSync(path.join(webRoot, 'main.js'), 'utf8');
const rust = fs.readFileSync(path.join(root, 'benchmarks', 'desktop', 'phase56', 'candidates', 'tauri', 'src', 'main.rs'), 'utf8');
const library = require(path.join(webRoot, 'library-model.js'));
const projection = require(path.join(webRoot, 'entity-projection.js'));

test('Library categories map to deterministic governed facets', () => {
  assert.deepEqual(library.CATEGORIES.map(item => item.id), ['all','attack','lolbas','gtfobins','telemetry','hunt']);
  assert.deepEqual(library.filtersFor('attack','attack-subtechnique','current'), {source_family:'mitre-attack',type:'attack-subtechnique',lifecycle:'current'});
  assert.deepEqual(library.filtersFor('attack','',''), {source_family:'mitre-attack',lifecycle:'current'});
  assert.deepEqual(library.filtersFor('attack','','all'), {source_family:'mitre-attack'});
  assert.deepEqual(library.filtersFor('telemetry','sysmon',''), {family:'telemetry',telemetry_family:'sysmon'});
  assert.equal(library.pageNumber(96,48),3);
  assert.equal(library.nextOffset({next_offset:48}),48);
  assert.equal(library.nextOffset({next_offset:null}),null);
});

test('Library UI uses runtime catalog counts, filters and bounded pagination', () => {
  for (const id of ['libraryCategories','libraryQuery','librarySubtype','libraryLifecycle','libraryGrid','libraryPrevious','libraryNext']) assert.ok(html.includes(`id="${id}"`));
  assert.ok(main.includes('await atlas.catalog('));
  assert.ok(main.includes("state.libraryLimit:48") === false);
  assert.ok(main.includes('libraryLimit:48'));
  assert.ok(rust.includes('const MAX_UI_CATALOG_OFFSET: i64 = 1_000_000'));
  assert.ok(rust.includes('if filters.len() > 16'));
  assert.ok(rust.includes('"catalog.list"'));
  assert.equal(main.includes('.innerHTML'),false);
});

test('ATT&CK tactics, techniques and sub-techniques use a generic non-event projection', () => {
  for (const entityType of ['attack-tactic','attack-technique','attack-subtechnique']) {
    const entity={entity_type:entityType,native_identifiers:[{type:'attack_id',value:'T1059'}]};
    assert.equal(projection.kind(entity),'attack');
    assert.equal(projection.overviewPredicate(entity),'behavior.description');
    assert.deepEqual(projection.tabs(entity).map(tab=>tab[1]),['Overview','ATT&CK Context','Relationships','Sources','Raw / Canonical']);
    assert.equal(projection.tabs(entity).some(tab=>tab[1]==='Fields'),false);
  }
  const security={attack_id:'T1059.001',stix_id:'attack-pattern--example',object_type:'sub-technique',platforms:['Windows'],tactics:['TA0002'],parent_technique:'T1059',attack_version:'19.2'};
  assert.ok(projection.attackDetails(security).includes('ATT&CK ID: T1059.001'));
  assert.deepEqual(projection.entityPivots({entity_type:'attack-subtechnique'}, {}, security, {}), ['T1059.001','T1059','TA0002','Windows']);
});
