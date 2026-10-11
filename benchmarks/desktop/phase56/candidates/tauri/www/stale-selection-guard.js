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
