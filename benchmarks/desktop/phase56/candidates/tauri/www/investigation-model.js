(function exposeAtlasInvestigationModel(root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.AtlasInvestigationModel = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function buildAtlasInvestigationModel() {
  'use strict';

  const PLAYBOOKS = Object.freeze({
    'atlas:event:microsoft.windows.security:4625': Object.freeze({
      title: 'Credential Failure Investigation',
      purpose: 'Distinguish credential attack patterns from stale credentials, service failures and isolated user error.',
      requirements: [
        ['Identity target', ['targetusername', 'target-user-name', 'targetdomainsid', 'target-domain-name']],
        ['Origin context', ['ipaddress', 'ip-address', 'workstationname', 'workstation-name', 'sourceport', 'source-port']],
        ['Logon pathway', ['logontype', 'logon-type', 'authenticationpackagename', 'authentication-package-name']],
        ['Failure reason', ['status', 'substatus', 'failure-reason']]
      ],
      hypotheses: [
        ['Password spray', 'Repeated failures across multiple accounts from a shared origin or infrastructure pattern.'],
        ['Brute force', 'Repeated failures against one or a small number of accounts from a concentrated origin.'],
        ['Remote access attack', 'Network or remote-interactive logon context consistent with RDP or another remote service.'],
        ['Benign credential failure', 'User error, stale stored credential, service account or scheduled task misconfiguration.']
      ],
      checks: [
        'Group by source address, target account, LogonType and time window.',
        'Correlate with 4624, 4672 and 4740 using account, origin and time.',
        'Inspect Status/SubStatus and authentication package before assigning intent.',
        'Validate expected service, scheduled-task and remote-access behavior.'
      ]
    }),
    'atlas:event:microsoft.windows.security:4688': Object.freeze({
      title: 'Suspicious Process Execution Investigation',
      purpose: 'Evaluate process creation using image, command line, creator context and surrounding telemetry.',
      requirements: [
        ['Created process', ['newprocessname', 'new-process-name', 'newprocessid', 'new-process-id']],
        ['Command context', ['commandline', 'process-command-line', 'command-line']],
        ['Creator context', ['creatorprocessname', 'creator-process-name', 'processid', 'process-id']],
        ['Security context', ['subjectusername', 'subject-user-name', 'targetusername', 'target-user-name', 'token-elevation-type']]
      ],
      hypotheses: [
        ['Living-off-the-land execution', 'A trusted Windows binary may be used with an unusual command line or execution context.'],
        ['Script or shell execution', 'Interpreter or shell activity may require PowerShell, script-block and child-process pivots.'],
        ['Persistence execution', 'Process creation may originate from a service, scheduled task or another persistence mechanism.'],
        ['Expected administrative activity', 'Approved automation, software deployment or interactive administration may explain the process.']
      ],
      checks: [
        'Validate image path, command line, signer/hash evidence and expected parent process.',
        'Correlate with Sysmon 1 by process identity, image, user and timestamp.',
        'Pivot to network, DNS, file and registry activity attributable to the process.',
        'Compare with change windows, deployment systems and administrator activity.'
      ]
    }),
    'atlas:event:microsoft.sysmon:1': Object.freeze({
      title: 'Process / LOLBin Investigation',
      purpose: 'Reconstruct process lineage and evaluate image, command, user, integrity and hash context.',
      requirements: [
        ['Stable process identity', ['processguid', 'process-guid', 'processid', 'process-id']],
        ['Execution content', ['image', 'commandline', 'command-line', 'currentdirectory', 'current-directory']],
        ['Parent lineage', ['parentprocessguid', 'parent-process-guid', 'parentimage', 'parent-image', 'parentcommandline', 'parent-command-line']],
        ['Trust context', ['hashes', 'originalfilename', 'original-file-name', 'company', 'integritylevel', 'integrity-level', 'user']]
      ],
      hypotheses: [
        ['LOLBAS-style abuse', 'A legitimate binary may be operating with an uncommon command pattern or origin.'],
        ['Suspicious process lineage', 'Parent/child structure may be inconsistent with the expected application or user workflow.'],
        ['Masqueraded or altered image', 'Path, metadata, configured hashes or original filename may conflict with expectations.'],
        ['Expected automation', 'Approved management, deployment, security or administrative tooling may explain the execution.']
      ],
      checks: [
        'Reconstruct lineage with ProcessGuid and ParentProcessGuid before relying on reusable PIDs.',
        'Correlate ProcessGuid with Sysmon network, DNS, image-load, access and termination events.',
        'Validate command line, path, configured hashes and image metadata as separate evidence.',
        'Corroborate with Windows Security 4688 and environment-specific allowlisted automation.'
      ]
    })
  });

  function normalize(value) {
    return String(value || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
  }

  function fieldIdentity(field) {
    return [field?.id, field?.canonical_key, field?.title, field?.native_name].filter(Boolean).map(normalize).join('|');
  }

  function build(detail) {
    if (!detail || detail.detail_version !== '1.0.0' || !detail.record) return null;
    const record = detail.record;
    const playbook = PLAYBOOKS[record.id];
    if (!playbook) return null;
    const fields = Array.isArray(detail.fields) ? detail.fields : [];
    const sources = Array.isArray(detail.sources) ? detail.sources : [];
    const nodes = [{
      id: 'record',
      classification: 'FACT',
      label: record.title || record.id,
      detail: 'Verified canonical record identity and semantics from the active pack.',
      status: 'VERIFIED'
    }];
    const edges = [];

    playbook.requirements.forEach(([label, terms], index) => {
      const matches = fields.filter(field => terms.some(term => fieldIdentity(field).includes(normalize(term))));
      const nodeId = `evidence-${index + 1}`;
      nodes.push({
        id: nodeId,
        classification: 'EVIDENCE REQUIREMENT',
        label,
        detail: matches.length ? matches.map(field => field.title || field.canonical_key || field.id).slice(0, 5).join(' · ') : 'Required field group is not present in the bounded detail projection.',
        status: matches.length ? 'AVAILABLE IN SCHEMA' : 'COLLECTION GAP',
        record_ids: matches.map(field => field.id).filter(Boolean)
      });
      edges.push({ from: 'record', to: nodeId, type: 'REQUIRES_EVIDENCE' });
    });

    playbook.hypotheses.forEach(([label, detailText], index) => {
      const nodeId = `hypothesis-${index + 1}`;
      nodes.push({ id: nodeId, classification: 'HYPOTHESIS', label, detail: detailText, status: 'UNASSESSED' });
      playbook.requirements.forEach((_, evidenceIndex) => edges.push({ from: `evidence-${evidenceIndex + 1}`, to: nodeId, type: 'INFORMS' }));
    });

    playbook.checks.forEach((detailText, index) => {
      const nodeId = `check-${index + 1}`;
      nodes.push({ id: nodeId, classification: 'CHECK', label: `Analyst check ${index + 1}`, detail: detailText, status: 'RECOMMENDED' });
      const hypothesisId = `hypothesis-${(index % playbook.hypotheses.length) + 1}`;
      edges.push({ from: hypothesisId, to: nodeId, type: 'REQUIRES_CHECK' });
    });

    sources.slice(0, 4).forEach((source, index) => {
      const nodeId = `source-${index + 1}`;
      nodes.push({
        id: nodeId,
        classification: 'PROVENANCE',
        label: source.title || source.canonical_key || source.id || `Source ${index + 1}`,
        detail: source.id || 'Source identity unavailable',
        status: 'LINKED'
      });
      edges.push({ from: nodeId, to: 'record', type: 'SUPPORTS_SEMANTICS' });
    });

    return Object.freeze({
      version: 'atlas-investigation/v0',
      record_id: record.id,
      title: playbook.title,
      purpose: playbook.purpose,
      confidence: 'UNASSESSED',
      nodes: Object.freeze(nodes),
      edges: Object.freeze(edges)
    });
  }

  const CASE_KINDS = Object.freeze(['positive', 'benign', 'incomplete']);
  const EVIDENCE_STATES = Object.freeze(['PRESENT', 'ABSENT', 'UNKNOWN']);
  const ASSESSMENT_EFFECTS = Object.freeze(['SUPPORTS', 'REFUTES', 'UNKNOWN']);

  function boundedString(value, name, maximum) {
    if (typeof value !== 'string' || !value.trim() || value.length > maximum) {
      throw new TypeError(`${name} must be a non-empty string no longer than ${maximum} characters`);
    }
    return value.trim();
  }

  function applyEvidence(graph, evidenceSet) {
    if (!graph || graph.version !== 'atlas-investigation/v0' || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) {
      throw new TypeError('a valid atlas-investigation/v0 graph is required');
    }
    if (!evidenceSet || typeof evidenceSet !== 'object') throw new TypeError('an evidence set is required');

    const scenarioId = boundedString(evidenceSet.scenario_id, 'scenario_id', 128);
    const recordId = boundedString(evidenceSet.record_id, 'record_id', 256);
    if (recordId !== graph.record_id) throw new TypeError('evidence record_id does not match the investigation graph');
    if (!CASE_KINDS.includes(evidenceSet.case_kind)) throw new TypeError('case_kind is not supported');
    if (!Array.isArray(evidenceSet.observations) || evidenceSet.observations.length > 64) {
      throw new TypeError('observations must be an array containing at most 64 items');
    }

    const hypothesisIds = new Set(graph.nodes.filter(node => node.classification === 'HYPOTHESIS').map(node => node.id));
    const seen = new Set();
    const assessmentCounts = new Map([...hypothesisIds].map(id => [id, { supports: 0, refutes: 0 }]));
    const evidenceNodes = [];
    const evidenceEdges = [];

    evidenceSet.observations.forEach((observation, index) => {
      if (!observation || typeof observation !== 'object') throw new TypeError(`observation ${index + 1} is invalid`);
      const sourceId = boundedString(observation.source_id, `observation ${index + 1} source_id`, 256);
      const observationId = boundedString(observation.id, `observation ${index + 1} id`, 128);
      if (seen.has(observationId)) throw new TypeError(`duplicate observation id: ${observationId}`);
      seen.add(observationId);
      if (!EVIDENCE_STATES.includes(observation.state)) throw new TypeError(`observation ${observationId} state is unsupported`);
      const assessments = Array.isArray(observation.assessments) ? observation.assessments : [];
      if (assessments.length > hypothesisIds.size) throw new TypeError(`observation ${observationId} has too many assessments`);

      const nodeId = `observed-${observationId}`;
      evidenceNodes.push(Object.freeze({
        id: nodeId,
        classification: 'EVIDENCE',
        label: boundedString(observation.label, `observation ${observationId} label`, 160),
        detail: boundedString(observation.summary, `observation ${observationId} summary`, 500),
        status: observation.state,
        provenance_id: sourceId
      }));
      evidenceEdges.push(Object.freeze({ from: nodeId, to: 'record', type: 'DERIVED_FROM_RECORD_CONTEXT' }));

      const assessedHypotheses = new Set();
      assessments.forEach(assessment => {
        if (!assessment || typeof assessment !== 'object' || !hypothesisIds.has(assessment.hypothesis_id)) {
          throw new TypeError(`observation ${observationId} targets an unknown hypothesis`);
        }
        if (!ASSESSMENT_EFFECTS.includes(assessment.effect)) throw new TypeError(`observation ${observationId} effect is unsupported`);
        if (assessedHypotheses.has(assessment.hypothesis_id)) throw new TypeError(`observation ${observationId} repeats a hypothesis assessment`);
        assessedHypotheses.add(assessment.hypothesis_id);
        evidenceEdges.push(Object.freeze({ from: nodeId, to: assessment.hypothesis_id, type: assessment.effect }));
        const count = assessmentCounts.get(assessment.hypothesis_id);
        if (assessment.effect === 'SUPPORTS') count.supports += 1;
        if (assessment.effect === 'REFUTES') count.refutes += 1;
      });
    });

    let assessed = 0;
    let conflicted = 0;
    const nodes = graph.nodes.map(node => {
      if (node.classification !== 'HYPOTHESIS') return node;
      const count = assessmentCounts.get(node.id);
      let status = 'UNASSESSED';
      if (count.supports && count.refutes) {
        status = 'CONFLICTING EVIDENCE';
        conflicted += 1;
      } else if (count.supports) {
        status = 'SUPPORTED BY PROVIDED EVIDENCE';
        assessed += 1;
      } else if (count.refutes) {
        status = 'REFUTED BY PROVIDED EVIDENCE';
        assessed += 1;
      }
      return Object.freeze({ ...node, status });
    });

    return Object.freeze({
      ...graph,
      scenario_id: scenarioId,
      case_kind: evidenceSet.case_kind,
      confidence: conflicted ? 'EVIDENCE-CONFLICTED' : assessed ? 'BOUNDED-EVIDENCE' : 'INCOMPLETE',
      nodes: Object.freeze([...nodes, ...evidenceNodes]),
      edges: Object.freeze([...graph.edges, ...evidenceEdges])
    });
  }

  return Object.freeze({ PLAYBOOKS, CASE_KINDS, EVIDENCE_STATES, ASSESSMENT_EFFECTS, build, applyEvidence });
}));
