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

  return Object.freeze({ PLAYBOOKS, build });
}));
