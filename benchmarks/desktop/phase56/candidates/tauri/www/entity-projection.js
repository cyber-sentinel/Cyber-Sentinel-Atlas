'use strict';

(function(root,factory){
  const api=factory();
  if(typeof module==='object'&&module.exports)module.exports=api;
  root.AtlasEntityProjection=api;
})(typeof globalThis!=='undefined'?globalThis:this,function(){
  const TAB_MODELS=Object.freeze({
    event:Object.freeze([['overview','Overview'],['fields','Fields'],['example','Example'],['analysis','Detection & Hunt'],['sources','Sources'],['raw','Raw / Canonical']]),
    tool:Object.freeze([['overview','Overview'],['capabilities','Capabilities'],['relationships','Relationships'],['sources','Sources'],['raw','Raw / Canonical']]),
    hunt:Object.freeze([['overview','Overview'],['investigation','Investigation'],['relationships','Relationships'],['sources','Sources'],['raw','Raw / Canonical']]),
    attack:Object.freeze([['overview','Overview'],['attack','ATT&CK Context'],['relationships','Relationships'],['sources','Sources'],['raw','Raw / Canonical']]),
    knowledge:Object.freeze([['overview','Overview'],['relationships','Relationships'],['sources','Sources'],['raw','Raw / Canonical']])
  });

  function kind(base){
    if(base?.entity_type==='event')return 'event';
    if(base?.entity_type==='tool')return 'tool';
    if(['attack-tactic','attack-technique','attack-subtechnique','attack-detection-strategy','attack-analytic','attack-mitigation','attack-data-component'].includes(base?.entity_type))return 'attack';
    const identifiers=Array.isArray(base?.native_identifiers)?base.native_identifiers:[];
    if(base?.entity_type==='activity'&&identifiers.some(item=>item?.type==='hunt_profile'))return 'hunt';
    return 'knowledge';
  }
  function overviewPredicate(base){return ['hunt','attack'].includes(kind(base))?'behavior.description':'telemetry.represents';}
  function tabs(base){return TAB_MODELS[kind(base)];}
  function label(base){return {event:'Telemetry Event',tool:'Tool Intelligence',hunt:'Hunt Profile',attack:'MITRE ATT&CK',knowledge:'Knowledge Entity'}[kind(base)];}
  function attackDetails(security={}){
    const rows=[];
    const add=(label,value)=>{if(value!==null&&value!==undefined&&value!=='')rows.push(`${label}: ${Array.isArray(value)?value.join(', '):value}`);};
    add('ATT&CK ID',security.attack_id);add('STIX ID',security.stix_id);add('Object type',security.object_type);add('Platforms',security.platforms);add('Tactics',security.tactics);add('Parent technique',security.parent_technique_name&&security.parent_technique?`${security.parent_technique} · ${security.parent_technique_name}`:security.parent_technique);add('Sub-techniques',security.subtechniques);add('Detection Strategies',security.detection_strategies);add('Analytics',security.analytics);add('Mitigations',security.mitigations);add('Detected techniques',security.detected_techniques);add('Data Components',security.data_components);add('Version',security.attack_version);add('Source modified',security.source_modified);
    return rows;
  }
  function toolFunctions(security={}){
    const values=[];
    for(const row of Array.isArray(security.gtfobins_functions)?security.gtfobins_functions:[]){
      if(!row||typeof row!=='object')continue;
      const label=String(row.label||row.function||'Capability').trim();
      const contexts=(Array.isArray(row.contexts)?row.contexts:[]).filter(value=>typeof value==='string'&&value.trim());
      const inherited=(Array.isArray(row.inherited_from)?row.inherited_from:[]).filter(value=>typeof value==='string'&&value.trim());
      values.push(`${label}${contexts.length?` · contexts: ${contexts.join(', ')}`:''}${inherited.length?` · inherited from: ${inherited.join(', ')}`:''}`);
    }
    values.push(...(Array.isArray(security.lolbas_categories)?security.lolbas_categories:[]));
    return [...new Set(values.filter(value=>typeof value==='string'&&value.trim()))];
  }
  function toolContexts(security={}){
    return [...new Set((Array.isArray(security.execution_contexts)?security.execution_contexts:[]).map(row=>{
      if(typeof row==='string')return row;
      if(!row||typeof row!=='object')return '';
      const context=String(row.context||'').trim(),meaning=String(row.meaning||'').trim();
      return context?`${context}${meaning?` · ${meaning}`:''}`:'';
    }).filter(Boolean))];
  }
  function toolTechniques(security={}){
    return [...new Set((Array.isArray(security.attack_techniques)?security.attack_techniques:[]).filter(value=>typeof value==='string'&&value.trim()))];
  }
  function entityPivots(base,overview={},security={},collection={}){
    const type=kind(base),values=[];
    if(type==='event')return values;
    if(type==='tool'){
      const functions=(Array.isArray(security.gtfobins_functions)?security.gtfobins_functions:[]).map(row=>row?.label||row?.function);
      const contexts=(Array.isArray(security.execution_contexts)?security.execution_contexts:[]).map(row=>typeof row==='string'?row:row?.context);
      values.push(...functions,...contexts,...(security.lolbas_categories||[]),...toolTechniques(security),...(collection.recommended_telemetry||[]));
    }
    if(type==='hunt')values.push(...(overview.artifact_families||[]),...(security.related_event_ids||[]).map(id=>`Event ${id}`));
    if(type==='attack')values.push(security.attack_id,security.parent_technique,...(security.tactics||[]),...(security.subtechniques||[]),...(security.detection_strategies||[]),...(security.analytics||[]),...(security.mitigations||[]),...(security.data_components||[]),...(security.platforms||[]));
    return [...new Set(values.filter(value=>typeof value==='string'&&value.trim()))].slice(0,8);
  }
  return Object.freeze({kind,overviewPredicate,tabs,label,toolFunctions,toolContexts,toolTechniques,attackDetails,entityPivots,TAB_MODELS});
});
