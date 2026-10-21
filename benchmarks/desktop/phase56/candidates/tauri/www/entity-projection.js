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
  function normalizeSpaces(value){return String(value==null?'':value).replace(/\s+/g,' ').trim();}
  function cleanProviderTitle(value){
    const text=normalizeSpaces(value),tokenIndex=text.search(/%\d+/);
    if(tokenIndex<0)return text;
    const prefix=text.slice(0,tokenIndex),sentenceBreak=prefix.lastIndexOf('. ');
    if(sentenceBreak>=0)return prefix.slice(0,sentenceBreak+1).trim();
    const fieldStart=prefix.search(/\b(?:Base CRL|CRL Number|Key Container|Next Publish|Publish URLs)\s*:/i);
    if(fieldStart>0)return prefix.slice(0,fieldStart).replace(/[,:;\s]+$/,'').trim();
    return prefix.replace(/[A-Za-z][A-Za-z0-9 /_-]{1,48}:\s*$/,'').replace(/[,:;\s]+$/,'').trim();
  }
  function eventTitleParts(eventId,value){
    const id=normalizeSpaces(eventId),clean=cleanProviderTitle(value);
    const escaped=id.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    const semantic=clean.replace(new RegExp(`^Windows Security Event(?: ID)?\\s*\\(?${escaped}\\)?\\s*(?:—|:|-)\\s*`,'i'),'').trim();
    return {prefix:`Windows Security Event ID (${id}) :`,semantic:semantic||'Provider-defined event'};
  }
  function primaryIdentifier(record){
    const identifiers=Array.isArray(record?.native_identifiers)?record.native_identifiers:[],primary=identifiers.find(item=>item?.primary)||identifiers[0];
    return primary?.value?String(primary.value).toUpperCase():'';
  }
  function attackBreadcrumb(detail,base,security={}){
    if(kind(base)!=='attack')return[];
    const names=new Map(),add=record=>{const id=primaryIdentifier(record);if(id&&record?.title)names.set(id,String(record.title));};
    add(base);for(const related of Array.isArray(detail?.related_entities)?detail.related_entities:[])add(related);
    const current=String(security.attack_id||primaryIdentifier(base)).toUpperCase();
    const parent=String(security.parent_technique||'').toUpperCase();
    if(parent&&security.parent_technique_name&&!names.has(parent))names.set(parent,String(security.parent_technique_name));
    const tacticIds=(Array.isArray(security.tactics)?security.tactics:[]).map(value=>String(value).toUpperCase()).sort();
    const ids=[...tacticIds,parent,current].filter(Boolean);
    return [...new Set(ids)].map(id=>({id,name:names.get(id)||'',current:id===current}));
  }
  function attackDetails(security={}){
    const rows=[];
    const add=(label,value)=>{if(value!==null&&value!==undefined&&value!=='')rows.push(`${label}: ${Array.isArray(value)?value.join(', '):value}`);};
    add('ATT&CK ID',security.attack_id);add('STIX ID',security.stix_id);add('Object type',security.object_type);add('Platforms',security.platforms);add('Tactics',security.tactics);add('Parent technique',security.parent_technique_name&&security.parent_technique?`${security.parent_technique} · ${security.parent_technique_name}`:security.parent_technique);add('Sub-techniques',security.subtechniques);add('Detection Strategies',security.detection_strategies);add('Analytics',security.analytics);add('Mitigations',security.mitigations);add('Mitigated techniques',security.mitigated_techniques);add('Detected techniques',security.detected_techniques);add('Data Components',security.data_components);add('Version',security.attack_version);add('Source modified',security.source_modified);
    return rows;
  }
  function attackObjectType(base,security={}){
    return String(base?.entity_type||security?.object_type||'').toLowerCase();
  }
  function relatedAttackEntities(detail,base,relationshipType){
    const current=String(base?.id||''),relatedById=new Map((Array.isArray(detail?.related_entities)?detail.related_entities:[]).map(record=>[String(record?.id||''),record])),rows=[];
    for(const relationship of Array.isArray(detail?.relationships)?detail.relationships:[]){
      if(!relationship||String(relationship.relationship_type||'').toUpperCase()!==String(relationshipType||'').toUpperCase())continue;
      const outbound=String(relationship.from||'')===current,relatedId=outbound?relationship.to:relationship.from;
      if(!relatedId||String(relatedId).includes(':source:'))continue;
      const record=relatedById.get(String(relatedId)),id=primaryIdentifier(record);
      if(id)rows.push({id,name:String(record?.title||''),record_id:String(relatedId)});
    }
    return rows;
  }
  function mitigatedTechniques(detail,base,security={}){
    const rows=relatedAttackEntities(detail,base,'MITIGATES'),names=new Map(),related=Array.isArray(detail?.related_entities)?detail.related_entities:[];
    for(const record of related){const id=primaryIdentifier(record);if(id&&record?.title)names.set(id,String(record.title));}
    for(const value of Array.isArray(security?.mitigated_techniques)?security.mitigated_techniques:[]){
      const id=String(value||'').toUpperCase();if(id)rows.push({id,name:names.get(id)||'',record_id:''});
    }
    const unique=new Map();
    for(const row of rows){if(!unique.has(row.id))unique.set(row.id,{...row,label:`${row.id}${row.name?` · ${row.name}`:''}`});}
    return [...unique.values()].sort((a,b)=>a.id.localeCompare(b.id,undefined,{numeric:true}));
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
    if(type==='attack')values.push(security.attack_id,security.parent_technique,...(security.tactics||[]),...(security.subtechniques||[]),...(security.detection_strategies||[]),...(security.analytics||[]),...(security.mitigations||[]),...(security.mitigated_techniques||[]),...(security.data_components||[]),...(security.platforms||[]));
    return [...new Set(values.filter(value=>typeof value==='string'&&value.trim()))].slice(0,8);
  }
  return Object.freeze({kind,overviewPredicate,tabs,label,cleanProviderTitle,eventTitleParts,attackBreadcrumb,attackObjectType,relatedAttackEntities,mitigatedTechniques,toolFunctions,toolContexts,toolTechniques,attackDetails,entityPivots,TAB_MODELS});
});
