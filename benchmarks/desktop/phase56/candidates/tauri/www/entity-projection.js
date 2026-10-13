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
    knowledge:Object.freeze([['overview','Overview'],['relationships','Relationships'],['sources','Sources'],['raw','Raw / Canonical']])
  });

  function kind(base){
    if(base?.entity_type==='event')return 'event';
    if(base?.entity_type==='tool')return 'tool';
    const identifiers=Array.isArray(base?.native_identifiers)?base.native_identifiers:[];
    if(base?.entity_type==='activity'&&identifiers.some(item=>item?.type==='hunt_profile'))return 'hunt';
    return 'knowledge';
  }
  function overviewPredicate(base){return kind(base)==='hunt'?'behavior.description':'telemetry.represents';}
  function tabs(base){return TAB_MODELS[kind(base)];}
  function label(base){return {event:'Telemetry Event',tool:'Tool Intelligence',hunt:'Hunt Profile',knowledge:'Knowledge Entity'}[kind(base)];}
  function entityPivots(base,overview={},security={},collection={}){
    const type=kind(base),values=[];
    if(type==='event')return values;
    if(type==='tool')values.push(...(security.lolbas_categories||[]),...(security.attack_techniques||[]),...(collection.recommended_telemetry||[]));
    if(type==='hunt')values.push(...(overview.artifact_families||[]),...(security.related_event_ids||[]).map(id=>`Event ${id}`));
    return [...new Set(values.filter(value=>typeof value==='string'&&value.trim()))].slice(0,8);
  }
  return Object.freeze({kind,overviewPredicate,tabs,label,entityPivots,TAB_MODELS});
});
