'use strict';

(function(root,factory){
  const api=factory();
  if(typeof module==='object'&&module.exports)module.exports=api;
  root.AtlasLibraryModel=api;
})(typeof globalThis!=='undefined'?globalThis:this,function(){
  const CATEGORIES=Object.freeze([
    Object.freeze({id:'all',label:'All',filters:Object.freeze({}),types:Object.freeze([])}),
    Object.freeze({id:'attack',label:'MITRE ATT&CK',filters:Object.freeze({source_family:'mitre-attack',lifecycle:'current'}),types:Object.freeze([
      Object.freeze({value:'attack-tactic',label:'Tactics'}),Object.freeze({value:'attack-technique',label:'Techniques'}),Object.freeze({value:'attack-subtechnique',label:'Sub-techniques'})
    ])}),
    Object.freeze({id:'lolbas',label:'LOLBAS',filters:Object.freeze({source_family:'lolbas'}),types:Object.freeze([])}),
    Object.freeze({id:'gtfobins',label:'GTFOBins',filters:Object.freeze({source_family:'gtfobins'}),types:Object.freeze([])}),
    Object.freeze({id:'telemetry',label:'Telemetry',filters:Object.freeze({family:'telemetry'}),types:Object.freeze([
      Object.freeze({value:'windows-security',label:'Windows Security',facet:'telemetry_family'}),Object.freeze({value:'sysmon',label:'Sysmon',facet:'telemetry_family'}),Object.freeze({value:'powershell-operational',label:'PowerShell Operational',facet:'telemetry_family'})
    ])}),
    Object.freeze({id:'hunt',label:'Hunt Knowledge',filters:Object.freeze({source_family:'hunt'}),types:Object.freeze([])})
  ]);
  function category(id){return CATEGORIES.find(item=>item.id===id)||CATEGORIES[0];}
  function filtersFor(categoryId,subtype,lifecycle){
    const selected=category(categoryId),filters={...selected.filters};
    if(subtype){
      const option=selected.types.find(item=>item.value===subtype);
      if(option)filters[option.facet||'type']=option.value;
    }
    if(lifecycle==='all')delete filters.lifecycle;
    else filters.lifecycle=lifecycle||'current';
    return filters;
  }
  function pageNumber(offset,limit){return Math.floor(Math.max(0,offset)/Math.max(1,limit))+1;}
  function nextOffset(page){return Number.isInteger(page?.next_offset)?page.next_offset:null;}
  return Object.freeze({CATEGORIES,category,filtersFor,pageNumber,nextOffset});
});
