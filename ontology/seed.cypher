// =====================================================================
// compliance-graph ontology v0.1.0 — seed
// Framework registry. `textRedistributable` controls whether requirement
// text may live in the published dump. Tier 3 frameworks are ID-only
// unless the user imports licensed text locally (BYOL).
// =====================================================================

MERGE (v:OntologyVersion {version: '0.1.0'})
  ON CREATE SET v.appliedAt = datetime()
  ON MATCH SET v.lastAppliedAt = datetime();

UNWIND [
  {id:'NIST-800-53-r5', name:'NIST SP 800-53 Rev. 5', publisher:'NIST', tier:1, redistributable:true,  kind:'control-catalog'},
  {id:'NIST-CSF-2.0',   name:'NIST Cybersecurity Framework 2.0', publisher:'NIST', tier:1, redistributable:true, kind:'framework'},
  {id:'NIST-SSDF-1.1',  name:'NIST SP 800-218 SSDF v1.1', publisher:'NIST', tier:1, redistributable:true, kind:'framework'},
  {id:'NIST-AI-RMF-1.0',name:'NIST AI RMF 1.0', publisher:'NIST', tier:1, redistributable:true, kind:'framework'},
  {id:'SCF',            name:'Secure Controls Framework', publisher:'SCF Council', tier:1, redistributable:true, kind:'metaframework', license:'CC-BY-4.0'},
  {id:'OWASP-ASVS-5.0', name:'OWASP ASVS 5.0', publisher:'OWASP', tier:1, redistributable:true, kind:'standard', license:'CC-BY-SA-4.0'},
  {id:'ISO-27001-2022', name:'ISO/IEC 27001:2022', publisher:'ISO', tier:3, redistributable:false, kind:'standard'},
  {id:'SOC2-TSC-2017',  name:'AICPA Trust Services Criteria (SOC 2)', publisher:'AICPA', tier:3, redistributable:false, kind:'criteria'},
  {id:'PCI-DSS-4.0',    name:'PCI DSS v4.0', publisher:'PCI SSC', tier:3, redistributable:false, kind:'standard'},
  {id:'CIS-v8.1',       name:'CIS Critical Security Controls v8.1', publisher:'CIS', tier:3, redistributable:false, kind:'controls'},
  {id:'HIPAA-SR',       name:'HIPAA Security Rule', publisher:'HHS', tier:1, redistributable:true, kind:'regulation'}
] AS f
MERGE (fw:Framework {frameworkId: f.id})
SET fw.name = f.name, fw.publisher = f.publisher, fw.licenseTier = f.tier,
    fw.textRedistributable = f.redistributable, fw.kind = f.kind,
    fw.license = coalesce(f.license, fw.license),
    fw.updatedAt = datetime();
