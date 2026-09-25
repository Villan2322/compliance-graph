// Handy queries for Neo4j Browser (http://localhost:7474). Not run automatically.

// 1. Everything a SQL injection finding touches, end to end
MATCH (w:Weakness {cweId: 'CWE-89'})
OPTIONAL MATCH direct = (w)-[:ADDRESSED_BY]->(:Requirement)
OPTIONAL MATCH threat = (w)<-[:EXPLOITS]-(:AttackPattern)-[:MAPS_TO]->(:Technique)<-[:MITIGATES]-(:Requirement)
RETURN direct, threat LIMIT 50;

// 2. Which frameworks does one NIST control satisfy (needs SCF loaded)?
MATCH (q:Requirement {reqId: 'NIST-800-53-r5:SI-10'})-[:MAPS_TO]->(s:SCFControl)<-[:MAPS_TO]-(o:Requirement)
RETURN s.scfId, o.frameworkId, collect(o.nativeId) AS ids ORDER BY o.frameworkId;

// 3. Open risks by rating across all audited repos
MATCH (k:Risk {status: 'open'})-[:ARISES_FROM]->(:Finding)-[:IN]->(r:Repository)
RETURN r.repoId, k.rating, count(DISTINCT k) AS risks ORDER BY r.repoId, k.rating;

// 4. Dependencies with actively exploited CVEs
MATCH (r:Repository)-[:DEPENDS_ON]->(c:Component)<-[:AFFECTS]-(:Finding)-[:INVOLVES]->(v:Vulnerability {kev: true})
RETURN r.repoId, c.purl, v.cveId, v.kevDueDate, v.ransomware;

// 5. Curated mappings still awaiting human review
MATCH (w:Weakness)-[x:ADDRESSED_BY {reviewed: false}]->(q:Requirement)
RETURN w.cweId, w.name, q.nativeId, q.title, x.confidence, x.rationale ORDER BY w.cweId;

// 6. Controls with the most evidence from automated scans
MATCH (e:Evidence)-[:SUPPORTS]->(q:Requirement)
RETURN q.nativeId, q.title, count(e) AS evidence ORDER BY evidence DESC;

// 7. LLM app threat surface
MATCH (w:Weakness)-[:RELATES_TO]->(a:AITechnique)
OPTIONAL MATCH (m:AIMitigation)-[:MITIGATES]->(a)
RETURN w.cweId, a.atlasId, a.name, collect(m.name)[..5] AS mitigations;
