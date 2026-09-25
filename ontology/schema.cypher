// =====================================================================
// compliance-graph ontology v0.1.0 — schema (Neo4j 5.x Community)
// Run before any ingestion. Idempotent: safe to re-run.
// Community Edition supports UNIQUE constraints, range/text/fulltext/
// vector indexes. Existence and property-type constraints are
// Enterprise-only, so required properties are enforced in code
// (cgraph/ingest/*) and verified by `cgraph verify`.
// =====================================================================

// ---------- Registry / provenance ----------
CREATE CONSTRAINT source_id IF NOT EXISTS FOR (n:Source) REQUIRE n.sourceId IS UNIQUE;
CREATE CONSTRAINT ontology_version IF NOT EXISTS FOR (n:OntologyVersion) REQUIRE n.version IS UNIQUE;

// ---------- Compliance layer ----------
CREATE CONSTRAINT framework_id IF NOT EXISTS FOR (n:Framework) REQUIRE n.frameworkId IS UNIQUE;
CREATE CONSTRAINT requirement_id IF NOT EXISTS FOR (n:Requirement) REQUIRE n.reqId IS UNIQUE;
CREATE CONSTRAINT scf_control_id IF NOT EXISTS FOR (n:SCFControl) REQUIRE n.scfId IS UNIQUE;

// ---------- Threat / weakness layer ----------
CREATE CONSTRAINT weakness_id IF NOT EXISTS FOR (n:Weakness) REQUIRE n.cweId IS UNIQUE;
CREATE CONSTRAINT attack_pattern_id IF NOT EXISTS FOR (n:AttackPattern) REQUIRE n.capecId IS UNIQUE;
CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (n:Technique) REQUIRE n.attackId IS UNIQUE;
CREATE CONSTRAINT tactic_id IF NOT EXISTS FOR (n:Tactic) REQUIRE n.attackId IS UNIQUE;
CREATE CONSTRAINT mitigation_id IF NOT EXISTS FOR (n:Mitigation) REQUIRE n.attackId IS UNIQUE;
CREATE CONSTRAINT ai_technique_id IF NOT EXISTS FOR (n:AITechnique) REQUIRE n.atlasId IS UNIQUE;
CREATE CONSTRAINT ai_tactic_id IF NOT EXISTS FOR (n:AITactic) REQUIRE n.atlasId IS UNIQUE;
CREATE CONSTRAINT ai_mitigation_id IF NOT EXISTS FOR (n:AIMitigation) REQUIRE n.atlasId IS UNIQUE;
CREATE CONSTRAINT vulnerability_id IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.cveId IS UNIQUE;

// ---------- Code layer ----------
CREATE CONSTRAINT detection_rule_id IF NOT EXISTS FOR (n:DetectionRule) REQUIRE n.ruleId IS UNIQUE;
CREATE CONSTRAINT secure_topic_id IF NOT EXISTS FOR (n:SecureCodingTopic) REQUIRE n.topicId IS UNIQUE;

// ---------- Audit layer (written by the agent) ----------
CREATE CONSTRAINT repository_id IF NOT EXISTS FOR (n:Repository) REQUIRE n.repoId IS UNIQUE;
CREATE CONSTRAINT component_purl IF NOT EXISTS FOR (n:Component) REQUIRE n.purl IS UNIQUE;
CREATE CONSTRAINT audit_run_id IF NOT EXISTS FOR (n:AuditRun) REQUIRE n.runId IS UNIQUE;
CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (n:Finding) REQUIRE n.findingId IS UNIQUE;
CREATE CONSTRAINT risk_id IF NOT EXISTS FOR (n:Risk) REQUIRE n.riskId IS UNIQUE;
CREATE CONSTRAINT evidence_id IF NOT EXISTS FOR (n:Evidence) REQUIRE n.evidenceId IS UNIQUE;

// ---------- Range indexes for traversal filters ----------
CREATE INDEX requirement_framework IF NOT EXISTS FOR (n:Requirement) ON (n.frameworkId);
CREATE INDEX requirement_native IF NOT EXISTS FOR (n:Requirement) ON (n.nativeId);
CREATE INDEX requirement_family IF NOT EXISTS FOR (n:Requirement) ON (n.family);
CREATE INDEX vulnerability_kev IF NOT EXISTS FOR (n:Vulnerability) ON (n.kev);
CREATE INDEX finding_status IF NOT EXISTS FOR (n:Finding) ON (n.status);
CREATE INDEX risk_rating IF NOT EXISTS FOR (n:Risk) ON (n.rating);
CREATE INDEX risk_status IF NOT EXISTS FOR (n:Risk) ON (n.status);
CREATE INDEX weakness_active IF NOT EXISTS FOR (n:Weakness) ON (n.isActive);

// ---------- Full-text (keyword retrieval for agents) ----------
CREATE FULLTEXT INDEX control_text IF NOT EXISTS
  FOR (n:Requirement|SCFControl) ON EACH [n.title, n.text, n.guidance];
CREATE FULLTEXT INDEX threat_text IF NOT EXISTS
  FOR (n:Weakness|AttackPattern|Technique|AITechnique) ON EACH [n.name, n.description];

// ---------- Vector (semantic retrieval; populated by `cgraph embed`) ----------
// 384 dims = BAAI/bge-small-en-v1.5 via fastembed. Change both here and
// CGRAPH_EMBED_DIM if you switch models.
CREATE VECTOR INDEX requirement_embedding IF NOT EXISTS
  FOR (n:Requirement) ON n.embedding
  OPTIONS { indexConfig: { `vector.dimensions`: 384, `vector.similarity_function`: 'cosine' } };
CREATE VECTOR INDEX weakness_embedding IF NOT EXISTS
  FOR (n:Weakness) ON n.embedding
  OPTIONS { indexConfig: { `vector.dimensions`: 384, `vector.similarity_function`: 'cosine' } };
