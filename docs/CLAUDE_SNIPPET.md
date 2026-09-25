<!-- Paste into the CLAUDE.md of any repo you want the coding agent to keep compliant. -->

## Security and compliance (compliance-graph MCP)

Before writing or changing code that touches authentication, authorization, sessions,
database queries, shell/process execution, file paths or uploads, outbound HTTP,
deserialization, cryptography or secrets, logging, dependencies, or LLM/agent calls:

1. Call `secure_coding_checklist` with the topic and follow its guidance.
2. If you are unsure whether a pattern is safe, call `controls_for_cwe` for the likely CWE.

Before you say a task is done:

3. Call `run_audit` on the repository root.
4. Fix every Critical and High risk you introduced. If a risk is pre-existing or you
   cannot fix it, say so explicitly and list its risk ID and implicated controls.
5. Never disable a scanner, delete a rule, or add a suppression to make the audit pass.
