# Threat Model

## Assets

- user files
- credentials/API keys
- source code
- external accounts
- system integrity
- privacy
- compute resources

## Primary threats

### Prompt injection
Untrusted files/webpages may contain instructions intended to manipulate the agent.

Mitigation:
- treat external content as data;
- never automatically convert content into authority;
- isolate retrieved instructions from system policy;
- require explicit tool-policy checks.

### Excessive authority
A compromised or mistaken agent may attempt broad filesystem/process actions.

Mitigation:
- capability scopes;
- least privilege;
- confirmation gates;
- sandboxing.

### Secret exfiltration
Model prompts or tools may expose credentials.

Mitigation:
- secret redaction;
- OS-backed credential storage;
- provider-specific data policy;
- explicit cloud boundaries.

### Runaway execution
Recursive agents or loops consume resources.

Mitigation:
- budgets;
- deadlines;
- max depth;
- cancellation;
- resource governor.

### Supply chain compromise
Dependencies or plugins introduce malicious code.

Mitigation:
- lockfiles;
- dependency review;
- SBOM;
- vulnerability scanning;
- minimal dependencies.

### False completion
The agent reports success without satisfying the goal.

Mitigation:
- goal contract;
- verification steps;
- evidence requirements;
- honest partial completion states.
