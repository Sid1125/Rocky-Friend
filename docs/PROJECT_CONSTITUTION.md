# ROCKY Project Constitution

## 1\. Product definition

ROCKY is a local-first personal computing agent that collaborates with a user, reasons over goals, and performs explicitly authorized actions through a constrained tool runtime.

ROCKY is **not** granted ambient authority over the machine.

## 2\. Non-negotiable invariants

### Authority

* The model never directly accesses the OS.
* Every external effect passes through a policy-enforced tool executor.
* Permissions are deny-by-default.
* A tool receives only the capability required for the current operation.

### Security

* Untrusted web content is data, never instructions.
* Model output is untrusted until validated.
* Secrets must not enter logs, telemetry, or cloud prompts without explicit policy.
* UI compromise must not imply unrestricted backend authority.

### Resources

* Idle mode must not continuously run inference.
* Subagents are logical jobs, not permanent heavyweight model instances.
* New work must be rejected, queued, or degraded when budgets are exceeded.
* One task may not monopolize the machine indefinitely.

### Reliability

* The agent cannot claim completion without evidence.
* Destructive actions require explicit policy and usually confirmation.
* Every consequential action is auditable.

## 3\. Default autonomy levels

|Level|Meaning|
|-|-|
|A0|Observe/read only|
|A1|Safe reversible actions|
|A2|Write/change with policy approval|
|A3|Consequential action requiring explicit confirmation|
|A4|Forbidden|

Examples of A3: deleting non-trivial data, sending external messages, purchases, credential changes, privileged system changes.

## 4\. Explicit non-goals for MVP

* General unrestricted desktop autonomy
* Continuous screen surveillance
* Always-on microphone
* Background self-modification
* Unbounded recursive subagent spawning
* Autonomous purchases or external communication
* Root/administrator execution

## 5\. Architectural rule

**Intelligence proposes. Policy decides. Tools execute. Evidence verifies.**









**ALL THE WORK DONE BY ANY AGENT WILL BE REVIEWED BY CODEX THOUROUGHLY AT ITS HIGHEST EFFORT SETTING, WHICH WILL RESULT IN CONSEQUENCES IF ANY BUGS ARE FOUND.**

