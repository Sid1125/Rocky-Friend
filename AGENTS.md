# Instructions for Coding Agents

Before modifying code:

1. Read `docs/PROJECT_CONSTITUTION.md`.
2. Read the subsystem documentation in `docs/`.
3. Preserve dependency direction.
4. Do not bypass the tool broker.
5. Do not add ambient authority.
6. Do not introduce unbounded loops or subagent recursion.
7. Prefer lightweight standard-library solutions before adding dependencies.
8. Add tests for changed behavior.

## Definition of done

A change is complete only when:
- the requested behavior works;
- relevant invariants remain true;
- tests pass;
- no security boundary was silently widened;
- documentation is updated when contracts changed.

Never report success without verification evidence.


ALL THE WORK DONE BY ANY AGENT WILL BE REVIEWED BY CODEX THOUROUGHLY AT ITS HIGHEST EFFORT SETTING, WHICH WILL RESULT IN CONSEQUENCES IF ANY BUGS ARE FOUND.