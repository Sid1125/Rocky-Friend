# Permission Model

## Capability-based permissions

Permissions are structured capabilities, not a boolean `can_use_computer`.

Examples:

```text
filesystem.read(path_scope)
filesystem.write(path_scope)
process.execute(command_scope)
network.connect(host_scope)
browser.interact(origin_scope)
```

## Permission decision

A request is allowed only if:

1. capability exists;
2. requested scope is within granted scope;
3. current autonomy level permits it;
4. risk policy permits it;
5. resource policy permits it;
6. required approval has been obtained.

## Path scopes

Use canonicalized paths and reject traversal outside authorized roots.

Never authorize based solely on raw string prefix.

## Shell execution

Preferred order:
1. structured tool;
2. allowlisted executable with typed arguments;
3. sandboxed command;
4. arbitrary shell only with explicit elevated permission.

Shell strings must not be the default tool API.

## Revocation

Permissions must be revocable immediately. Running work should receive cancellation or lose access at the next enforcement boundary.
