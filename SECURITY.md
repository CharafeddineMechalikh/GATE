# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| Earlier | No |

## Reporting a vulnerability

Do not open a public issue for a security bypass. Use GitHub's private advisory flow:

<https://github.com/CharafeddineMechalikh/GATE/security/advisories/new>

Include a minimal reproduction and state whether the tool call reached the GATE guard. Do not include secrets, live credentials, or third-party data.

## Scope

GATE is a policy-enforcement layer at the tool-dispatch boundary. In scope:

- A guarded tool body executing without an `ALLOW` decision or an approved escalation.
- A failed postcondition whose output still reaches the agent.
- A stage error that is treated as a pass instead of a denial.
- An escalation that is dispatched without approval.
- An adapter that fails to install a guard on a tool it reports as guarded.

Out of scope, as documented in the [security model](docs/security-model.md):

- A compromised Python process, interpreter, dependency, or tool implementation.
- Code that invokes a raw tool callable directly, bypassing the guarded object.
- Tools that the adapter never receives or discovers.
- Rollback of side effects that already occurred.
- Authentication of human approvers.
- Prompt injection that stays within the allowed tool surface and satisfies all contracts.

Read the [security model](docs/security-model.md) before deploying GATE in a production path.
