# Security boundary

The runtime treats model-produced tool calls as untrusted. Authentication comes
from the TLS peer certificate. Authorization comes from the administrator's
registered task, tool and resource policy. Execution requires both a verified
signed capability and a current, single-use Provider admission.

The Provider, policy files, private keys, C++ coordinator, registered handlers,
kernel and host administrator are trusted. Agent models and tool-call text are
untrusted. The implementation does not isolate mutually hostile programs running
as the same operating-system user, protect a stolen enrolled private key, provide
Byzantine Provider tolerance or roll back completed side effects.

Keep Provider state in a dedicated owner-only directory. Use a fresh PKI for
experiments and separate credentials in an actual deployment. The provisioning
command creates local demonstration material and never imports personal keys.

The worker requires Landlock ABI 9 or newer and refuses execution otherwise.
The host must also permit executable memfds. Each handler runs only after
`execveat` replaces the coordinator image with the sealed embedded executor;
unavailable exec/memfd support has no fork-only fallback. This removes inherited
virtual mappings, not physical RAM remnants or results already returned to a
trusted model runtime. Arbitrary native programs are not exposed as handlers.
The registered handler interface is deliberately finite. Extending it requires
matching Provider validation, exact sandbox derivation and tests. The diagnostic
sandbox probe shares the production sandbox but is not a tool exposed to models.

An unfinished execution is retained across Provider restart. Do not delete the
database or clear its execution rows to restore availability while a worker may
still be alive. First stop the relevant executor and verify its effects. There
is no automatic lease expiry or recovery endpoint in this release.

Persist a stable operation ID before an action and reuse it after uncertainty.
The same ID never receives another grant. Do not delete operation keys to enable
retries: an old request could then repeat an effect. Stored completion receipts
contain sensitive output, are readable only with the original enrolled
certificate, and require the same protection as state and backups. Audit and
failure streams remain redacted. A missing completion is not proof that an
external effect did not occur.

Report a suspected issue with the affected revision, the exact input and a
reproduction using fresh test credentials. Exclude private keys and live tokens.
