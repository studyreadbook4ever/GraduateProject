Keep live policy and credentials outside this repository. Create a fresh local
deployment with `saga-cap provision --directory /absolute/private/demo`.
The generated directory is mode 0700 and each file is mode 0600.

The certificate SHA-256 fingerprint identifies an agent. Agent names in tool
calls and natural-language content do not participate in authentication.
Administrator policy maps agent IDs to task IDs and each task to exact tool and
resource pairs. Database query names refer to administrator-written SELECT
statements. An agent supplies parameters, never SQL or a filesystem path.

SQLite resources are frozen database snapshots in rollback format. Use SQLite's
backup API to export a live database, close it, and register the resulting file.
WAL mode and journal sidecars are rejected at startup and each token issuance.
Do not modify a registered snapshot while executions may be reading it.
