# Relationship to SAGA

Reference: Syros et al., [SAGA, NDSS 2026](https://www.ndss-symposium.org/wp-content/uploads/2026-s869-paper.pdf).
The reference implementation was inspected at
[`7372111bea150e32cee390a616849316d2780bfc`](https://github.com/gsiros/saga/tree/7372111bea150e32cee390a616849316d2780bfc).

SAGA registers agents with a Provider and governs agent contact using
cryptographic communication tokens. SAGA Capability adds a separate execution
protocol for individual functions and resources. The repository follows the
reference's separation of Provider, agent integration, configuration,
experiments and documentation.

| Area | Reference SAGA | This implementation |
| --- | --- | --- |
| Authorization target | Agent communication/contact | Individual registered tool call |
| Token construction | Agent-derived communication token | Provider-signed Ed25519 capability |
| Execution enforcement | Agent communication protocol | Online admission plus C++/kernel sandbox |
| Rights transition | Communication token lifecycle | Single current epoch, revocation before publication |
| API envelopes | Local-agent integration boundary | Provider adapters for five tool-call envelopes |
| State store | Dedicated MongoDB in reference | Dedicated SQLite transactional Provider state |

This is a new implementation inspired by SAGA, not an upstream patch or a
drop-in implementation of its wire protocol. It does not reproduce SAGA's
one-time-key exchange, end-to-end messaging or formal proofs. SAGA's proofs must
not be cited as proofs of this protocol. The contribution to evaluate here is
the strict function/resource boundary and its executable evidence.

The Python namespace is `saga`; use a separate environment if experimenting with
upstream SAGA, which uses the same namespace.
