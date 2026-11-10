# VTR-NIST-108-Q4-001 — KDF Construction Distinguishability

**Reproducible synthetic evidence supporting public comments on NIST SP 800-108 Rev. 2, Question 4.**

## Context

On November 4, 2026, Vector Telemetry Research (VTR) submitted public comments concerning Question 4 of the [NIST SP 800-108 Rev. 2 pre-draft consultation](https://csrc.nist.gov/pubs/sp/800/108/r2/iprd).

The comments address compatibility, implementation distinguishability, validation dependencies, and transition traceability when revising, deprecating, or retiring key-derivation constructions.

This repository preserves a synthetic laboratory experiment developed to support those comments.

**This repository is not a NIST publication, a FIPS validation, an implementation certification, or a cryptographic security assessment.**

## Research objective

The experiment examines whether selected KDF constructions produce distinguishable outputs under explicitly defined synthetic inputs.

The implemented cases include the TLS 1.2 PRF, SP 800-108 Double-Pipeline Iteration Mode with and without its optional counter, and SP 800-108 Counter Mode, using HMAC-SHA-256.

The experiment is intended to demonstrate observable differences under specified conditions. It does not establish general interoperability, normative equivalence, or normative dependency between the constructions.

## Repository contents

| Path | Purpose |
|---|---|
| `probe.py` | Synthetic implementations and experimental observations |
| `test_probe.py` | 15 unit tests covering reference behavior, reproducibility, distinguishability, and negative assertions |
| `matrix_synthetic.json` | Synthetic transition matrix and validation rules |
| `evidence/probe_results.json` | Archived baseline experimental results |
| `evidence/test_log.txt` | Archived baseline test execution |
| `evidence/freebsd-14.5-python3.12/` | FreeBSD reproduction logs, results, environment record, and integrity manifest |
| `VTR-NIST-108-Q4-VALIDATION.md` | Original experimental validation report |
| `VTR-NIST-108-Q4-CROSS-PLATFORM-ADDENDUM.md` | Subsequent cross-platform reproduction record and updated gate assessment |
| `SHA256SUMS.txt` | Primary artifact integrity manifest |
| `SHA256SUMS-ADDENDUM.txt` | Addendum integrity manifest |

The original validation report is preserved unchanged. Its earlier gate status is supplemented by the cross-platform addendum rather than retroactively rewritten.

## Reproduction

The scripts use the Python standard library. The documented executions used Python 3.12 and 3.13; compatibility with other versions has not been established by this evidence package.

Run the following commands in a disposable working copy to preserve the archived evidence:

```sh
python3 test_probe.py
python3 probe.py
```

Expected results for the documented environments:

- 15 unit tests completed successfully.
- Four defined experimental observations reported `PASS`.
- Synthetic transition-matrix validation reported `PASS`.

These results apply to the included test inputs and assertions only.

## Integrity verification

From the repository root, on Linux with GNU coreutils:

```sh
sha256sum -c SHA256SUMS.txt
sha256sum -c SHA256SUMS-ADDENDUM.txt
sha256sum -c evidence/freebsd-14.5-python3.12/SHA256SUMS.txt
```

The three manifests cover 11 preserved evidence and source files.

The original laboratory artifacts and their subsequent addendum are maintained as separate integrity records.

## Documented execution environments

| Environment | Python | Unit tests | Defined observations |
|---|---|---|---|
| Linux 6.18.57, x86_64 | 3.13.5 | 15/15 | 4/4 PASS |
| Linux 6.17.0-40, x86_64 | 3.12.3 | 15/15 | 4/4 PASS |
| FreeBSD 14.5-RELEASE, amd64 | 3.12.13 | 15/15 | 4/4 PASS |

The recorded `probe_results.json` SHA-256 digest is:

```text
0b65e8b7f649986d71c59e4272f98911679c17d890371d62a7acb205b7c72c01
```

The matching digest supports byte-level equivalence of the recorded JSON result artifact across the documented executions. It does not imply that every execution log, environmental condition, or implementation artifact is byte-identical.

## VTR evidence assessment

| Gate | Status | Qualification |
|---|---|---|
| GATE-LOCAL | ACHIEVED | Defined local tests and observations |
| GATE-CROSS-PLATFORM | ACHIEVED | Reproduction of defined synthetic results across Linux and FreeBSD |
| GATE-INDEPENDENT | PENDING | No independent third-party reproduction documented |
| GATE-REAL-WORLD | OUT_OF_SCOPE | No production deployment or validated cryptographic module evaluated |
| GATE-NORMATIVE-CHANGE | PENDING | No resulting NIST revision assessed |

**GLOBAL GATE-CONFIRMED: NOT ACHIEVED.**

The cross-platform result is a bounded experimental observation, not an independent assurance or certification claim.

## Scope and limitations

The experiment does not establish CAVP algorithm validation, CMVP/FIPS 140 module certification, cryptographic security, real-world interoperability, or deployment suitability.

It does not infer that support for the TLS 1.2 PRF constitutes support for SP 800-108 Double-Pipeline Iteration Mode.

It also does not determine what normative changes NIST should ultimately adopt. The transition matrix is an illustrative audit artifact, not an authoritative compatibility or compliance matrix.

## References

[NIST SP 800-108 Rev. 2 — Pre-Draft Consultation](https://csrc.nist.gov/pubs/sp/800/108/r2/iprd)

[NIST SP 800-108 Rev. 1 Update 1](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final)

[RFC 5246, Section 5 — TLS 1.2 PRF](https://www.rfc-editor.org/rfc/rfc5246#section-5)

[RFC 4231 — HMAC-SHA-256 Test Vectors](https://www.rfc-editor.org/rfc/rfc4231)

## License

MIT. See `LICENSE`.

## Author

Luis Castellanos  
Vector Telemetry Research (VTR)

[GitHub — LuisCastellanos-dev](https://github.com/LuisCastellanos-dev)
