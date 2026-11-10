# VTR — NIST SP 800-108 Q4
## Cross-Platform Reproduction Addendum

Date: 2026-11-10
Status: GATE-CROSS-PLATFORM — ACHIEVED
Scope: Synthetic HMAC-SHA-256 experiments only

### 1. Purpose

Record the cross-platform reproduction of the experimental
results documented in VTR-NIST-108-Q4-VALIDATION.md.

This addendum preserves the original report and does not
constitute NIST approval, FIPS validation, or a general
cryptographic security claim.

### 2. Reproduction environment

Operating system: FreeBSD 14.5-RELEASE amd64
Python: 3.12.13

Source SHA-256:

probe.py:
81fe4818cadce65cbb43b9945d6a933f3a7d1aea1d20a79b05bfbf3d06e55237

test_probe.py:
68f56252d5aeb6422385ea9bbe8fecc53943f24e989a11c79aaf544974b5def3

matrix_synthetic.json:
b36ecd1bc2483fc260b7b897088e9cd3c1463047a36d9bfd9cca33bac7afe0df

### 3. Experimental results

Unit tests: 15/15 PASS
Test exit code: 0
Probe exit code: 0
Synthetic matrix: PASS
Experimental observations: 4/4 PASS

Regenerated evidence SHA-256:
0b65e8b7f649986d71c59e4272f98911679c17d890371d62a7acb205b7c72c01

Binary comparison with the local evidence file:
cmp exit code: 0

The regenerated JSON matches the previously recorded
output byte for byte.

### 4. VTR evidence classification

HECHO:
The specified tests completed successfully on FreeBSD
14.5-RELEASE with Python 3.12.13.

HECHO:
The regenerated JSON matches the previously recorded
experimental evidence by SHA-256 and binary comparison.

HECHO:
The supplied laboratory record also documents successful
execution on Linux Mint with matching output.

INFERENCIA:
The tested algorithms exhibit deterministic behavior across
the recorded execution environments for the defined inputs.

LIMITATION:
These observations do not establish general implementation
equivalence, cryptographic security, FIPS validation, or
production suitability.

### 5. Gate status

GATE-LOCAL: ACHIEVED

GATE-CROSS-PLATFORM: ACHIEVED
Restricted to the documented synthetic experiments.

GATE-INDEPENDENT: PENDING
Independent third-party reproduction was not performed.

GATE-REAL-WORLD: OUT_OF_SCOPE
No production system or real CMVP certificate was evaluated.

GATE-NORMATIVE-CHANGE: PENDING
Requires an official normative publication and comparison.

GLOBAL GATE-CONFIRMED: NOT ACHIEVED

### 6. Reproducibility dimensions

Delta C: Observed across the recorded platforms and
Python versions, restricted to the tested inputs.

Delta A: NOT_EVIDENCED.
Independent reviewer verification remains pending.

Delta T: NOT_DETERMINED.
No normative revision comparison is claimed.

Delta K: NOT_DETERMINED.
No independent contribution-attribution review is claimed.

### 7. Preserved evidence

evidence/freebsd-14.5-python3.12/test_log.txt
evidence/freebsd-14.5-python3.12/probe_stdout.txt
evidence/freebsd-14.5-python3.12/probe_results.json
evidence/freebsd-14.5-python3.12/environment.txt

### 8. Conclusion

Cross-platform reproduction is supported for the defined
synthetic experiments.

No global confirmation, independent review, real-world
deployment decision, or normative approval is claimed.

The original validation report remains unchanged.
