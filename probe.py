#!/usr/bin/env python3
"""VTR SP800-108 Q4 illustrative lab -- synthetic data only, not CAVP/CMVP."""
import hashlib
import hmac
import json
from pathlib import Path


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def tls12_prf_sha256(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """RFC 5246 section 5: P_SHA256(secret, label || seed)."""
    if not 1 <= length <= 4096:
        raise ValueError('lab length must be in 1..4096')
    data = label + seed
    a = data
    result = b''
    while len(result) < length:
        a = mac(secret, a)
        result += mac(secret, a + data)
    return result[:length]


def sp800108_dp_hmac_sha256(key: bytes, label: bytes, context: bytes,
                             length: int, counter: bool = True) -> bytes:
    """SP 800-108r1-upd1 4.3, default fixed-input encoding, byte-aligned L, r=32."""
    if not 1 <= length <= 4096:
        raise ValueError('lab length must be in 1..4096')
    l_bits = (length * 8).to_bytes(4, 'big')
    fixed = label + b'\x00' + context + l_bits
    a = fixed
    result = b''
    i = 0
    while len(result) < length:
        i += 1
        a = mac(key, a)
        ctr = i.to_bytes(4, 'big') if counter else b''
        result += mac(key, a + ctr + fixed)
    return result[:length]


def sp800108_ctr_hmac_sha256(key: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """SP 800-108r1-upd1 section 4.1, counter r=32, byte-aligned L."""
    if not 1 <= length <= 4096:
        raise ValueError('lab length must be in 1..4096')
    fixed = label + b'\x00' + context + (length * 8).to_bytes(4, 'big')
    result = b''
    i = 0
    while len(result) < length:
        i += 1
        result += mac(key, i.to_bytes(4, 'big') + fixed)
    return result[:length]


ALLOWED_STATES = {'NOT_EVIDENCED', 'EXPLICITLY_IDENTIFIED_IN_FIXTURE'}


def check_matrix(rows: list[dict]) -> list[str]:
    """Fail closed: synthetic evidence and normative status must not be conflated."""
    issues = []
    expected = {'id', 'protocol', 'kdf_claim', 'implementation_evidence',
                'normative_status', 'normative_source', 'cmvp_claim',
                'module_certificate', 'operational_environment', 'deployment_decision',
                'decision_source', 'action', 'vtr_state'}
    valid_normative = {'NOT_DETERMINED', 'HYPOTHETICAL_ONLY'}
    for row in rows:
        rid = row.get('id', '<missing-id>')
        missing = expected - set(row)
        if missing:
            issues.append(f'{rid}: missing fields {sorted(missing)}')
            continue
        if row['vtr_state'] not in {'HECHO', 'INFERENCIA', 'PROYECCION'}:
            issues.append(f'{rid}: invalid VTR evidence state')
        if row['kdf_claim'] not in ALLOWED_STATES:
            issues.append(f'{rid}: unsupported KDF claim')
        if row['kdf_claim'] == 'EXPLICITLY_IDENTIFIED_IN_FIXTURE' and row['implementation_evidence'] == 'NOT_EVIDENCED':
            issues.append(f'{rid}: asserted KDF lacks implementation evidence')
        if row['normative_status'] not in valid_normative:
            issues.append(f'{rid}: cannot assert official approval/deprecation from synthetic fixture')
        if row['normative_status'] != 'NOT_DETERMINED' and row['normative_source'] == 'NOT_EVIDENCED':
            issues.append(f'{rid}: hypothetical status lacks documented fixture basis')
        if row['cmvp_claim'] != 'NOT_EVIDENCED':
            issues.append(f'{rid}: CMVP validation cannot be asserted from fixture')
        if row['module_certificate'] != 'NOT_EVIDENCED':
            issues.append(f'{rid}: synthetic certificate cannot establish CMVP validation')
        if row['protocol'] == 'TLS1.2' and row['kdf_claim'] == 'EXPLICITLY_IDENTIFIED_IN_FIXTURE' and row['implementation_evidence'] == 'RFC5246_SEC5_ONLY':
            issues.append(f'{rid}: TLS1.2 support alone cannot establish SP800-108 DP')
        if row['deployment_decision'] != 'PENDING_OFFICIAL_APPLICABILITY_REVIEW':
            issues.append(f'{rid}: deployment decision requires official applicability review')
    ids = [row.get('id', '<missing-id>') for row in rows]
    if len(ids) != len(set(ids)):
        issues.append('duplicate row id')
    return issues


def probe_evidence() -> dict:
    key = bytes.fromhex('00112233445566778899aabbccddeeff' * 2)  # synthetic nonsecret
    label = b'VTR-LAB'
    context = b'asset-A'
    length = 64
    tls = tls12_prf_sha256(key, label, context, length)
    dp = sp800108_dp_hmac_sha256(key, label, context, length, True)
    dp_nocounter = sp800108_dp_hmac_sha256(key, label, context, length, False)
    changed = sp800108_dp_hmac_sha256(key, label, b'asset-B', length, True)
    counter = sp800108_ctr_hmac_sha256(key, label, context, length)
    return {
        'scope': 'synthetic, byte-aligned, HMAC-SHA256; algorithm demonstration, not NIST validation',
        'key_type': 'public fixed test input, not production secret',
        'inputs': {'label': label.decode(), 'context': context.decode(), 'length_bytes': length,
                   'counter_bits': 32, 'key_sha256': hashlib.sha256(key).hexdigest()},
        'outputs': {'tls12_prf_sha256': tls.hex(), 'sp800108_dp_hmac_ctr32': dp.hex(),
                    'sp800108_dp_hmac_no_counter': dp_nocounter.hex(),
                    'sp800108_dp_hmac_changed_context': changed.hex(),
                    'sp800108_counter_hmac': counter.hex()},
        'observations': {
            'dp_differs_from_tls_prf_on_defined_inputs': dp != tls,
            'dp_counter_option_changes_bytes': dp != dp_nocounter,
            'context_change_changes_dp_output': dp != changed,
            'ctr_differs_from_dp_on_defined_inputs': counter != dp,
        },
        'limits': ['distinct outputs do not establish protocol dependency or independence',
                   'no cryptographic security claim, formal proof, production inference, or FIPS validation']
    }


if __name__ == '__main__':
    root = Path(__file__).resolve().parent
    matrix = json.loads((root / 'matrix_synthetic.json').read_text(encoding='utf-8'))['rows']
    issues = check_matrix(matrix)
    report = probe_evidence()
    report['matrix_validation'] = {'rows_checked': len(matrix), 'issues': issues,
                                   'pass': len(issues) == 0}
    report['script_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    text = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + '\n'
    (root / 'evidence' / 'probe_results.json').write_text(text, encoding='utf-8')
    print('EVIDENCE_WRITE:', root / 'evidence' / 'probe_results.json')
    print('MATRIX:', 'PASS' if not issues else 'FAIL')
    for label, passed in report['observations'].items():
        print(label + ':', 'PASS' if passed else 'FAIL')
    if issues or not all(report['observations'].values()):
        raise SystemExit(1)
