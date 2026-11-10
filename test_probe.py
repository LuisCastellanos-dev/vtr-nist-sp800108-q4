#!/usr/bin/env python3
"""Reproducible positive and negative tests for illustrative VTR probe."""
import hashlib
import hmac
import json
from copy import deepcopy
from pathlib import Path
import unittest

from probe import (check_matrix, mac, probe_evidence, sp800108_ctr_hmac_sha256,
                   sp800108_dp_hmac_sha256, tls12_prf_sha256)

ROOT = Path(__file__).resolve().parent
ROWS = json.loads((ROOT / 'matrix_synthetic.json').read_text(encoding='utf-8'))['rows']
KEY = bytes.fromhex('00112233445566778899aabbccddeeff' * 2)


class TestVTRQ4(unittest.TestCase):
    def test_01_hmac_rfc4231_vector1(self):
        got = mac(bytes.fromhex('0b' * 20), b'Hi There').hex()
        expected = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
        self.assertEqual(got, expected)

    def test_02_repeatable_dp(self):
        a = sp800108_dp_hmac_sha256(KEY, b'LAB', b'A', 64)
        b = sp800108_dp_hmac_sha256(KEY, b'LAB', b'A', 64)
        self.assertEqual(a, b)

    def test_03_tls_vs_dp_distinct_on_fixture(self):
        tls = tls12_prf_sha256(KEY, b'LAB', b'A', 64)
        dp = sp800108_dp_hmac_sha256(KEY, b'LAB', b'A', 64)
        self.assertNotEqual(tls, dp)

    def test_04_dp_counter_variant_changes_output(self):
        a = sp800108_dp_hmac_sha256(KEY, b'LAB', b'A', 64, True)
        b = sp800108_dp_hmac_sha256(KEY, b'LAB', b'A', 64, False)
        self.assertNotEqual(a, b)

    def test_05_context_changes_dp(self):
        a = sp800108_dp_hmac_sha256(KEY, b'LAB', b'A', 64)
        b = sp800108_dp_hmac_sha256(KEY, b'LAB', b'B', 64)
        self.assertNotEqual(a, b)

    def test_06_ctr_vs_dp_distinct(self):
        a = sp800108_ctr_hmac_sha256(KEY, b'LAB', b'A', 64)
        b = sp800108_dp_hmac_sha256(KEY, b'LAB', b'A', 64)
        self.assertNotEqual(a, b)

    def test_07_matrix_synthetic_valid(self):
        self.assertEqual(check_matrix(ROWS), [])

    def test_08_reject_tls_only_implies_sp_dp(self):
        bad = deepcopy(ROWS)
        bad[0]['kdf_claim'] = 'EXPLICITLY_IDENTIFIED_IN_FIXTURE'
        self.assertTrue(check_matrix(bad))

    def test_09_reject_unsubstantiated_official_approval(self):
        bad = deepcopy(ROWS)
        bad[1]['normative_status'] = 'APPROVED'
        self.assertTrue(check_matrix(bad))

    def test_10_reject_fake_cmvp_certificate(self):
        bad = deepcopy(ROWS)
        bad[1]['cmvp_claim'] = 'VALIDATED'
        bad[1]['module_certificate'] = '12345'
        self.assertTrue(check_matrix(bad))

    def test_11_reject_premature_deployment_decision(self):
        bad = deepcopy(ROWS)
        bad[2]['deployment_decision'] = 'SAFE_TO_DEPLOY'
        self.assertTrue(check_matrix(bad))

    def test_12_reject_missing_implementation_evidence(self):
        bad = deepcopy(ROWS)
        bad[1]['implementation_evidence'] = 'NOT_EVIDENCED'
        self.assertTrue(check_matrix(bad))

    def test_13_reject_duplicate_ids(self):
        bad = deepcopy(ROWS)
        bad[2]['id'] = bad[1]['id']
        self.assertTrue(check_matrix(bad))

    def test_14_input_length_constraints(self):
        with self.assertRaises(ValueError):
            sp800108_dp_hmac_sha256(KEY, b'LAB', b'A', 0)
        with self.assertRaises(ValueError):
            tls12_prf_sha256(KEY, b'LAB', b'A', 4097)

    def test_15_probe_observations(self):
        self.assertTrue(all(probe_evidence()['observations'].values()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
