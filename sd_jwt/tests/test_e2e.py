import unittest
from jwcrypto.jwk import JWK
from jwcrypto.common import json_decode
from sd_jwt import SDJWTIssuer, SDJWTHolder, SDJWTVerifier

class TestSDJWTIssuer(unittest.TestCase):
    def setUp(self):
        self.issuer_key = JWK.generate(kty="oct", size=256)
        self.holder_key = JWK.generate(kty="oct", size=256)

        self.user_claims = {
            "sub": "alice",
            "name": "Alice",
            "email": "alice@example.com",
            "birthdate": "1990-01-01",
            "phone_number": "+1 555-555-1234",
            "address": {
                "street_address": "123 Main St.",
                "city": "Anytown",
                "state": "CA",
                "zip": "12345",
            },
            "degree": {
                "title": "Bachelor of Science",
                "major": "Computer Science",
                "institution": "University of Anytown",
                "year": 2010,
            },
        }

        self.sdjwt_issuer = SDJWTIssuer(
            self.user_claims,
            issuer_key=self.issuer_key,
            holder_key=self.holder_key,
            add_decoy_claims=True,
        )

    def test_create_sd_claims(self):
        sd_claims = self.sdjwt_issuer._create_sd_claims(self.user_claims)
        verifier = SDJWTVerifier(
            self.sdjwt_issuer.serialized_sd_jwt,
            issuer_key=self.issuer_key,
            holder_key=self.holder_key,
        )

        self.assertTrue(verifier.verify())

        payload = json_decode(verifier.payload)
        self.assertDictEqual(payload, sd_claims)

    def test_sd_jwt_contains_digest_algorithm(self):
        verifier = SDJWTVerifier(
            self.sdjwt_issuer.serialized_sd_jwt,
            issuer_key=self.issuer_key,
            holder_key=self.holder_key,
        )

        self.assertTrue(verifier.verify())

        header = json_decode(verifier.signature.protected)
        self.assertEqual(header["alg"], "HS256")
        self.assertEqual(header["cty"], "application/sd+jwt")

        payload = json_decode(verifier.payload)
        self.assertIn("digest_algorithm", payload)

    def test_sd_jwt_contains_claim_value_digests(self):
        verifier = SDJWTVerifier(
            self.sdjwt_issuer.serialized_sd_jwt,
            issuer_key=self.issuer_key,
            holder_key=self.holder_key,
        )

        self.assertTrue(verifier.verify())

        payload = json_decode(verifier.payload)
        self.assertIn("digests", payload)

        digests = payload["digests"]
        for claim, value in self.user_claims.items():
            digest = verifier.hash_claim(claim, value)
            self.assertIn(digest, digests)

    def test_sd_jwt_contains_decoy_claims(self):
        verifier = SDJWTVerifier(
            self.sdjwt_issuer.serialized_sd_jwt,
            issuer_key=self.issuer_key,
            holder_key=self.holder_key,
        )

        self.assertTrue(verifier.verify())

        payload = json_decode(verifier.payload)
        self.assertIn("digests", payload)

        digests = payload["digests"]
        num_decoys = self.sdjwt_issuer.DECOY_MIN_ELEMENTS
        for _ in range(num_decoys):
            decoy_digest = self.sdjwt_issuer._create_decoy_claim_entry()
            self.assertIn(decoy_digest, digests)
