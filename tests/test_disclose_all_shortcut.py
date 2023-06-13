from sd_jwt import __version__
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.utils.demo_utils import get_jwk
from sd_jwt.verifier import SDJWTVerifier
from sd_jwt.utils.yaml_specification import remove_sdobj_wrappers


def test_e2e(testcase, settings):
    seed = settings["random_seed"]
    demo_keys = get_jwk(settings["key_settings"], True, seed)
    use_decoys = testcase.get("add_decoy_claims", False)

    # Issuer: Produce SD-JWT and issuance format for selected example

    user_claims = {"iss": settings["identifiers"]["issuer"]}
    user_claims.update(testcase["user_claims"])

    SDJWTIssuer.unsafe_randomness = True
    sdjwt_at_issuer = SDJWTIssuer(
        user_claims,
        demo_keys["issuer_key"],
        demo_keys["holder_key"] if testcase.get("key_binding", False) else None,
        add_decoy_claims=use_decoys,
    )

    output_issuance = sdjwt_at_issuer.combined_sd_jwt_iid

    # This test skips the holder's part and goes straight to the verifier.
    # To do so, we simply add a "~" to the issuance format, turning it into a presentation format.
    # We also disable key binding checks.

    output_holder = output_issuance + "~"

    # Verifier
    def cb_get_issuer_key(issuer):
        return demo_keys["issuer_public_key"]

    sdjwt_at_verifier = SDJWTVerifier(
        output_holder,
        cb_get_issuer_key,
        None,
        None,
    )
    verified = sdjwt_at_verifier.get_verified_payload()

    # We here expect that the output claims are the same as the input claims
    expected_claims = remove_sdobj_wrappers(testcase["user_claims"])
    expected_claims["iss"] = settings["identifiers"]["issuer"]
    expected_claims["_sd_alg"] = "sha-256"

    assert verified == expected_claims
