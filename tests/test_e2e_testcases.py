from sd_jwt import __version__
from sd_jwt.holder import SDJWTHolder
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.utils.demo_utils import get_jwk
from sd_jwt.verifier import SDJWTVerifier


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
        demo_keys["holder_key"]
        if testcase.get("holder_binding", False)
        else None,
        add_decoy_claims=use_decoys,
    )

    output_issuance = sdjwt_at_issuer.combined_sd_jwt_iid

    # Holder

    sdjwt_at_holder = SDJWTHolder(output_issuance)
    sdjwt_at_holder.create_presentation(
        testcase["holder_disclosed_claims"],
        settings["holder_binding_nonce"]
        if testcase.get("holder_binding", False)
        else None,
        settings["identifiers"]["verifier"]
        if testcase.get("holder_binding", False)
        else None,
        demo_keys["holder_key"]
        if testcase.get("holder_binding", False)
        else None,
    )

    output_holder = sdjwt_at_holder.combined_presentation

    # Verifier
    def cb_get_issuer_key(issuer):
        return demo_keys["issuer_public_key"]

    sdjwt_at_verifier = SDJWTVerifier(
        output_holder,
        cb_get_issuer_key,
        settings["identifiers"]["verifier"]
        if testcase.get("holder_binding", False)
        else None,
        settings["holder_binding_nonce"]
        if testcase.get("holder_binding", False)
        else None,
    )
    verified = sdjwt_at_verifier.get_verified_payload()

    expected_claims = testcase["expect_verified_user_claims"]
    expected_claims["iss"] = settings["identifiers"]["issuer"]
    expected_claims["_sd_alg"] = "sha-256"

    assert verified == expected_claims
