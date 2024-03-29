from .common import (
    SDJWTCommon,
    DEFAULT_SIGNING_ALG,
    DIGEST_ALG_KEY,
    SD_DIGESTS_KEY,
    SD_LIST_PREFIX,
)

from json import dumps, loads
from typing import Dict, List, Union, Callable

from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS


class SDJWTVerifier(SDJWTCommon):
    _input_disclosures: List
    _hash_to_decoded_disclosure: Dict
    _hash_to_disclosure: Dict

    def __init__(
        self,
        sd_jwt_presentation: str,
        cb_get_issuer_key: Callable[[str], str],
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
        serialization_format: str = "compact",
    ):
        super().__init__(serialization_format=serialization_format)

        self._parse_sd_jwt(sd_jwt_presentation)
        self._create_hash_mappings(self._input_disclosures)
        self._verify_sd_jwt(cb_get_issuer_key)

        # expected aud and nonce either need to be both set or both None
        if expected_aud or expected_nonce:
            if not (expected_aud and expected_nonce):
                raise ValueError(
                    "Either both expected_aud and expected_nonce must be provided or both must be None"
                )

            # Verify the SD-JWT-Release
            self._verify_key_binding_jwt(
                expected_aud,
                expected_nonce,
            )

    def get_verified_payload(self):
        return self._extract_sd_claims()

    def _verify_sd_jwt(
        self,
        cb_get_issuer_key,
        sign_alg: str = None,
    ):
        parsed_input_sd_jwt = JWS()
        parsed_input_sd_jwt.deserialize(self._unverified_input_sd_jwt)

        unverified_issuer = self._unverified_input_sd_jwt_payload.get("iss", None)
        issuer_public_key = cb_get_issuer_key(unverified_issuer)
        parsed_input_sd_jwt.verify(issuer_public_key, alg=sign_alg)

        self._sd_jwt_payload = loads(parsed_input_sd_jwt.payload.decode("utf-8"))
        # TODO: Check exp/nbf/iat

        self._holder_public_key_payload = self._sd_jwt_payload.get("cnf", None)

    def _verify_key_binding_jwt(
        self,
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
        sign_alg: Union[str, None] = None,
    ):
        _alg = sign_alg or DEFAULT_SIGNING_ALG
        parsed_input_key_binding_jwt = JWS()
        parsed_input_key_binding_jwt.deserialize(self._unverified_input_key_binding_jwt)

        if not self._holder_public_key_payload:
            raise ValueError("No holder public key in SD-JWT")

        holder_public_key_payload_jwk = self._holder_public_key_payload.get("jwk", None)
        if not holder_public_key_payload_jwk:
            raise ValueError(
                "The holder_public_key_payload is malformed. "
                "It doesn't contain the claim jwk: "
                f"{self._holder_public_key_payload}"
            )

        pubkey = JWK.from_json(dumps(holder_public_key_payload_jwk))

        parsed_input_key_binding_jwt.verify(pubkey, alg=_alg)

        key_binding_jwt_header = parsed_input_key_binding_jwt.jose_header

        if key_binding_jwt_header["typ"] != self.KB_JWT_TYP_HEADER:
            raise ValueError("Invalid header typ")

        key_binding_jwt_payload = loads(parsed_input_key_binding_jwt.payload)

        if key_binding_jwt_payload["aud"] != expected_aud:
            raise ValueError("Invalid audience")
        if key_binding_jwt_payload["nonce"] != expected_nonce:
            raise ValueError("Invalid nonce")

    def _extract_sd_claims(self):
        if DIGEST_ALG_KEY in self._sd_jwt_payload:
            if self._sd_jwt_payload[DIGEST_ALG_KEY] != self.HASH_ALG["name"]:
                # TODO: Support other hash algorithms
                raise ValueError("Invalid hash algorithm")

        self._duplicate_hash_check = []
        return self._unpack_disclosed_claims(self._sd_jwt_payload)

    def _unpack_disclosed_claims(self, sd_jwt_claims):
        # In a list, unpack each element individually
        if type(sd_jwt_claims) is list:
            output = []
            for element in sd_jwt_claims:
                if (
                    type(element) is dict
                    and len(element) == 1
                    and SD_LIST_PREFIX in element
                    and type(element[SD_LIST_PREFIX]) is str
                ):
                    digest_to_check = element[SD_LIST_PREFIX]
                    if digest_to_check in self._hash_to_decoded_disclosure:
                        _, value = self._hash_to_decoded_disclosure[digest_to_check]
                        output.append(self._unpack_disclosed_claims(value))
                else:
                    output.append(self._unpack_disclosed_claims(element))
            return output

        elif type(sd_jwt_claims) is dict:
            # First, try to figure out if there are any claims to be
            # disclosed in this dict. If so, replace them by their
            # disclosed values.

            pre_output = {
                k: self._unpack_disclosed_claims(v)
                for k, v in sd_jwt_claims.items()
                if k != SD_DIGESTS_KEY and k != DIGEST_ALG_KEY
            }

            for digest in sd_jwt_claims.get(SD_DIGESTS_KEY, []):
                if digest in self._duplicate_hash_check:
                    raise ValueError(f"Duplicate hash found in SD-JWT: {digest}")
                self._duplicate_hash_check.append(digest)

                if digest in self._hash_to_decoded_disclosure:
                    _, key, value = self._hash_to_decoded_disclosure[digest]
                    if key in pre_output:
                        raise ValueError(
                            f"Duplicate key found when unpacking disclosed claim: '{key}' in {pre_output}. This is not allowed."
                        )
                    unpacked_value = self._unpack_disclosed_claims(value)
                    pre_output[key] = unpacked_value

            # Now, go through the dict and unpack any nested dicts.

            return pre_output

        else:
            return sd_jwt_claims
