from .common import SDJWTCommon, DEFAULT_SIGNING_ALG, SD_DIGESTS_KEY
from json import dumps, loads
from time import time
from typing import Dict, List, Optional
from itertools import zip_longest

from jwcrypto.jws import JWS


class SDJWTHolder(SDJWTCommon):
    hs_disclosures: List
    holder_binding_jwt_payload: Dict
    holder_binding_jwt: JWS
    serialized_holder_binding_jwt: str = ""
    combined_presentation: str

    _ii_disclosures: List
    _hash_to_decoded_disclosure: Dict
    _hash_to_disclosure: Dict

    def __init__(self, combined_sd_jwt_iid: str):
        self._parse_combined_sd_jwt_iid(combined_sd_jwt_iid)
        self._create_hash_mappings(self._ii_disclosures)
        self._extract_payload_unverified()
        self._determine_sd_list_prefix(self.sd_jwt_payload)

    def _parse_combined_sd_jwt_iid(self, combined):
        self.serialized_sd_jwt, *self._ii_disclosures = self._split(combined)

    def _extract_payload_unverified(self):
        # TODO: This holder does not verify the SD-JWT yet - this
        # is not strictly needed, but it would be nice to have.

        # Extract only the body from SD-JWT without verifying the signature
        _, jwt_body, _ = self.serialized_sd_jwt.split(".")
        self.sd_jwt_payload = loads(self._base64url_decode(jwt_body))

    def create_presentation(
        self, claims_to_disclose, nonce=None, aud=None, holder_key=None, sign_alg=None
    ):
        # Select the disclosures
        self.hs_disclosures = []
        self._select_disclosures(self.sd_jwt_payload, claims_to_disclose)

        # Optional: Create a holder binding JWT
        if nonce and aud and holder_key:
            self._create_holder_binding_jwt(nonce, aud, holder_key, sign_alg)

        # Create the combined presentation
        # Note: If the holder binding JWT is not created, then the
        # last element is empty, matching the spec.
        self.combined_presentation = self._combine(
            self.serialized_sd_jwt,
            *self.hs_disclosures,
            self.serialized_holder_binding_jwt,
        )

    def _select_disclosures(self, sd_jwt_claims, claims_to_disclose):
        # Recursively process the claims in sd_jwt_claims. In each
        # object found therein, look at the SD_DIGESTS_KEY. If it
        # contains hash digests for claims that should be disclosed,
        # then add the corresponding disclosures to the claims_to_disclose.

        if type(sd_jwt_claims) is list:
            return self._select_disclosures_list(sd_jwt_claims, claims_to_disclose)
        elif type(sd_jwt_claims) is dict:
            return self._select_disclosures_dict(sd_jwt_claims, claims_to_disclose)
        else:
            pass

    def _select_disclosures_list(self, sd_jwt_claims, claims_to_disclose):
        if claims_to_disclose is None:
            return []
        if claims_to_disclose is True:
            claims_to_disclose = []
        if not type(claims_to_disclose) is list:
            raise ValueError(
                f"To disclose array elements, an array must be provided as disclosure information.\n"
                f"Found {claims_to_disclose} instead.\n"
                f"Check disclosure information for array: {sd_jwt_claims}"
            )

        for pos, (claims_to_disclose_element, element) in enumerate(
            zip_longest(claims_to_disclose, sd_jwt_claims, fillvalue=None)
        ):
            if type(element) is str and element.startswith(self._sd_list_prefix):
                digest_to_check = element[len(self._sd_list_prefix) :]
                if digest_to_check not in self._hash_to_decoded_disclosure:
                    # fake digest
                    continue

                # Determine type of disclosure
                decoded = self._hash_to_decoded_disclosure[digest_to_check]
                _, disclosure_key, disclosure_value = decoded

                # Disclose the claim only if in claims_to_disclose (assumed to be an array)
                # there is an element with the current index and it is not None or False
                if claims_to_disclose_element not in (
                    False,
                    None,
                ):
                    self.hs_disclosures.append(
                        self._hash_to_disclosure[digest_to_check]
                    )
                    if type(disclosure_value) is dict:
                        if claims_to_disclose_element is True:
                            # Tolerate a "True" for a disclosure of an object
                            claims_to_disclose_element = {}
                        if not type(claims_to_disclose_element) is dict:
                            raise ValueError(
                                f"To disclose object elements in arrays, provide an object (can be empty).\n"
                                f"Found {claims_to_disclose_element} instead.\n"
                                f"Problem at position {pos} of {claims_to_disclose}.\n"
                                f"Check disclosure information for object: {sd_jwt_claims}"
                            )
                        self._select_disclosures(
                            disclosure_value, claims_to_disclose_element
                        )
                    elif type(disclosure_value) is list:
                        if claims_to_disclose_element is True:
                            # Tolerate a "True" for a disclosure of an array
                            claims_to_disclose_element = []
                        if not type(claims_to_disclose_element) is list:
                            raise ValueError(
                                f"To disclose array elements nested in arrays, provide an array (can be empty).\n"
                                f"Found {claims_to_disclose_element} instead.\n"
                                f"Problem at position {pos} of {claims_to_disclose}.\n"
                                f"Check disclosure information for array: {sd_jwt_claims}"
                            )

                        self._select_disclosures(
                            disclosure_value, claims_to_disclose_element
                        )

            else:
                self._select_disclosures(element, claims_to_disclose_element)

    def _select_disclosures_dict(self, sd_jwt_claims, claims_to_disclose):
        if claims_to_disclose is None:
            return {}
        if claims_to_disclose is True:
            # Tolerate a "True" for a disclosure of an object
            claims_to_disclose = {}
        if not type(claims_to_disclose) is dict:
            raise ValueError(
                f"To disclose object elements, an object must be provided as disclosure information.\n"
                f"Found {claims_to_disclose} (type {type(claims_to_disclose)}) instead.\n"
                f"Check disclosure information for object: {sd_jwt_claims}"
            )
        for key, value in sd_jwt_claims.items():
            if key == SD_DIGESTS_KEY:
                for digest_to_check in value:
                    if digest_to_check not in self._hash_to_decoded_disclosure:
                        # fake digest
                        continue
                    decoded = self._hash_to_decoded_disclosure[digest_to_check]
                    _, key, value = decoded

                    try:
                        print(f"In _select_disclosures_dict: {key}, {value}, {claims_to_disclose}")
                        if key in claims_to_disclose and claims_to_disclose[key]:
                            print(f"Adding disclosure for {digest_to_check}")
                            self.hs_disclosures.append(
                                self._hash_to_disclosure[digest_to_check]
                            )
                        else:
                            print(f"Not adding disclosure for {digest_to_check}, {key} (type {type(key)}) not in {claims_to_disclose}")
                    except TypeError:
                        # claims_to_disclose is not a dict
                        raise TypeError(
                            f"claims_to_disclose does not contain a dict where a dict was expected (found {claims_to_disclose} instead)\n"
                            f"Check claims_to_disclose for key: {key}, value: {value}"
                        ) from None

                    self._select_disclosures(value, claims_to_disclose.get(key, None))
            else:
                self._select_disclosures(value, claims_to_disclose.get(key, None))

    def _create_holder_binding_jwt(
        self, nonce, aud, holder_key, sign_alg: Optional[str] = None
    ):
        _alg = sign_alg or DEFAULT_SIGNING_ALG

        self.holder_binding_jwt_payload = {
            "nonce": nonce,
            "aud": aud,
            "iat": int(time()),
        }

        # Sign the SD-JWT-Release using the holder's key
        self.holder_binding_jwt = JWS(payload=dumps(self.holder_binding_jwt_payload))

        _data = {"alg": _alg}
        if self.SD_JWT_R_HEADER:
            _data["typ"] = self.SD_JWT_R_HEADER

        self.holder_binding_jwt.add_signature(
            holder_key,
            alg=_alg,
            protected=dumps(_data),
        )
        self.serialized_holder_binding_jwt = self.holder_binding_jwt.serialize(
            compact=True
        )
