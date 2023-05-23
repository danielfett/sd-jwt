from .common import (
    SDJWTCommon,
    SDKey,
    DEFAULT_SIGNING_ALG,
    DIGEST_ALG_KEY,
    SD_DIGESTS_KEY,
)
import random
from json import dumps
from typing import Dict, Tuple, List

from jwcrypto.jws import JWS


class SDJWTIssuer(SDJWTCommon):
    DECOY_MIN_ELEMENTS = 2
    DECOY_MAX_ELEMENTS = 5

    sd_jwt_payload: Dict
    sd_jwt: JWS
    serialized_sd_jwt: str

    ii_disclosures: List
    combined_sd_jwt_iid: str

    _debug_ii_disclosures_contents: List

    decoy_digests: List

    def __init__(
        self,
        user_claims: Dict,
        issuer_key,
        holder_key=None,
        sign_alg=None,
        add_decoy_claims: bool = False,
    ):
        self._user_claims = user_claims
        self._issuer_key = issuer_key
        self._holder_key = holder_key
        self._sign_alg = sign_alg or DEFAULT_SIGNING_ALG
        self._add_decoy_claims = add_decoy_claims

        self.ii_disclosures = []
        self._debug_ii_disclosures_contents = []
        self.decoy_digests = []

        self._check_for_sd_claim(self._user_claims)
        self._assemble_sd_jwt_payload()
        self._create_signed_jwt()
        self._create_combined()

    def _assemble_sd_jwt_payload(self):
        # Create the JWS payload
        self.sd_jwt_payload = self._create_sd_claims(self._user_claims)
        self.sd_jwt_payload.update(
            {
                DIGEST_ALG_KEY: self.HASH_ALG["name"],
            }
        )
        if self._holder_key:
            self.sd_jwt_payload["cnf"] = {
                "jwk": self._holder_key.export_public(as_dict=True)
            }

    def _hash_claim(self, key, value) -> Tuple[str, str]:
        json = dumps([self._generate_salt(), key, value]).encode("utf-8")
        self._debug_ii_disclosures_contents.append(json.decode("utf-8"))

        raw_b64 = self._base64url_encode(json)
        hash = self._b64hash(raw_b64.encode("ascii"))

        return (hash, raw_b64)

    def _create_sd_claim_key_value(self, key, value: any) -> str:
        hash, raw_b64 = self._hash_claim(key, value)
        self.ii_disclosures.append(raw_b64)
        return hash

    def _create_sd_claim_list_entry(self, list_name, position, value: any) -> str:
        hash, raw_b64 = self._hash_claim([list_name, position], value)
        self.ii_disclosures.append(raw_b64)
        return hash

    def _create_decoy_claim_entry(self) -> str:
        digest = self._b64hash(self._generate_salt().encode("ascii"))
        self.decoy_digests.append(digest)
        return digest

    def _create_sd_claims(self, user_claims, key_name=""):
        # This function can be called recursively.
        #
        # If the user claims are a list, apply this function
        # to each item in the list. 
        if type(user_claims) is list:
            return self._create_sd_claims_list(user_claims, key_name)

        # If the user claims are a dictionary, apply this function
        # to each key/value pair in the dictionary. 
        elif type(user_claims) is dict:
            return self._create_sd_claims_object(user_claims)

        # For other types, assume that the value can be disclosed.
        else:
            return user_claims
        
    def _create_sd_claims_list(self, user_claims: List, key_name: str):
        # Walk through all elements in the list.
        # If an element is marked as SD, then create a proper disclosure for it and replace it with a null value.
        # Otherwise, just return the element.
        #
        # Also keep track of the last non-sd element in the array. Remove all
        # elements from it until the last non-sd element is reached. Then
        # return the array.

        last_non_sd_element = None
        output_user_claims = []
        for claim in user_claims:
            if isinstance(claim, SDKey):
                # Assemble all hash digests in the disclosures list.
                output_user_claims.append(
                    self._create_sd_claim_list_entry(key_name, len(output_user_claims), claim)
                )


        #return [self._create_sd_claims(claim) for claim in user_claims]

    def _create_sd_claims_object(self, user_claims: Dict):
        sd_claims = {SD_DIGESTS_KEY: []}
        for key, value in user_claims.items():
            subtree_from_here = self._create_sd_claims(value)
            if isinstance(key, SDKey):
                # Assemble all hash digests in the disclosures list.
                sd_claims[SD_DIGESTS_KEY].append(
                    self._create_sd_claim_key_value(key, subtree_from_here)
                )
            else:
                sd_claims[key] = subtree_from_here

        # Add decoy claims if requested
        if self._add_decoy_claims:
            for _ in range(
                random.randint(self.DECOY_MIN_ELEMENTS, self.DECOY_MAX_ELEMENTS)
            ):
                sd_claims[SD_DIGESTS_KEY].append(self._create_decoy_claim_entry())

        # Delete the SD_DIGESTS_KEY if it is empty
        if len(sd_claims[SD_DIGESTS_KEY]) == 0:
            del sd_claims[SD_DIGESTS_KEY]
        else:
            # Sort the hash digests otherwise
            sd_claims[SD_DIGESTS_KEY].sort()

        return sd_claims


    def _create_signed_jwt(self):
        """
        Create the SD-JWT
        """

        # Sign the SD-JWT using the issuer's key
        self.sd_jwt = JWS(payload=dumps(self.sd_jwt_payload))
        _headers = {"alg": self._sign_alg}
        if self.SD_JWT_HEADER:
            _headers["typ"] = self.SD_JWT_HEADER
        self.sd_jwt.add_signature(
            self._issuer_key,
            alg=self._sign_alg,
            protected=dumps(_headers),
        )
        self.serialized_sd_jwt = self.sd_jwt.serialize(compact=True)

    def _create_combined(self):
        self.combined_sd_jwt_iid = self._combine(
            self.serialized_sd_jwt, *self.ii_disclosures
        )
