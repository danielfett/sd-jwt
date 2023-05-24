from dataclasses import dataclass
from json import dumps
from typing import Optional


@dataclass
class SDJWTDisclosure:
    """This class represents a disclosure of a claim."""

    issuer: "SDJWTIssuer"
    key: Optional[str]  # only for object keys
    value: any

    def __post_init__(self):
        self._hash()

    def _hash(self):
        print(f"key is {self.key}, type is {type(self.key)}")
        print(f"value is {self.value}, type is {type(self.value)}")
        self._json = dumps([self.issuer._generate_salt(), self.key, self.value]).encode(
            "utf-8"
        )

        self._raw_b64 = self.issuer._base64url_encode(self._json)
        self._hash = self.issuer._b64hash(self._raw_b64.encode("ascii"))

    @property
    def hash(self):
        return self._hash

    @property
    def b64(self):
        return self._raw_b64

    @property
    def json(self):
        return self._json.decode("utf-8")
