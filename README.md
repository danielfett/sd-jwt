**Note: This is work in progress to transfer the SD-JWT implementation from https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/ into this repository. Until this is done, please refer to the original repository.**

# SD-JWT Reference Implementation

This is a reference implementation of the [IETF SD-JWT specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/). It is written in Python.

This implementation is used to generate the examples in the specification, but can also be used as a library in other projects.

## generate.py

The script `generate.py` can be used for generating test cases (for consumption by other SD-JWT implementations) and for generating the examples in the SD-JWT specification and other documents.

For both use cases, the script expects a JSON file with settings (`settings.yml`). Examples for these files can be found in the `test_cases` and `examples` directories.

Furthermore, the script expects, in its working directory, one subdirectory for each test case or example. In each such directory, there must be a file `specification.yml` with the test case or example specifications. Examples for these files can be found in the subdirectories of the `test_cases` and `examples` directories, respectively.

The script outputs the following files in each test case or example directory:

`combined_issuance.txt`: The issuance format of the SD-JWT.

`combined_presentation.txt`: The presentation format of the SD-JWT.

`disclosures.md`: The disclosures, formatted as markdown (only in 'example' mode).

`user_claims.json`: The user claims.

`sd_jwt_payload.json`: The payload of the SD-JWT.

`sd_jwt_serialized.txt`: The serialized SD-JWT.

`hb_jwt_payload.json`: The payload of the holder binding JWT.

`hb_jwt_serialized.txt`: The serialized holder binding JWT.

`verified_contents.json`: The verified contents of the SD-JWT.

