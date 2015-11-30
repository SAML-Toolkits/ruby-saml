# Culture Amp Ruby Saml

## Overview

Supports multiple X509 certificates in metadata.
Stores fingerprints and certs in an array.
Validate response against array of fingerprints/certs.

The primary differences between this and the official gem are

- IdpMetadataParser will parse ALL X509 certificates in the metadata
- it stores fingerprints in `idp_cert_fingerprints`
- it stores certificates in `idp_certs`
- `idp_certs` and `idp_cert_fingerprints` are arrays
- it calls `is_valids?` to validates against multiple fingerprints or certs
