# Culture Amp Ruby Saml

## Overview

Supports multiple X509 certificates in metadata.
Stores fingerprints and certs in an array.
Validate response against array of fingerprints/certs.

The primary differences between this and the official gem are

- `IdpMetadataParser` will parse ALL X509 certificates in the metadata
- it stores fingerprints in `idp_cert_fingerprint_multi`
- it stores certificates in `idp_cert_multi`
- `idp_cert_multi` and `idp_cert_fingerprint_multi` are arrays
- it calls `is_valid_multi_cert?` to validates against multiple fingerprints or certs
