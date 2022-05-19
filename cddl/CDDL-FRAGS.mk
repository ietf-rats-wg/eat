# These variables are lists of CDDL fragments used for 1) inclusion in
# the document and 2) validation of examples.  There are variants
# becase cddl and the cddl tool aren't fully up to the task handling
# CBOR and JSON simultaneously.


# The big set of CDDL fragments common to validation and the document,
# and common to JSON and CBOR. This is original normative CDDL that is
# defined by EAT.

COMMON_CDDL_FRAGS += common-types.cddl
COMMON_CDDL_FRAGS += nonce.cddl
COMMON_CDDL_FRAGS += ueid.cddl
COMMON_CDDL_FRAGS += sueids.cddl
COMMON_CDDL_FRAGS += oemid.cddl
COMMON_CDDL_FRAGS += hardware-version.cddl
COMMON_CDDL_FRAGS += hardware-model.cddl
COMMON_CDDL_FRAGS += software-name.cddl
COMMON_CDDL_FRAGS += software-version.cddl
COMMON_CDDL_FRAGS += security-level.cddl
COMMON_CDDL_FRAGS += secure-boot.cddl
COMMON_CDDL_FRAGS += debug-status.cddl
COMMON_CDDL_FRAGS += location.cddl
COMMON_CDDL_FRAGS += uptime.cddl
COMMON_CDDL_FRAGS += boot-seed.cddl
COMMON_CDDL_FRAGS += odometer.cddl
COMMON_CDDL_FRAGS += intended-use.cddl
COMMON_CDDL_FRAGS += dloas.cddl
COMMON_CDDL_FRAGS += profile.cddl
COMMON_CDDL_FRAGS += manifests.cddl
COMMON_CDDL_FRAGS += swevidence.cddl
COMMON_CDDL_FRAGS += measurement-results.cddl
COMMON_CDDL_FRAGS += submods.cddl
COMMON_CDDL_FRAGS += detached-digest.cddl
COMMON_CDDL_FRAGS += deb.cddl
COMMON_CDDL_FRAGS += claim-labels.cddl


# The common CDDL section in the document.  The CDDL common to CBOR
# and JSON.  

DOCUMENT_COMMON_CDDL_FRAGS = $(COMMON_CDDL_FRAGS)


# CDDL that is common to CBOR and JSON, that is a refence or
# replication of something defined externally. It is not normative
# definitions.

COMMON_EXTERNAL_CDDL_FRAGS = external/claims-set.cddl


# This is normative CDDL defined by EAT that is CBOR-specific

CBOR_SPECIFIC_CDDL_FRAGS += eat-cbor.cddl
CBOR_SPECIFIC_CDDL_FRAGS += nested-token-cbor.cddl


# This is normative CDDL defined by EAT that is JSON-specific

JSON_SPECIFIC_CDDL_FRAGS += eat-json.cddl
JSON_SPECIFIC_CDDL_FRAGS += nested-token-json.cddl


# CDDL that is CBOR-specific that is a reference or replication of
# something defined externally.

CBOR_EXTERNAL_CDDL_FRAGS += external/oid-stub.cddl
CBOR_EXTERNAL_CDDL_FRAGS += external/cwt.cddl
CBOR_EXTERNAL_CDDL_FRAGS += external/concise-swid-tag.cddl
CBOR_EXTERNAL_CDDL_FRAGS += external/coswid-tag-stub.cddl
CBOR_EXTERNAL_CDDL_FRAGS += external/cose-stub.cddl
CBOR_EXTERNAL_CDDL_FRAGS += external/draft-ietf-suit-manifest.cddl
# TODO: remove this or such...
CBOR_EXTERNAL_CDDL_FRAGS += external/uccs.cddl



# CDDL that is JSON-specific that is a reference
# or replication of something defined externally.

JSON_EXTERNAL_CDDL_FRAGS += external/jwt.cddl
JSON_EXTERNAL_CDDL_FRAGS += external/coswid-version-for-json.cddl
JSON_EXTERNAL_CDDL_FRAGS += external/oid-stub.cddl


# The CDDL used for validating CBOR starting with a payload. Note The
# start of this CDDL is a Claims-Set.

CBOR_PAYLOAD_VALIDATION_CDDL_FRAGS += $(COMMON_EXTERNAL_CDDL_FRAGS)
CBOR_PAYLOAD_VALIDATION_CDDL_FRAGS += $(COMMON_CDDL_FRAGS)
CBOR_PAYLOAD_VALIDATION_CDDL_FRAGS += $(CBOR_SPECIFIC_CDDL_FRAGS)
CBOR_PAYLOAD_VALIDATION_CDDL_FRAGS += $(CBOR_EXTERNAL_CDDL_FRAGS)


# The CDDL used for validating CBOR a full CBOR Token. Note the start
# is an EAT-CBOR-Token. The only difference from the above is the
# order.

CBOR_TOKEN_VALIDATION_CDDL_FRAGS += $(CBOR_SPECIFIC_CDDL_FRAGS)
CBOR_TOKEN_VALIDATION_CDDL_FRAGS += $(COMMON_EXTERNAL_CDDL_FRAGS)
CBOR_TOKEN_VALIDATION_CDDL_FRAGS += $(COMMON_CDDL_FRAGS)
CBOR_TOKEN_VALIDATION_CDDL_FRAGS += $(CBOR_EXTERNAL_CDDL_FRAGS)


# CDDL for validating JSON payloads. The start of this is the
# CDDL Claims-Set.

JSON_PAYLOAD_VALIDATION_CDDL_FRAGS += $(COMMON_EXTERNAL_CDDL_FRAGS)
JSON_PAYLOAD_VALIDATION_CDDL_FRAGS += $(COMMON_CDDL_FRAGS)
JSON_PAYLOAD_VALIDATION_CDDL_FRAGS += $(JSON_SPECIFIC_CDDL_FRAGS)
JSON_PAYLOAD_VALIDATION_CDDL_FRAGS += $(JSON_EXTERNAL_CDDL_FRAGS)


JSON_TOKEN_VALIDATION_CDDL_FRAGS += $(JSON_SPECIFIC_CDDL_FRAGS)
JSON_TOKEN_VALIDATION_CDDL_FRAGS += $(COMMON_EXTERNAL_CDDL_FRAGS)
JSON_TOKEN_VALIDATION_CDDL_FRAGS += $(COMMON_CDDL_FRAGS)
JSON_TOKEN_VALIDATION_CDDL_FRAGS += $(JSON_EXTERNAL_CDDL_FRAGS)

