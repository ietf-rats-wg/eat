

# The big set of CDDL common to validation and the document
# and common to JSON and CBOR. This is normative CDDL
# that is defined in EAT
COMMON_CDDL_FRAGS += common-types.cddl
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
COMMON_CDDL_FRAGS += swresults.cddl
COMMON_CDDL_FRAGS += submods.cddl
COMMON_CDDL_FRAGS += detached-digest.cddl
COMMON_CDDL_FRAGS += deb.cddl
COMMON_CDDL_FRAGS += labels-assigned.cddl


# The common CDDL section in the document
# The CDDL common to CBOR and JSON
# (This will be the same as COMMON_CDDL_FRAGS when
# there are no more tbd labels)
DOCUMENT_COMMON_CDDL_FRAGS = $(COMMON_CDDL_FRAGS)
DOCUMENT_COMMON_CDDL_FRAGS += labels-tbd.cddl


# CDDL that is common to CBOR and JSON, that is a
# refence or replication of something defined 
# externally. It is not normative definitions.
COMMON_EXTERNAL_CDDL_FRAGS = external/claims-set.cddl


# Common to JSON and CBOR, used only for validation
VALIDATION_COMMON_CDDL_FRAGS = labels-validate.cddl


# This is normative EAT CDDL that is CBOR-specific
CBOR_SPECIFIC_CDDL_FRAGS += eat-cbor.cddl
CBOR_SPECIFIC_CDDL_FRAGS += nested-token-cbor.cddl
CBOR_SPECIFIC_CDDL_FRAGS += nonce.cddl


# This is normative EAT CDDL that is CBOR-specific
JSON_SPECIFIC_CDDL_FRAGS += eat-json.cddl
JSON_SPECIFIC_CDDL_FRAGS += nested-token-json.cddl


# CDDL that is CBOR-specific that is a reference
# or replication of something defined externally
CBOR_EXTERNAL_CDDL_FRAGS += external/oid-stub.cddl
CBOR_EXTERNAL_CDDL_FRAGS += external/cwt.cddl
CBOR_EXTERNAL_CDDL_FRAGS += external/concise-swid-tag.cddl
CBOR_EXTERNAL_CDDL_FRAGS += external/coswid-tag-stub.cddl
CBOR_EXTERNAL_CDDL_FRAGS += external/cose-stub.cddl



# CDDL that is JSON-specific that is a reference
# or replication of something defined externally
JSON_EXTERNAL_CDDL_FRAGS = external/jwt.cddl


# The CDDL used for validating CBOR. Note
# that this is just for validating payloads
# The start of this CDDL is a Claims-Set
CBOR_VALIDATION_CDDL_FRAGS += $(COMMON_EXTERNAL_CDDL_FRAGS)
CBOR_VALIDATION_CDDL_FRAGS += $(COMMON_CDDL_FRAGS)
CBOR_VALIDATION_CDDL_FRAGS += $(VALIDATION_COMMON_CDDL_FRAGS)
CBOR_VALIDATION_CDDL_FRAGS += $(CBOR_SPECIFIC_CDDL_FRAGS)
CBOR_VALIDATION_CDDL_FRAGS += $(CBOR_EXTERNAL_CDDL_FRAGS)


# TODO: fill this in
JSON_VALIDATION_CDDL_FRAGS += $(COMMON_EXTERNAL_CDDL_FRAGS)
