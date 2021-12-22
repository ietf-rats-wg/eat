
# Files with CDDL fragments that are common to CBOR and JSON
COMMON_CDDL_FRAGS := claims-set.cddl
COMMON_CDDL_FRAGS += common-types.cddl
COMMON_CDDL_FRAGS += web-token-claims.cddl
COMMON_CDDL_FRAGS += nonce.cddl
COMMON_CDDL_FRAGS += ueid.cddl
COMMON_CDDL_FRAGS += sueids.cddl
COMMON_CDDL_FRAGS += oemid.cddl
COMMON_CDDL_FRAGS += hardware-version.cddl
COMMON_CDDL_FRAGS += hardware-class.cddl
COMMON_CDDL_FRAGS += hardware-class2.cddl
COMMON_CDDL_FRAGS += software-name.cddl
COMMON_CDDL_FRAGS += software-version.cddl
COMMON_CDDL_FRAGS += security-level.cddl
COMMON_CDDL_FRAGS += secure-boot.cddl
COMMON_CDDL_FRAGS += debug-status.cddl
COMMON_CDDL_FRAGS += location.cddl
COMMON_CDDL_FRAGS += uptime.cddl
COMMON_CDDL_FRAGS += boot-seed.cddl
COMMON_CDDL_FRAGS += intended-use.cddl
COMMON_CDDL_FRAGS += dloas.cddl
COMMON_CDDL_FRAGS += profile.cddl
COMMON_CDDL_FRAGS += manifests.cddl
COMMON_CDDL_FRAGS += swevidence.cddl
COMMON_CDDL_FRAGS += swresults.cddl
COMMON_CDDL_FRAGS += submods.cddl
COMMON_CDDL_FRAGS += deb.cddl


# CDDL files that are for CBOR only
CBOR_CDDL_FRAGS := cbor-token.cddl
CBOR_CDDL_FRAGS += cbor-nested-token.cddl
CBOR_CDDL_FRAGS += cwt-labels.cddl
CBOR_CDDL_FRAGS += eat-assigned-labels.cddl
CBOR_CDDL_FRAGS += eat-tbd-labels.cddl


# CDDL files that are for JSON only
JSON_CDDL_FRAGS := json-token.cddl
JSON_CDDL_FRAGS += json-nested-token.cddl
JSON_CDDL_FRAGS += jwt-labels.cddl
JSON_CDDL_FRAGS += eat-json-labels.cddl



# This is the CDDL that is used to validate CBOR examples.
# It varies from the main CDDL in the document in two ways.
# First, it assigns actual labels rather than TBD lablels.
# Second, it includes CDDL from standards that are referenced
# by EAT.
#
# When all the labels are officially assigned this can be
# simplied. It only needs to add the CDDL from other standards
# top CBOR_CDDL_FRAGS.
VALIDATION_CBOR_CDDL := cbor-token.cddl
VALIDATION_CBOR_CDDL += $(COMMON_CDDL_FRAGS)
VALIDATION_CBOR_CDDL += cbor-nested-token.cddl
VALIDATION_CBOR_CDDL += cwt-labels.cddl
VALIDATION_CBOR_CDDL += eat-assigned-labels.cddl
VALIDATION_CBOR_CDDL += eat-tbd-labels-validate.cddl
VALIDATION_CBOR_CDDL += cose-stub.cddl
VALIDATION_CBOR_CDDL += oid-stub.cddl


# Make targets that are used for validation
CDDL_FOR_CBOR_VALIDATION = cbor-for-validation.cddl
CDDL_FOR_JSON_VALIDATION = json-for-validation.cddl




CLEANFILES += $(COMMON_CDDL_FOR_DOCUMENT)
CLEANFILES += $(CBOR_CDDL_FOR_DOCUMENT)
CLEANFILES += $(JSON_CDDL_FOR_DOCUMENT)
CLEANFILES += $(CDDL_FOR_CBOR_VALIDATION)
CLEANFILES += $(CDDL_FOR_JSON_VALIDATION)
