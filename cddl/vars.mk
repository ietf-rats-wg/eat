
# Files with CDDL fragments that are common to CBOR and JSON
COMMON_CDDL_FRAGS := eat.cddl
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
COMMON_CDDL_FRAGS += swresults.cddl
COMMON_CDDL_FRAGS += submods.cddl
COMMON_CDDL_FRAGS += nested-token.cddl
COMMON_CDDL_FRAGS += deb.cddl
COMMON_CDDL_FRAGS += labels-assigned.cddl




# This is the CDDL that is used to validate CBOR examples.
# It varies from the main CDDL in the document in two ways.
# First, it assigns actual labels rather than TBD lablels.
# Second, it includes CDDL from standards that are referenced
# by EAT.
#
# When all the labels are officially assigned this can be
# simplied. It only needs to add the CDDL from other standards
# top CBOR_CDDL_FRAGS.
VALIDATION_CDDL += $(COMMON_CDDL_FRAGS)
VALIDATION_CDDL += labels-validate.cddl
VALIDATION_CDDL += external/cose-stub.cddl
VALIDATION_CDDL += external/oid-stub.cddl
VALIDATION_CDDL += external/uccs.cddl







CLEANFILES += $(COMMON_CDDL_FOR_DOCUMENT)
