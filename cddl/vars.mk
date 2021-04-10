CDDL_FRAGS := eat-main.cddl
CDDL_FRAGS += common-types.cddl
CDDL_FRAGS += cwt.cddl
CDDL_FRAGS += debug-status.cddl
CDDL_FRAGS += location.cddl
CDDL_FRAGS += nonce.cddl
CDDL_FRAGS += oemid.cddl
CDDL_FRAGS += version-scheme.cddl
CDDL_FRAGS += hardware-version.cddl
CDDL_FRAGS += origination.cddl
CDDL_FRAGS += secure-boot.cddl
CDDL_FRAGS += security-level.cddl
CDDL_FRAGS += submods.cddl
CDDL_FRAGS += ueid.cddl
CDDL_FRAGS += intended-use.cddl
CDDL_FRAGS += layered.cddl
CDDL_FRAGS += uptime.cddl
CDDL_FRAGS += eat-assigned-labels.cddl

CDDL_DOC_FRAGS := $(CDDL_FRAGS) eat-tbd-labels.cddl json.cddl

CDDL_VALIDATE_FRAGS := $(CDDL_FRAGS) eat-tbd-labels-validate.cddl

CDDL_FRAGS += profile.cddl
CDDL_FRAGS += boot-seed.cddl
CDDL_FRAGS += json.cddl

CDDL_FULL := eat-token.cddl

CDDL_VALIDATE := eat-for-validation.cddl

CLEANFILES += $(CDDL_FULL)
CLEANFILES += $(CDDL_VALIDATE)
