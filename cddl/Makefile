SHELL := /bin/bash

include tools.mk
include vars.mk


# --- Make CBOR examples from diag files
%.cbor: %.diag ; @$(diag2cbor) $< > $@


DIAG_EXAMPLES := $(wildcard examples/*.diag)
;DIAG_EXAMPLES := $(wildcard examples/simple.diag)
CBOR_EXAMPLES := $(DIAG_EXAMPLES:.diag=.cbor)

CLEANFILES += $(CBOR_EXAMPLES)

.PHONY: check-examples

all: check-examples


# ---- Make the CBOR validation CDDL
# Turn the CDDL fragments into one file 
# that is used for validation.
CBOR_VALIDATION_CDDL := CBOR_VALIDATION.CDDL
CLEANFILES += $(CBOR_VALIDATION_CDDL)

$(CBOR_VALIDATION_CDDL): $(CBOR_VALIDATION_CDDL_FRAGS) 
	@for f in $^ ; do \
		( cat $$f ; echo ) ; \
	done > $@


# ---- Actually run the validation
check-examples: $(CBOR_VALIDATION_CDDL) $(CBOR_EXAMPLES)
	@for f in $(CBOR_EXAMPLES); do \
		echo ">> validating $$f" ; \
		$(cddl) $< validate $$f ; \
	done


.PHONY: clean
clean: ; $(RM) $(CLEANFILES)


GITHUB := https://raw.githubusercontent.com/

# ---- Pull in the Coswid CDDL
COSWID_REPO := sacmwg/draft-ietf-sacm-coswid/master
COSWID_REPO_URL := $(join $(GITHUB), $(COSWID_REPO))
external/concise-swid-tag.cddl: ; (cd external ; $(curl) -O $(COSWID_REPO_URL)/concise-swid-tag.cddl )
CLEANFILES += external/concise-swid-tag.cddl


# ---- Pull in the SUIT Manifest CDDL
SUIT_REPO := suit-wg/manifest-spec/master
SUIT_REPO_URL := $(join $(GITHUB), $(SUIT_REPO))
external/draft-ietf-suit-manifest.cddl: ; (cd external; $(curl) -O $(SUIT_REPO_URL)/draft-ietf-suit-manifest.cddl )
CLEANFILES += external/draft-ietf-suit-manifest.cddl
