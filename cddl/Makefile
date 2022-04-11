SHELL := /bin/bash

include tools.mk
include vars.mk

# Rule to make CBOR examples from diag files
%.cbor: %.diag ; @$(diag2cbor) $< > $@

DIAG_EXAMPLES := $(wildcard examples/*.diag)
CBOR_EXAMPLES := $(DIAG_EXAMPLES:.diag=.cbor)

CLEANFILES += $(CBOR_EXAMPLES)

.PHONY: check-examples

all: $(CDDL_FOR_VALIDATION) check-examples

CDDL_FOR_VALIDATION := VALIDATION.CDDL
CLEANFILES += $(CDDL_FOR_VALIDATION)

check-examples: $(CDDL_FOR_VALIDATION) $(CBOR_EXAMPLES)
	@for f in $(CBOR_EXAMPLES); do \
		echo ">> validating $$f" ; \
		$(cddl) $< validate $$f ; \
	done



$(CDDL_FOR_VALIDATION): $(VALIDATION_CDDL) 
	@for f in $^ ; do \
		( cat $$f ; echo ) ; \
	done > $@


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
