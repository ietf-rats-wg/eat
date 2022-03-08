SHELL := /bin/bash

include tools.mk
include vars.mk

%.cbor: %.diag ; @$(diag2cbor) $< > $@

#DIAG_EXAMPLES := $(wildcard examples/*.diag)
DIAG_EXAMPLES := $(wildcard examples/simple.diag)
CBOR_EXAMPLES := $(DIAG_EXAMPLES:.diag=.cbor)

CLEANFILES += $(CBOR_EXAMPLES)

.PHONY: check-examples

all: $(CDDL_FOR_VALIDATION) check-examples

CDDL_FOR_VALIDATION := VALIDATION.CDDL

check-examples: $(CDDL_FOR_VALIDATION) $(CBOR_EXAMPLES)
	@for f in $(CBOR_EXAMPLES); do \
		echo ">> validating $$f" ; \
		$(cddl) $< validate $$f ; \
	done



$(CDDL_FOR_VALIDATION): $(VALIDATION_CDDL) external/cose-stub.cddl external/concise-swid-tag.cddl external/coswid-tag-stub.cddl external/uccs.cddl
	@for f in $^ ; do \
		( cat $$f ; echo ) ; \
	done > $@


.PHONY: clean
clean: ; $(RM) $(CLEANFILES)

GITHUB := https://raw.githubusercontent.com/
COSWID_REPO := sacmwg/draft-ietf-sacm-coswid/master
COSWID_REPO_URL := $(join $(GITHUB), $(COSWID_REPO))

concise-swid-tag.cddl: ; $(curl) -O $(COSWID_REPO_URL)/$@

CLEANFILES += concise-swid-tag.cddl

SUIT_REPO := suit-wg/manifest-spec/master
SUIT_REPO_URL := $(join $(GITHUB), $(SUIT_REPO))

draft-ietf-suit-manifest.cddl: ; $(curl) -O $(SUIT_REPO_URL)/$@

CLEANFILES += draft-ietf-suit-manifest.cddl
