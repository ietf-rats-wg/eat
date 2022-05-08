SHELL := /bin/bash

include tools.mk
include vars.mk

%.cbor: %.diag ; @$(diag2cbor) $< > $@

DIAG_EXAMPLES := $(wildcard examples/*.diag)
CBOR_EXAMPLES := $(DIAG_EXAMPLES:.diag=.cbor)

CLEANFILES += $(CBOR_EXAMPLES)

.PHONY: check-examples

all: $(COMMON_CDDL_FOR_DOCUMENT) $(CBOR_CDDL_FOR_DOCUMENT) $(JSON_CDDL_FOR_DOCUMENT) $(CDDL_FOR_CBOR_VALIDATION) check-examples

check-examples: $(CDDL_FOR_CBOR_VALIDATION) $(CBOR_EXAMPLES)
	@for f in $(CBOR_EXAMPLES); do \
		echo ">> validating $$f" ; \
		$(cddl) $< validate $$f ; \
	done

$(COMMON_CDDL_FOR_DOCUMENT): $(COMMON_CDDL_FRAGS)
	@for f in $^ ; do \
		( cat $$f ; echo ) ; \
	done > $@


$(CBOR_CDDL_FOR_DOCUMENT): $(CBOR_CDDL_FRAGS)
	@for f in $^ ; do \
		( cat $$f ; echo ) ; \
	done > $@


$(JSON_CDDL_FOR_DOCUMENT): $(JSON_CDDL_FRAGS)
	@for f in $^ ; do \
		( cat $$f ; echo ) ; \
	done > $@


$(CDDL_FOR_CBOR_VALIDATION): $(VALIDATION_CBOR_CDDL) cose-stub.cddl concise-swid-tag.cddl coswid-tag-stub.cddl  draft-ietf-suit-manifest.cddl
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
