SHELL := /bin/bash

include tools.mk

# ---- Get the big list of CDDL fragment files
include CDDL-FRAGS.mk


# --- Make CBOR examples from diag files
%.cbor: %.diag ; @$(diag2cbor) $< > $@


DIAG_PAYLOAD_EXAMPLES  := $(wildcard Example-Payloads/*.diag)
DIAG_TOKEN_EXAMPLES    := $(wildcard Example-Tokens/*.diag)
CBOR_PAYLOAD_EXAMPLES  := $(DIAG_PAYLOAD_EXAMPLES:.diag=.cbor)
CBOR_TOKEN_EXAMPLES    := $(DIAG_TOKEN_EXAMPLES:.diag=.cbor)

CLEANFILES += $(CBOR_PAYLOAD_EXAMPLES)



.PHONY: payload-examples token-examples

all: payload-examples token-examples


# ---- Make the CBOR validation CDDL
# Turn the CDDL fragments into single files that is used for
# validation.

CBOR_PAYLOAD_VALIDATION_CDDL := .CBOR_PAYLOAD_VALIDATION.CDDL
CBOR_TOKEN_VALIDATION_CDDL   := .CBOR_TOKEN_VALIDATION.CDDL
CLEANFILES                   += $(CBOR_TOKEN_VALIDATION_CDDL) $(CBOR_PAYLOAD_VALIDATION_CDDL)

$(CBOR_PAYLOAD_VALIDATION_CDDL): $(CBOR_PAYLOAD_VALIDATION_CDDL_FRAGS) 
	@for f in $^ ; do \
		( cat $$f ; echo ) ; \
	done > $@

$(CBOR_TOKEN_VALIDATION_CDDL): $(CBOR_TOKEN_VALIDATION_CDDL_FRAGS) 
	@for f in $^ ; do \
		( cat $$f ; echo ) ; \
	done > $@


# ---- Actually run the validation
payload-examples: $(CBOR_PAYLOAD_VALIDATION_CDDL) $(CBOR_PAYLOAD_EXAMPLES)
	@for f in $(CBOR_PAYLOAD_EXAMPLES); do \
		echo ">> validating $$f" ; \
		$(cddl) $< validate $$f ; \
	done

token-examples: $(CBOR_TOKEN_VALIDATION_CDDL) $(CBOR_TOKEN_EXAMPLES)
	@for f in $(CBOR_TOKEN_EXAMPLES); do \
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
