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

JSON_PAYLOAD_EXAMPLES  := $(wildcard Example-Payloads/*.json)
JSON_TOKEN_EXAMPLES    := $(wildcard Example-Tokens/*.json)

CLEANFILES += $(CBOR_PAYLOAD_EXAMPLES)



.PHONY: payload-examples token-examples json-payload-examples json-token-examples

all: payload-examples token-examples json-payload-examples json-token-examples


# ---- Make the CBOR validation CDDL
# Turn the CDDL fragments into single files that is used for
# validation.

CBOR_PAYLOAD_VALIDATION_CDDL := .CBOR_PAYLOAD_VALIDATION.CDDL
CBOR_TOKEN_VALIDATION_CDDL   := .CBOR_TOKEN_VALIDATION.CDDL
JSON_PAYLOAD_VALIDATION_CDDL := .JSON_PAYLOAD_VALIDATION.CDDL
JSON_TOKEN_VALIDATION_CDDL   := .JSON_TOKEN_VALIDATION.CDDL
CLEANFILES                   += $(CBOR_TOKEN_VALIDATION_CDDL) $(CBOR_PAYLOAD_VALIDATION_CDDL)
CLEANFILES                   += $(JSON_PAYLOAD_VALIDATION_CDDL)
CLEANFILES                   += $(JSON_TOKEN_VALIDATION_CDDL)

$(CBOR_PAYLOAD_VALIDATION_CDDL): $(CBOR_PAYLOAD_VALIDATION_CDDL_FRAGS)
	@for f in $^ ; do \
		( echo "; ==== $$f ====" ; cat $$f ; echo ) ; \
	done > $@

$(CBOR_TOKEN_VALIDATION_CDDL): $(CBOR_TOKEN_VALIDATION_CDDL_FRAGS)
	@for f in $^ ; do \
		( cat $$f ; echo ) ; \
	done > $@

# The sed script JSON-CDDL.sed removes some things that don't work
# in CDDL for JSON, ".cbor" and "~" for example
$(JSON_TOKEN_VALIDATION_CDDL): $(JSON_TOKEN_VALIDATION_CDDL_FRAGS)
	@for f in $^ ; do \
		( echo "; ==== $$f ====" ; sed -f JSON-CDDL.sed $$f ; echo ) ; \
	done > $@


# The sed script JSON-CDDL.sed removes some things that don't work
# in CDDL for JSON, ".cbor" and "~" for example
$(JSON_PAYLOAD_VALIDATION_CDDL): $(JSON_PAYLOAD_VALIDATION_CDDL_FRAGS)
	@for f in $^ ; do \
		( echo "; ==== $$f ====" ; sed -f JSON-CDDL.sed $$f ; echo ) ; \
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

json-payload-examples: $(JSON_PAYLOAD_VALIDATION_CDDL) $(JSON_PAYLOAD_EXAMPLES)
	@for f in $(JSON_PAYLOAD_EXAMPLES); do \
		echo ">> validating $$f" ; \
		$(cddl) $< validate $$f ; \
	done

json-token-examples: $(JSON_TOKEN_VALIDATION_CDDL) $(JSON_TOKEN_EXAMPLES)
	@for f in $(JSON_TOKEN_EXAMPLES); do \
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


