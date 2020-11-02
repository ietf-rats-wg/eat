include tools.mk
include vars.mk

%.cbor: %.diag ; @$(diag2cbor) $< > $@

DIAG_EXAMPLES := $(wildcard examples/*.diag)
CBOR_EXAMPLES := $(DIAG_EXAMPLES:.diag=.cbor)

CLEANFILES += $(CBOR_EXAMPLES)

.PHONY: check-examples
check-examples: $(CDDL_FULL) $(CBOR_EXAMPLES)
	@for f in $(CBOR_EXAMPLES); do \
		echo ">> validating $$f" ; \
		$(cddl) $< validate $$f ; \
	done

$(CDDL_FULL): $(CDDL_FRAGS)
	@for f in $^ ; do \
		( cat $$f ; echo ) ; \
	done > $@

.PHONY: clean
clean: ; $(RM) $(CLEANFILES)
