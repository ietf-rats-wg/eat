SHELL := /bin/bash

LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone -q --depth 10 $(CLONE_ARGS) \
	    -b master https://github.com/martinthomson/i-d-template $(LIBDIR)
endif



#include cddl/tools.mk
include cddl/CDDL-FRAGS.mk

# The list of files that have CDDL fragments from which the comments were removed
NC_COMMON_CDDL_FRAGS := $(addprefix nc-cddl/,$(DOCUMENT_COMMON_CDDL_FRAGS))
NC_CBOR_CDDL_FRAGS   := $(addprefix nc-cddl/,$(CBOR_SPECIFIC_CDDL_FRAGS))
NC_JSON_CDDL_FRAGS   := $(addprefix nc-cddl/,$(JSON_SPECIFIC_CDDL_FRAGS))

# Make targets that get put in the document
# (Also the individual COMMON_CDDL_FRAGS go into the document)
NC_COMMON_CDDL_FOR_DOCUMENT := nc-cddl/common.cddl
NC_CBOR_CDDL_FOR_DOCUMENT   := nc-cddl/cbor.cddl
NC_JSON_CDDL_FOR_DOCUMENT   := nc-cddl/json.cddl

CLEANFILES += $(NC_COMMON_CDDL_FRAGS)
CLEANFILES += $(NC_CBOR_CDDL_FRAGS)
CLEANFILES += $(NC_JSON_CDDL_FRAGS)

draft-ietf-rats-eat.md: $(NC_COMMON_CDDL_FRAGS) \
                        $(NC_COMMON_CDDL_FOR_DOCUMENT) \
                        $(NC_CBOR_CDDL_FOR_DOCUMENT) \
                        $(NC_JSON_CDDL_FOR_DOCUMENT)

# Rule to build CDDL files without CDDL comments
# This also turns the unassigned integer labels in to "TBD"
# Remove these substitutions when they are no longer TBD.
nc-cddl/%.cddl: cddl/%.cddl
	mkdir -p nc-cddl
	sed 's/;.*//' $< | \
           sed -e 's/267/TBD/;s/268/TBD/;s/269/TBD/;s/270/TBD/;s/271/TBD/' | \
           sed -e 's/272/TBD/;s/273/TBD/;s/274/TBD/;s/275/TBD/;s/276/TBD/;s/602/TBD/' | \
           cat -s > $@

$(NC_COMMON_CDDL_FOR_DOCUMENT): $(NC_COMMON_CDDL_FRAGS)
	@for f in $^ ; do \
	    ( cat $$f ; echo ) ; \
	done > $@


$(NC_CBOR_CDDL_FOR_DOCUMENT): $(NC_CBOR_CDDL_FRAGS)
	@for f in $^ ; do \
		( cat $$f ; echo ) ; \
	done > $@


$(NC_JSON_CDDL_FOR_DOCUMENT): $(NC_JSON_CDDL_FRAGS)
	@for f in $^ ; do \
	                ( cat $$f ; echo ) ; \
	done > $@


# TODO: re-enable examples checking as some point
#.PHONY: examples
#examples: ; $(MAKE) -C cddl check-examples

