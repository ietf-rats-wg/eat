SHELL := /bin/bash

# Rule to build CDDL files without CDDL comments
nc-cddl/%.cddl: cddl/%.cddl
	grep -v '^;' $< | cat -s > $@

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
include cddl/vars.mk

# The list of files that have CDDL fragments from which the comments were removed
NC_COMMON_CDDL_FRAGS := $(addprefix nc-cddl/,$(COMMON_CDDL_FRAGS))
NC_CBOR_CDDL_FRAGS := $(addprefix nc-cddl/,$(CBOR_CDDL_FRAGS))
NC_JSON_CDDL_FRAGS := $(addprefix nc-cddl/,$(JSON_CDDL_FRAGS))

# Make targets that get put in the document
COMMON_CDDL_FOR_DOCUMENT := nc-cddl/common.cddl
CBOR_CDDL_FOR_DOCUMENT := nc-cddl/cbor.cddl
JSON_CDDL_FOR_DOCUMENT := nc-cddl/json.cddl

CLEANFILES += $(NC_COMMON_CDDL_FRAGS)
CLEANFILES += $(NC_CBOR_CDDL_FRAGS)
CLEANFILES += $(NC_JSON_CDDL_FRAGS)

draft-ietf-rats-eat.md: $(NC_COMMON_CDDL_FRAGS) $(COMMON_CDDL_FOR_DOCUMENT) $(CBOR_CDDL_FOR_DOCUMENT) $(JSON_CDDL_FOR_DOCUMENT)

$(COMMON_CDDL_FOR_DOCUMENT): $(NC_COMMON_CDDL_FRAGS)
	@for f in $^ ; do \
	    ( cat $$f ; echo ) ; \
	done > $@


$(CBOR_CDDL_FOR_DOCUMENT): $(NC_CBOR_CDDL_FRAGS)
	@for f in $^ ; do \
		( cat $$f ; echo ) ; \
	done > $@


$(JSON_CDDL_FOR_DOCUMENT): $(NC_JSON_CDDL_FRAGS)
	@for f in $^ ; do \
	                ( cat $$f ; echo ) ; \
	done > $@


#.PHONY: examples
#examples: ; $(MAKE) -C cddl check-examples


