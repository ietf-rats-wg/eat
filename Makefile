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
include cddl/vars.mk

COMMON_CDDL_FOR_DOCUMENT := $(addprefix cddl/,$(COMMON_CDDL_FOR_DOCUMENT))
CBOR_CDDL_FOR_DOCUMENT := $(addprefix cddl/,$(CBOR_CDDL_FOR_DOCUMENT))
JSON_CDDL_FOR_DOCUMENT := $(addprefix cddl/,$(JSON_CDDL_FOR_DOCUMENT))

draft-ietf-rats-eat.md: $(COMMON_CDDL_FOR_DOCUMENT) $(CBOR_CDDL_FOR_DOCUMENT) $(JSON_CDDL_FOR_DOCUMENT)


COMMON_CDDL_FRAGS := $(addprefix cddl/,$(COMMON_CDDL_FRAGS))
CBOR_CDDL_FRAGS := $(addprefix cddl/,$(CBOR_CDDL_FRAGS))
JSON_CDDL_FRAGS := $(addprefix cddl/,$(JSON_CDDL_FRAGS))

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


#.PHONY: examples
#examples: ; $(MAKE) -C cddl check-examples
