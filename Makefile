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

CDDL_FULL := $(addprefix cddl/,$(CDDL_FULL))

draft-ietf-rats-eat.md: $(CDDL_FULL) 

CDDL_FRAGS := $(addprefix cddl/,$(CDDL_FRAGS))

$(CDDL_FULL): $(CDDL_FRAGS)
	@for f in $^ ; do \
		( cat $$f ; echo ) ; \
	done > $@

#.PHONY: examples
#examples: ; $(MAKE) -C cddl check-examples
