#
# Tools (need cddl and diag2cbor to work)
#
cddl ?= $(shell command -v cddl)
ifeq ($(strip $(cddl)),)
  $(error cddl tool not found. To install cddl, run: 'gem install cddl')
endif

diag2cbor ?= $(shell command -v diag2cbor.rb)
ifeq ($(strip $(diag2cbor)),)
  $(error diag2cbor tool not found. To install diag2cbor, run: 'gem install cbor-diag')
endif
