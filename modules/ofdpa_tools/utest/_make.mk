###############################################################################
#
# ofdpa-tools Unit Test Makefile.
#
###############################################################################
UMODULE := ofdpa-tools
UMODULE_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/utest.mk
