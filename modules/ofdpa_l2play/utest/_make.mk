###############################################################################
#
# ofdpa_l2play Unit Test Makefile.
#
###############################################################################
UMODULE := ofdpa_l2play
UMODULE_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/utest.mk
