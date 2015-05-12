###############################################################################
#
# indigo_ofdpa_driver Unit Test Makefile.
#
###############################################################################
UMODULE := indigo_ofdpa_driver
UMODULE_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/utest.mk
