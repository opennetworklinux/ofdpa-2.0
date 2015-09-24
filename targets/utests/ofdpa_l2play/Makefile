###############################################################################
#
# 
#
###############################################################################

include ../../../init.mk
MODULE := ofdpa_l2play_utest
TEST_MODULE := ofdpa_l2play
DEPENDMODULES := AIM
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MODULES_INIT=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MAIN=1
include $(BUILDER)/build-unit-test.mk
