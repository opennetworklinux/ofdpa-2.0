###############################################################################
#
# 
#
###############################################################################
THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
indigo_ofdpa_driver_INCLUDES := -I $(THIS_DIR)inc
indigo_ofdpa_driver_INTERNAL_INCLUDES := -I $(THIS_DIR)src
indigo_ofdpa_driver_DEPENDMODULE_ENTRIES := init:indigo_ofdpa_driver ucli:indigo_ofdpa_driver

