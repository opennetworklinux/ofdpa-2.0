###############################################################################
#
# 
#
###############################################################################
THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
ofdpa_tools_INCLUDES := -I $(THIS_DIR)inc
ofdpa_tools_INTERNAL_INCLUDES := -I $(THIS_DIR)src
ofdpa_tools_DEPENDMODULE_ENTRIES := init:ofdpa_tools ucli:ofdpa_tools

