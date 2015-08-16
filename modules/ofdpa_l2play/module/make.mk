###############################################################################
#
# 
#
###############################################################################
THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
ofdpa_l2play_INCLUDES := -I $(THIS_DIR)inc
ofdpa_l2play_INTERNAL_INCLUDES := -I $(THIS_DIR)src
ofdpa_l2play_DEPENDMODULE_ENTRIES := init:ofdpa_l2play ucli:ofdpa_l2play

