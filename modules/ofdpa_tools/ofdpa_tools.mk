
###############################################################################
#
# Inclusive Makefile for the ofdpa_tools module.
#
# Autogenerated 2015-05-15 08:11:58.974589
#
###############################################################################
ofdpa_tools_BASEDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
include $(ofdpa_tools_BASEDIR)/module/make.mk
include $(ofdpa_tools_BASEDIR)/module/auto/make.mk
include $(ofdpa_tools_BASEDIR)/module/src/make.mk
include $(ofdpa_tools_BASEDIR)/utest/_make.mk

