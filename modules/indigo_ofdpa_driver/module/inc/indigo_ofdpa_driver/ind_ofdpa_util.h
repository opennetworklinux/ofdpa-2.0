/*********************************************************************
*
* (C) Copyright Broadcom Corporation 2013-2014
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*
**********************************************************************
*
* @filename     ind_ofdpa_util.h 
*
* @purpose      This file contains utility functions for Indigo
*
* @component    OF-DPA
*
* @comments     none
*
* @create       11 Nov 2013
*
* @end
*
**********************************************************************/
#include <indigo/error.h>
#include <loci/of_match.h>
#include <loci/loci.h>
#include <ofdpa_api.h>
#include <linux/if_ether.h>

#define IND_OFDPA_IP_DSCP_MASK     0xfc
#define IND_OFDPA_IP_ECN_MASK      0x03 
#define IND_OFDPA_IPV6_FLABEL_MASK 0x000fffff 

#define IND_OFDPA_DEFAULT_SOURCEIP4MASK 0xFFFFFFFFu
#define IND_OFDPA_DEFAULT_DESTIP4MASK   0xFFFFFFFFu

#define IND_OFDPA_NANO_SEC 1000000000


typedef struct  indTableNameList
{
  OFDPA_FLOW_TABLE_ID_t type;
  char *name;
} indTableNameList_t;

typedef struct indPacketOutActions_s
{
  uint32_t outputPort;
  uint32_t pipeline;
}indPacketOutActions_t;


indigo_error_t indigoConvertOfdpaRv(OFDPA_ERROR_t result);


/* Short hand logging macros */
#define LOG_ERROR AIM_LOG_ERROR
#define LOG_WARN AIM_LOG_WARN

#ifdef ROBS_HACK
#define LOG_INFO AIM_LOG_INFO
#endif

#define LOG_VERBOSE AIM_LOG_VERBOSE
#define LOG_TRACE AIM_LOG_TRACE

typedef struct ind_ofdpa_group_bucket_s
{
  uint32_t        outputPort;
  uint32_t        referenceGroupId;
  uint32_t        popVlanTag;
  uint32_t        pushL2Hdr;
  uint32_t        pushVlan;
  uint16_t        newTpid;      
  uint32_t        pushMplsHdr;
  uint16_t        mplsEtherType;       
  uint32_t        pushCW;
  uint32_t        mplsCopyTTLOutwards;
  uint32_t        mplsCopyEXPOutwards;
  uint32_t        mplsEXPRemarkTableIndex;
  uint32_t        priorityRemarkTableIndex;
  uint32_t        dscpRemarkTableIndex;
  uint32_t        lmepId;

  /** data for Set-Field action */
  uint32_t        vlanId;
  uint32_t        vlanPcp;
  uint32_t        vlanCfi;
  uint32_t        dscp;
  of_mac_addr_t   srcMac;  
  of_mac_addr_t   dstMac;  
  uint32_t        mplsLabel;
  uint32_t        mplsBOS;
  uint32_t        mplsEXP;
  uint32_t        mplsTTL;
} ind_ofdpa_group_bucket_t;

typedef unsigned long long ind_ofdpa_fields_t;

//ind_ofdpa_field_t start
#define IND_OFDPA_VLANID                      (1 <<  0)
#define IND_OFDPA_SRCMAC                      (1 <<  1)
#define IND_OFDPA_DSTMAC                      (1 <<  2)
#define IND_OFDPA_PORT                        (1 <<  3)
#define IND_OFDPA_ETHER_TYPE                  (1 <<  4)
#define IND_OFDPA_IPV4_DST                    (1 <<  5)
#define IND_OFDPA_IPV4_SRC                    (1 <<  6)
#define IND_OFDPA_IPV6_DST                    (1 <<  7)
#define IND_OFDPA_IPV6_SRC                    (1 <<  8)
#define IND_OFDPA_TUNNEL_ID                   (1 <<  9)
#define IND_OFDPA_VLAN_PCP                    (1 << 10)
#define IND_OFDPA_IPV4_ARP_SPA                (1 << 11)
#define IND_OFDPA_IP_PROTO                    (1 << 12)
#define IND_OFDPA_IP_DSCP                     (1 << 13)
#define IND_OFDPA_IP_ECN                      (1 << 14)
#define IND_OFDPA_TCP_L4_SRC_PORT             (1 << 15)
#define IND_OFDPA_TCP_L4_DST_PORT             (1 << 16)
#define IND_OFDPA_UDP_L4_SRC_PORT             (1 << 17)
#define IND_OFDPA_UDP_L4_DST_PORT             (1 << 18)
#define IND_OFDPA_SCTP_L4_SRC_PORT            (1 << 19)
#define IND_OFDPA_SCTP_L4_DST_PORT            (1 << 20)
#define IND_OFDPA_ICMPV4_TYPE                 (1 << 21)
#define IND_OFDPA_ICMPV4_CODE                 (1 << 22)
#define IND_OFDPA_IPV6_FLOW_LABEL             (1 << 23)
#define IND_OFDPA_ICMPV6_TYPE                 (1 << 24)
#define IND_OFDPA_ICMPV6_CODE                 (1 << 25)
#define IND_OFDPA_MPLS_LABEL                  (1 << 26)
#define IND_OFDPA_MPLS_BOS                    (1 << 27)
#define IND_OFDPA_MPLS_TC                     (1 << 28)

#define IND_OFDPA_VRF                         ((unsigned long long) 1 << 31)
#define IND_OFDPA_TC                          ((unsigned long long) 1 << 32)
#define IND_OFDPA_COLOR                       ((unsigned long long) 1 << 33)
#define IND_OFDPA_VLAN_DEI                    ((unsigned long long) 1 << 34)
#define IND_OFDPA_QOS_INDEX                   ((unsigned long long) 1 << 35)
#define IND_OFDPA_LMEP_ID                     ((unsigned long long) 1 << 36)
#define IND_OFDPA_MPLS_TTL                    ((unsigned long long) 1 << 37)
#define IND_OFDPA_MPLS_L2_PORT                ((unsigned long long) 1 << 38)
#define IND_OFDPA_BFD_DISCRIMINATOR           ((unsigned long long) 1 << 39)
#define IND_OFDPA_OVID                        ((unsigned long long) 1 << 40)
#define IND_OFDPA_MPLS_DATA_FIRST_NIBBLE      ((unsigned long long) 1 << 41)
#define IND_OFDPA_MPLS_ACH_CHANNEL            ((unsigned long long) 1 << 42)
#define IND_OFDPA_MPLS_NEXT_LABEL_IS_GAL      ((unsigned long long) 1 << 43)
#define IND_OFDPA_OAM_Y1731_MDL               ((unsigned long long) 1 << 44)
#define IND_OFDPA_OAM_Y1731_OPCODE            ((unsigned long long) 1 << 45)
#define IND_OFDPA_COLOR_ACTIONS_INDEX         ((unsigned long long) 1 << 46)
#define IND_OFDPA_TXFCL                       ((unsigned long long) 1 << 47)
#define IND_OFDPA_RXFCL                       ((unsigned long long) 1 << 48)
#define IND_OFDPA_RX_TIMESTAMP                ((unsigned long long) 1 << 49)
#define IND_OFDPA_ACTSET_OUTPUT               ((unsigned long long) 1 << 50)
//ind_ofdpa_field_t end 

//ind_ofdpa_action_t start
#define IND_OFDPA_WATCH_PORT                  (1 <<  0)
#define IND_OFDPA_OUTPUT                      (1 <<  1)
#define IND_OFDPA_COPY_TTL_OUT                (1 <<  2)
#define IND_OFDPA_COPY_TTL_IN                 (1 <<  3)
#define IND_OFDPA_SET_MPLS_TTL                (1 <<  4)
#define IND_OFDPA_PUSH_VLAN                   (1 <<  5)
#define IND_OFDPA_POP_VLAN                    (1 <<  6)
#define IND_OFDPA_PUSH_MPLS                   (1 <<  7)
#define IND_OFDPA_POP_MPLS                    (1 <<  8)
#define IND_OFDPA_SET_QUEUE                   (1 <<  9)
#define IND_OFDPA_REFGROUP                    (1 << 10)
                                              
#define IND_OFDPA_PUSH_L2_HDR                 (1 << 11)
#define IND_OFDPA_POP_L2_HDR                  (1 << 12)
#define IND_OFDPA_PUSH_CW                     (1 << 13)
#define IND_OFDPA_POP_CW                      (1 << 14)
#define IND_OFDPA_COPY_MPLS_TC_OUT            (1 << 15)
#define IND_OFDPA_COPY_MPLS_TC_IN             (1 << 16)
#define IND_OFDPA_MPLS_TC_REMARK_TABLE_INDEX  (1 << 17)
#define IND_OFDPA_DSCP_REMARK_TABLE_INDEX     (1 << 18)
#define IND_OFDPA_PCP_REMARK_TABLE_INDEX      (1 << 19)
#define IND_OFDPA_OAM_LM_RX_COUNT             (1 << 20)
#define IND_OFDPA_OAM_LM_TX_COUNT             (1 << 21)
#define IND_OFDPA_OAM_SET_COUNTER_FIELDS      (1 << 22)
#define IND_OFDPA_DEC_TTL_MTU                 (1 << 23)
#define IND_OFDPA_CHECK_DROP_STATUS           (1 << 24)
//ind_ofdpa_action_t end

#define IND_OFDPA_L2INTF_BITMAP                   (IND_OFDPA_POP_VLAN | IND_OFDPA_OUTPUT | \
                                                   IND_OFDPA_PCP_REMARK_TABLE_INDEX | \
                                                   IND_OFDPA_DSCP_REMARK_TABLE_INDEX)
#define IND_OFDPA_L2INTF_SF_BITMAP                (IND_OFDPA_VLAN_PCP | IND_OFDPA_VLAN_DEI | \
                                                   IND_OFDPA_IP_DSCP)

#define IND_OFDPA_L2_UNFILTERED_INTF_BITMAP       (IND_OFDPA_OUTPUT | \
                                                   IND_OFDPA_PCP_REMARK_TABLE_INDEX | \
                                                   IND_OFDPA_DSCP_REMARK_TABLE_INDEX)
#define IND_OFDPA_L2_UNFILTERED_INTF_SF_BITMAP    (IND_OFDPA_VLAN_PCP | IND_OFDPA_VLAN_DEI | \
                                                   IND_OFDPA_IP_DSCP)

#define IND_OFDPA_L2REWRITE_BITMAP                (IND_OFDPA_REFGROUP)
#define IND_OFDPA_L2REWRITE_SF_BITMAP             (IND_OFDPA_VLANID | IND_OFDPA_SRCMAC | \
                                                   IND_OFDPA_DSTMAC)

#define IND_OFDPA_L3UNICAST_BITMAP                (IND_OFDPA_REFGROUP)
#define IND_OFDPA_L3UNICAST_SF_BITMAP             (IND_OFDPA_VLANID | IND_OFDPA_SRCMAC | \
                                                   IND_OFDPA_DSTMAC)

#define IND_OFDPA_L3INTERFACE_BITMAP              (IND_OFDPA_REFGROUP)
#define IND_OFDPA_L3INTERFACE_SF_BITMAP           (IND_OFDPA_VLANID | IND_OFDPA_SRCMAC)

#define IND_OFDPA_L2OVERLAY_BITMAP                (IND_OFDPA_OUTPUT)

#define IND_OFDPA_L2MULTICAST_BITMAP              (IND_OFDPA_REFGROUP)

#define IND_OFDPA_L2FLOOD_BITMAP                  (IND_OFDPA_REFGROUP)

#define IND_OFDPA_L3MULTICAST_BITMAP              (IND_OFDPA_REFGROUP)

#define IND_OFDPA_L3ECMP_BITMAP                   (IND_OFDPA_REFGROUP)

#define IND_OFDPA_MPLSINTERFACE_BITMAP            (IND_OFDPA_SRCMAC |IND_OFDPA_DSTMAC | \
                                                   IND_OFDPA_VLANID | IND_OFDPA_REFGROUP | \
                                                   IND_OFDPA_OAM_LM_TX_COUNT)

#define IND_OFDPA_MPLSLABEL_BITMAP                (IND_OFDPA_PUSH_L2_HDR |IND_OFDPA_PUSH_VLAN | \
                                                   IND_OFDPA_PUSH_MPLS | IND_OFDPA_PUSH_CW | \
                                                   IND_OFDPA_COPY_MPLS_TC_OUT | \
                                                   IND_OFDPA_MPLS_TC_REMARK_TABLE_INDEX | \
                                                   IND_OFDPA_SET_MPLS_TTL | IND_OFDPA_COPY_TTL_OUT | \
                                                   IND_OFDPA_PCP_REMARK_TABLE_INDEX | IND_OFDPA_REFGROUP | \
                                                   IND_OFDPA_OAM_LM_TX_COUNT)
#define IND_OFDPA_MPLSLABEL_SF_BITMAP             (IND_OFDPA_MPLS_LABEL | IND_OFDPA_MPLS_BOS | \
                                                   IND_OFDPA_MPLS_TC | IND_OFDPA_MPLS_TTL)

#define IND_OFDPA_MPLSL2REP_BITMAP                (IND_OFDPA_REFGROUP)
#define IND_OFDPA_MPLS_L2_SPLIT_HORIZON_BITMAP    (IND_OFDPA_REFGROUP)
#define IND_OFDPA_MPLSFF_BITMAP                   (IND_OFDPA_WATCH_PORT | IND_OFDPA_REFGROUP)
#define IND_OFDPA_MPLS_1_PLUS_1_PROT_BITMAP       (IND_OFDPA_REFGROUP)
#define IND_OFDPA_MPLSL2TAG_BITMAP                (IND_OFDPA_PUSH_VLAN | IND_OFDPA_POP_VLAN | \
                                                   IND_OFDPA_REFGROUP)
#define IND_OFDPA_MPLSL2TAG_SF_BITMAP             (IND_OFDPA_VLANID)

#define IND_OFDPA_ING_PORT_FLOW_MATCH_BITMAP      (IND_OFDPA_PORT | IND_OFDPA_ETHER_TYPE | \
                                                   IND_OFDPA_TUNNEL_ID)

#define IND_OFDPA_VLAN_FLOW_MATCH_BITMAP          (IND_OFDPA_PORT | IND_OFDPA_VLANID | \
                                                   IND_OFDPA_ETHER_TYPE | IND_OFDPA_DSTMAC)

#define IND_OFDPA_VLAN1_FLOW_MATCH_BITMAP         (IND_OFDPA_PORT | IND_OFDPA_VLANID | IND_OFDPA_OVID | \
                                                   IND_OFDPA_ETHER_TYPE | IND_OFDPA_DSTMAC)

#define IND_OFDPA_MP_FLOW_MATCH_BITMAP            (IND_OFDPA_LMEP_ID | IND_OFDPA_OAM_Y1731_OPCODE | \
                                                   IND_OFDPA_OAM_Y1731_MDL)

#define IND_OFDPA_MPLS_L2_PORT_FLOW_MATCH_BITMAP  (IND_OFDPA_MPLS_L2_PORT | IND_OFDPA_ETHER_TYPE | \
                                                   IND_OFDPA_TUNNEL_ID)

#define IND_OFDPA_TERM_MAC_FLOW_MATCH_BITMAP      (IND_OFDPA_PORT | IND_OFDPA_ETHER_TYPE | \
                                                   IND_OFDPA_DSTMAC | IND_OFDPA_VLANID)

#define IND_OFDPA_BRIDGING_FLOW_MATCH_BITMAP      (IND_OFDPA_VLANID | IND_OFDPA_TUNNEL_ID | \
                                                   IND_OFDPA_DSTMAC)

#define IND_OFDPA_UCAST_ROUTING_FLOW_MATCH_BITMAP (IND_OFDPA_ETHER_TYPE | IND_OFDPA_IPV4_DST | \
                                                   IND_OFDPA_IPV6_DST | IND_OFDPA_VRF)

#define IND_OFDPA_MCAST_ROUTING_FLOW_MATCH_BITMAP (IND_OFDPA_ETHER_TYPE | IND_OFDPA_VLANID | \
                                                   IND_OFDPA_IPV4_SRC | IND_OFDPA_IPV4_DST | \
                                                   IND_OFDPA_IPV6_SRC | IND_OFDPA_IPV6_DST | \
                                                   IND_OFDPA_VRF)

#define IND_OFDPA_MPLS_FLOW_MATCH_BITMAP          (IND_OFDPA_ETHER_TYPE | IND_OFDPA_MPLS_LABEL | \
                                                   IND_OFDPA_MPLS_BOS | IND_OFDPA_PORT | \
                                                   IND_OFDPA_MPLS_TTL | IND_OFDPA_MPLS_DATA_FIRST_NIBBLE | \
                                                   IND_OFDPA_MPLS_ACH_CHANNEL | IND_OFDPA_MPLS_NEXT_LABEL_IS_GAL | \
                                                   IND_OFDPA_IPV4_DST | IND_OFDPA_IPV6_DST | \
                                                   IND_OFDPA_IP_PROTO | IND_OFDPA_UDP_L4_SRC_PORT | \
                                                   IND_OFDPA_UDP_L4_DST_PORT)

#define IND_OFDPA_MPLS_MP_FLOW_MATCH_BITMAP       (IND_OFDPA_LMEP_ID | IND_OFDPA_OAM_Y1731_OPCODE)

#define IND_OFDPA_DSCP_TRUST_FLOW_MATCH_BITMAP    (IND_OFDPA_QOS_INDEX | IND_OFDPA_IP_DSCP | \
                                                   IND_OFDPA_MPLS_L2_PORT)

#define IND_OFDPA_PCP_TRUST_FLOW_MATCH_BITMAP     (IND_OFDPA_QOS_INDEX | IND_OFDPA_VLAN_PCP | \
                                                   IND_OFDPA_VLAN_DEI | IND_OFDPA_MPLS_L2_PORT)

#define IND_OFDPA_MPLS_QOS_FLOW_MATCH_BITMAP      (IND_OFDPA_QOS_INDEX | IND_OFDPA_MPLS_TC)

#define IND_OFDPA_ACL_POLICY_FLOW_MATCH_BITMAP    (IND_OFDPA_PORT | IND_OFDPA_ETHER_TYPE |       \
                                                   IND_OFDPA_SRCMAC | IND_OFDPA_DSTMAC |         \
                                                   IND_OFDPA_VLANID | IND_OFDPA_TUNNEL_ID |       \
                                                   IND_OFDPA_VLAN_PCP | IND_OFDPA_IPV4_SRC |     \
                                                   IND_OFDPA_IPV4_DST | IND_OFDPA_IPV6_SRC |     \
                                                   IND_OFDPA_IPV6_DST | IND_OFDPA_IPV4_ARP_SPA | \
                                                   IND_OFDPA_IP_PROTO | IND_OFDPA_IP_DSCP |         \
                                                   IND_OFDPA_IP_ECN | IND_OFDPA_TCP_L4_SRC_PORT |       \
                                                   IND_OFDPA_TCP_L4_DST_PORT | IND_OFDPA_UDP_L4_SRC_PORT | \
                                                   IND_OFDPA_UDP_L4_DST_PORT | IND_OFDPA_ICMPV4_TYPE | \
                                                   IND_OFDPA_ICMPV4_CODE | IND_OFDPA_IPV6_FLOW_LABEL | \
                                                   IND_OFDPA_SCTP_L4_SRC_PORT | IND_OFDPA_SCTP_L4_DST_PORT | \
                                                   IND_OFDPA_ICMPV6_CODE | IND_OFDPA_ICMPV6_TYPE | \
                                                   IND_OFDPA_VRF | IND_OFDPA_VLAN_DEI | \
                                                   IND_OFDPA_MPLS_L2_PORT)

#define IND_OFDPA_EGRESS_VLAN_FLOW_MATCH_BITMAP   (IND_OFDPA_ACTSET_OUTPUT | IND_OFDPA_VLANID | \
                                                   IND_OFDPA_ETHER_TYPE | IND_OFDPA_DSTMAC)

#define IND_OFDPA_EGRESS_VLAN1_FLOW_MATCH_BITMAP  (IND_OFDPA_ACTSET_OUTPUT | IND_OFDPA_VLANID | IND_OFDPA_OVID | \
                                                   IND_OFDPA_ETHER_TYPE | IND_OFDPA_DSTMAC)

#define IND_OFDPA_EGRESS_MP_FLOW_MATCH_BITMAP     (IND_OFDPA_LMEP_ID | IND_OFDPA_OAM_Y1731_OPCODE | \
                                                   IND_OFDPA_OAM_Y1731_MDL)


extern ind_ofdpa_fields_t ind_ofdpa_match_fields_bitmask;
indigo_error_t indigoConvertOfdpaRv(OFDPA_ERROR_t result);

void ind_ofdpa_port_event_receive(void);
void ind_ofdpa_flow_event_receive(void);
void ind_ofdpa_pkt_receive(void);

void ind_ofdpa_fwd_init(void);
void ind_ofdpa_group_init(void);
