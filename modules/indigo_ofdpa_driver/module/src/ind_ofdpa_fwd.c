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
* @filename   ind_ofdpa_fwd.c
*
* @purpose    OF-DPA Driver for Indigo
*
* @component  OF-DPA
*
* @comments   none
*
* @create     6 Nov 2013
*
* @end
*
**********************************************************************/
#include <indigo_ofdpa_driver/ind_ofdpa_util.h>
#include <unistd.h>
#include <indigo/memory.h>
#include <indigo/forwarding.h>
#include <indigo_ofdpa_driver/ind_ofdpa_log.h>
#include <indigo/of_state_manager.h>
#include <indigo/fi.h>
#include <OFStateManager/ofstatemanager.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>

ind_ofdpa_fields_t ind_ofdpa_match_fields_bitmask;

static indigo_error_t ind_ofdpa_packet_out_actions_get(of_list_action_t *of_list_actions, 
                                                       indPacketOutActions_t *packetOutActions);
static indigo_error_t ind_ofdpa_match_fields_masks_get(const of_match_t *match, ofdpaFlowEntry_t *flow);
static indigo_error_t ind_ofdpa_translate_openflow_actions(of_list_action_t *actions, ofdpaFlowEntry_t *flow);

extern int ofagent_of_version;

indTableNameList_t tableNameList[] =
{
  {OFDPA_FLOW_TABLE_ID_INGRESS_PORT,             "Ingress Port"},
  {OFDPA_FLOW_TABLE_ID_PORT_DSCP_TRUST,          "Port DSCP Trust"},
  {OFDPA_FLOW_TABLE_ID_PORT_PCP_TRUST,           "Port PCP Trust"},
  {OFDPA_FLOW_TABLE_ID_TUNNEL_DSCP_TRUST,        "Tunnel DSCP Trust"},
  {OFDPA_FLOW_TABLE_ID_TUNNEL_PCP_TRUST,         "Tunnel PCP Trust"},
  {OFDPA_FLOW_TABLE_ID_VLAN,                     "VLAN"},
  {OFDPA_FLOW_TABLE_ID_VLAN_1,                   "VLAN 1"},
  {OFDPA_FLOW_TABLE_ID_MAINTENANCE_POINT,        "MAINTENANCE POINT"},
  {OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT,             "MPLS L2 Port"},
  {OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST,          "MPLS DSCP Trust"},
  {OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST,           "MPLS PCP Trust"},
  {OFDPA_FLOW_TABLE_ID_TERMINATION_MAC,          "Termination MAC"},
  {OFDPA_FLOW_TABLE_ID_MPLS_0,                   "MPLS 0"},
  {OFDPA_FLOW_TABLE_ID_MPLS_1,                   "MPLS 1"},
  {OFDPA_FLOW_TABLE_ID_MPLS_2,                   "MPLS 2"},
  {OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT,   "MPLS-TP MAINTENANCE POINT"},
  {OFDPA_FLOW_TABLE_ID_BFD,                      "BFD"},
  {OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING,          "Unicast Routing"},
  {OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING,        "Multicast Routing"},
  {OFDPA_FLOW_TABLE_ID_BRIDGING,                 "Bridging"},
  {OFDPA_FLOW_TABLE_ID_ACL_POLICY,               "ACL Policy"},
  {OFDPA_FLOW_TABLE_ID_EGRESS_VLAN,              "Egress VLAN"},
  {OFDPA_FLOW_TABLE_ID_EGRESS_VLAN_1,            "Egress VLAN 1"},
  {OFDPA_FLOW_TABLE_ID_EGRESS_MAINTENANCE_POINT, "Egress MAINTENANCE POINT"},
  {OFDPA_FLOW_TABLE_ID_MPLS_QOS,                 "MPLS QOS"}
};

#define TABLE_NAME_LIST_SIZE (sizeof(tableNameList)/sizeof(tableNameList[0]))

static indigo_error_t ind_ofdpa_match_fields_prerequisite_validate(const of_match_t *match, OFDPA_FLOW_TABLE_ID_t tableId)
{
  indigo_error_t err = INDIGO_ERROR_NONE;
  /* comment out validation logic in Indigo, which will be done in OF-DPA core */
  switch(tableId)
  {
    case OFDPA_FLOW_TABLE_ID_ACL_POLICY:

      if ((ind_ofdpa_match_fields_bitmask & (IND_OFDPA_TCP_L4_SRC_PORT | IND_OFDPA_TCP_L4_DST_PORT)) &&
          (match->fields.ip_proto != IPPROTO_TCP))
      {
        LOG_ERROR("Invalid protocol ID %d for TCP L4 src/dst ports.", match->fields.ip_proto);
        err = INDIGO_ERROR_COMPAT;
        break;
      }

      if ((ind_ofdpa_match_fields_bitmask & (IND_OFDPA_UDP_L4_SRC_PORT | IND_OFDPA_UDP_L4_DST_PORT)) &&
          (match->fields.ip_proto != IPPROTO_UDP))
      {
        LOG_ERROR("Invalid protocol ID %d for UDP L4 src/dst ports.", match->fields.ip_proto);
        err = INDIGO_ERROR_COMPAT;
        break;
      }

      if ((ind_ofdpa_match_fields_bitmask & (IND_OFDPA_SCTP_L4_SRC_PORT | IND_OFDPA_SCTP_L4_DST_PORT)) &&
          (match->fields.ip_proto != IPPROTO_SCTP))
      {
        LOG_ERROR("Invalid protocol ID %d for SCTP L4 src/dst ports.", match->fields.ip_proto);
        err = INDIGO_ERROR_COMPAT;
        break;
      }

      break;
    default:
      break;
  }
  return err; 
}

static void ind_ofdpa_populate_flow_bitmask(const of_match_t *match)
{
  of_mac_addr_t macAddr;
  of_ipv6_t     ipAddr;

  if (match->masks.vlan_vid != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_VLANID;
  }

  memset(&macAddr, 0, sizeof(macAddr));

  if ((memcmp(&match->masks.eth_src, &macAddr, sizeof(match->masks.eth_src))) != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_SRCMAC;
  }

  if ((memcmp(&match->masks.eth_dst, &macAddr, sizeof(match->masks.eth_dst))) != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_DSTMAC;
  }

  if ((match->masks.in_port != 0) ||(match->masks.in_phy_port != 0))
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_PORT;
  }

  if (match->masks.eth_type != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_ETHER_TYPE;
  }

  if (match->masks.ipv4_dst != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_IPV4_DST;
  }

  if (match->masks.ipv4_src != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_IPV4_SRC;
  }

  memset(&ipAddr, 0, sizeof(ipAddr));

  if ((memcmp(&match->masks.ipv6_dst, &ipAddr, sizeof(match->masks.ipv6_dst))) != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_IPV6_DST;
  }

  if ((memcmp(&match->masks.ipv6_src, &ipAddr, sizeof(match->masks.ipv6_src))) != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_IPV6_SRC;
  }

  if (match->masks.tunnel_id != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_TUNNEL_ID;
  }

  if (match->masks.vlan_pcp != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_VLAN_PCP;
  }

#ifdef ROBS_HACK
  if (match->masks.ofdpa_dei != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_VLAN_DEI;
  }
#endif // ROBS_HACK
  if (match->masks.arp_spa != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_IPV4_ARP_SPA;
  }

  if (match->masks.arp_op != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_IP_PROTO;
  }

  if (match->masks.ip_dscp != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_IP_DSCP;
  }

  if (match->masks.ip_ecn != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_IP_ECN;
  }

  if (match->masks.tcp_src != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_TCP_L4_SRC_PORT;
  }

  if (match->masks.tcp_dst != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_TCP_L4_DST_PORT;
  }

  if (match->masks.udp_src != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_UDP_L4_SRC_PORT;
  }

  if (match->masks.udp_dst != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_UDP_L4_DST_PORT;
  }

  if (match->masks.sctp_src != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_SCTP_L4_SRC_PORT;
  }

  if (match->masks.sctp_dst != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_SCTP_L4_DST_PORT;
  }

  if (match->masks.icmpv4_type != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_ICMPV4_TYPE;
  }

  if (match->masks.icmpv4_code != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_ICMPV4_CODE;
  }

  if (match->masks.ipv6_flabel != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_IPV6_FLOW_LABEL;
  }

  if (match->masks.icmpv6_type != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_ICMPV6_TYPE;
  }

  if (match->masks.icmpv6_code != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_ICMPV6_CODE;
  }
  if (match->masks.mpls_label != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_MPLS_LABEL;
  }
  if (match->masks.mpls_bos != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_MPLS_BOS;
  }
  if (match->masks.mpls_tc != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_MPLS_TC;
  }
#ifdef ROBS_HACK
  if (match->masks.ofdpa_mpls_l2_port != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_MPLS_L2_PORT;
  }
  if (match->masks.ofdpa_ovid != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_OVID;
  }
#endif
  if (match->masks.bsn_vrf != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_VRF;
  }
#ifdef ROBS_HACK
  if (match->masks.ofdpa_qos_index != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_QOS_INDEX;
  }
  if (match->masks.ofdpa_lmep_id != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_LMEP_ID;
  }
  if (match->masks.ofdpa_mpls_ttl != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_MPLS_TTL;
  }
  if (match->masks.ofdpa_bfd_discriminator != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_BFD_DISCRIMINATOR;
  }
  if (match->masks.ofdpa_mpls_data_first_nibble != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_MPLS_DATA_FIRST_NIBBLE;
  }
  if (match->masks.ofdpa_mpls_ach_channel != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_MPLS_ACH_CHANNEL;
  }
  if (match->masks.ofdpa_mpls_next_label_is_gal != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_MPLS_NEXT_LABEL_IS_GAL;
  }
  if (match->masks.ofdpa_oam_y1731_mdl != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_OAM_Y1731_MDL;
  }
  if (match->masks.ofdpa_oam_y1731_opcode != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_OAM_Y1731_OPCODE;
  }
  if (match->masks.ofdpa_color_actions_index != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_COLOR_ACTIONS_INDEX;
  }
  if (match->masks.ofdpa_txfcl != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_TXFCL;
  }
  if (match->masks.ofdpa_rxfcl != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_RXFCL;
  }
  if (match->masks.ofdpa_rx_timestamp != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_RX_TIMESTAMP;
  }
  if (match->masks.ofdpa_actset_output != 0)
  {
    ind_ofdpa_match_fields_bitmask |= IND_OFDPA_ACTSET_OUTPUT;
  }
#endif // ROBS_HACK
  LOG_TRACE("match_fields_bitmask is 0x%llX", ind_ofdpa_match_fields_bitmask);
}

/* Get the flow match criteria from of_match */

static indigo_error_t ind_ofdpa_match_fields_masks_get(const of_match_t *match, ofdpaFlowEntry_t *flow)
{
  indigo_error_t err = INDIGO_ERROR_NONE;

  ind_ofdpa_populate_flow_bitmask(match);

  switch(flow->tableId)
  {
    case OFDPA_FLOW_TABLE_ID_INGRESS_PORT:
      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_ING_PORT_FLOW_MATCH_BITMAP) != IND_OFDPA_ING_PORT_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }
      
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_PORT)
      {
        flow->flowData.ingressPortFlowEntry.match_criteria.inPort = match->fields.in_port;
        flow->flowData.ingressPortFlowEntry.match_criteria.inPortMask = OFDPA_INPORT_EXACT_MASK;
      }

      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_TUNNEL_ID)
      {
        flow->flowData.ingressPortFlowEntry.match_criteria.tunnelId = match->fields.tunnel_id;
        flow->flowData.ingressPortFlowEntry.match_criteria.tunnelIdMask= match->masks.tunnel_id;
      }

      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_ETHER_TYPE)
      {
        flow->flowData.ingressPortFlowEntry.match_criteria.etherType = match->fields.eth_type;
        flow->flowData.ingressPortFlowEntry.match_criteria.etherTypeMask = match->masks.eth_type;
      }

      break; 
      
    case OFDPA_FLOW_TABLE_ID_VLAN:

      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_VLAN_FLOW_MATCH_BITMAP) != IND_OFDPA_VLAN_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }    

      flow->flowData.vlanFlowEntry.match_criteria.inPort = match->fields.in_port;

      /* DEI bit indicating 'present' is included in the VID match field */
      flow->flowData.vlanFlowEntry.match_criteria.vlanId = match->fields.vlan_vid; 
      if (match->masks.vlan_vid != 0)
      {
        if (match->fields.vlan_vid  == OFDPA_VID_PRESENT) /* All */
        {
          flow->flowData.vlanFlowEntry.match_criteria.vlanIdMask = OFDPA_VID_PRESENT;
        }
        else if ((match->fields.vlan_vid & OFDPA_VID_EXACT_MASK) == OFDPA_VID_NONE) /* untagged */
        {
          flow->flowData.vlanFlowEntry.match_criteria.vlanIdMask = OFDPA_VID_EXACT_MASK;
        }
        else /* tagged */
        {
          flow->flowData.vlanFlowEntry.match_criteria.vlanIdMask = (OFDPA_VID_PRESENT | OFDPA_VID_EXACT_MASK);
        }
      }
      else /* ALL */
      {
        flow->flowData.vlanFlowEntry.match_criteria.vlanId = OFDPA_VID_NONE;
        flow->flowData.vlanFlowEntry.match_criteria.vlanIdMask = OFDPA_VID_FIELD_MASK;
      }

      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_ETHER_TYPE)
      {
        flow->flowData.vlanFlowEntry.match_criteria.etherType = match->fields.eth_type;
        flow->flowData.vlanFlowEntry.match_criteria.etherTypeMask = match->masks.eth_type;
      }
      
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_DSTMAC)
      {
        memcpy(&flow->flowData.vlanFlowEntry.match_criteria.destMac, &match->fields.eth_dst, OF_MAC_ADDR_BYTES);
        memcpy(&flow->flowData.vlanFlowEntry.match_criteria.destMacMask, &match->masks.eth_dst, OF_MAC_ADDR_BYTES);
      }
      break;
   
    case OFDPA_FLOW_TABLE_ID_VLAN_1:

      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_VLAN1_FLOW_MATCH_BITMAP) != IND_OFDPA_VLAN1_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }    

      flow->flowData.vlan1FlowEntry.match_criteria.inPort = match->fields.in_port;

      flow->flowData.vlan1FlowEntry.match_criteria.vlanId = match->fields.vlan_vid; 

#ifdef ROBS_HACK
      flow->flowData.vlan1FlowEntry.match_criteria.brcmOvid = match->fields.ofdpa_ovid; 
#endif // ROBS_HACK

      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_ETHER_TYPE)
      {
        flow->flowData.vlan1FlowEntry.match_criteria.etherType = match->fields.eth_type;
        flow->flowData.vlan1FlowEntry.match_criteria.etherTypeMask = match->masks.eth_type;
      }
      
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_DSTMAC)
      {
        memcpy(&flow->flowData.vlan1FlowEntry.match_criteria.destMac, &match->fields.eth_dst, OF_MAC_ADDR_BYTES);
        memcpy(&flow->flowData.vlan1FlowEntry.match_criteria.destMacMask, &match->masks.eth_dst, OF_MAC_ADDR_BYTES);
      }
      break;
   
#ifdef ROBS_HACK    // seems a shame to lose an entire table -- FIXME!
    case OFDPA_FLOW_TABLE_ID_MAINTENANCE_POINT:

      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_MP_FLOW_MATCH_BITMAP) != IND_OFDPA_MP_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }    

      flow->flowData.mpFlowEntry.match_criteria.lmepId = match->fields.ofdpa_lmep_id;

      flow->flowData.mpFlowEntry.match_criteria.oamY1731Opcode = match->fields.ofdpa_oam_y1731_opcode; 

      flow->flowData.mpFlowEntry.match_criteria.oamY1731Mdl = match->fields.ofdpa_oam_y1731_mdl; 
      break;
   
    case OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT:

      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_MPLS_L2_PORT_FLOW_MATCH_BITMAP) != IND_OFDPA_MPLS_L2_PORT_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }    

      flow->flowData.mplsL2PortFlowEntry.match_criteria.mplsL2Port = match->fields.ofdpa_mpls_l2_port;
      flow->flowData.mplsL2PortFlowEntry.match_criteria.mplsL2PortMask = match->masks.ofdpa_mpls_l2_port;

      flow->flowData.mplsL2PortFlowEntry.match_criteria.tunnelId = match->fields.tunnel_id;

      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_ETHER_TYPE)
      {
        flow->flowData.mplsL2PortFlowEntry.match_criteria.etherType = match->fields.eth_type;
        flow->flowData.mplsL2PortFlowEntry.match_criteria.etherTypeMask = match->masks.eth_type;
      }
      break;
#endif // ROBS_HACK
   
    case OFDPA_FLOW_TABLE_ID_TERMINATION_MAC:
      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_TERM_MAC_FLOW_MATCH_BITMAP) != IND_OFDPA_TERM_MAC_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }
     
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_PORT) 
      {
        flow->flowData.terminationMacFlowEntry.match_criteria.inPort = match->fields.in_port;
        if (match->fields.in_port == 0) /* For multicast flow of termination mac table in_port must be 0 */
        {
          flow->flowData.terminationMacFlowEntry.match_criteria.inPortMask = 0;
        }
        else
        {
          if (match->masks.in_port != 0)
          {
            flow->flowData.terminationMacFlowEntry.match_criteria.inPortMask = match->masks.in_port;
          }
          else
          {
            flow->flowData.terminationMacFlowEntry.match_criteria.inPortMask = OFDPA_INPORT_EXACT_MASK;
          }
        }
      }

      flow->flowData.terminationMacFlowEntry.match_criteria.etherType = match->fields.eth_type;

      memcpy(&flow->flowData.terminationMacFlowEntry.match_criteria.destMac, &match->fields.eth_dst, OF_MAC_ADDR_BYTES);
      memcpy(&flow->flowData.terminationMacFlowEntry.match_criteria.destMacMask, &match->masks.eth_dst, OF_MAC_ADDR_BYTES);

      flow->flowData.terminationMacFlowEntry.match_criteria.vlanId = match->fields.vlan_vid & OFDPA_VID_EXACT_MASK;
      if (match->masks.vlan_vid != 0)
      {
        flow->flowData.terminationMacFlowEntry.match_criteria.vlanIdMask = match->masks.vlan_vid & OFDPA_VID_EXACT_MASK;
      }
      else
      {
        flow->flowData.terminationMacFlowEntry.match_criteria.vlanIdMask = OFDPA_VID_FIELD_MASK;
      }
      break;

    case OFDPA_FLOW_TABLE_ID_MPLS_0:
    case OFDPA_FLOW_TABLE_ID_MPLS_1:
    case OFDPA_FLOW_TABLE_ID_MPLS_2:
      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_MPLS_FLOW_MATCH_BITMAP) != IND_OFDPA_MPLS_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }
      
      flow->flowData.mplsFlowEntry.match_criteria.etherType = match->fields.eth_type;

      flow->flowData.mplsFlowEntry.match_criteria.mplsLabel = match->fields.mpls_label;
      
      flow->flowData.mplsFlowEntry.match_criteria.mplsBos = match->fields.mpls_bos;

      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_PORT)
      {
        flow->flowData.mplsFlowEntry.match_criteria.inPort = match->fields.in_port;
        flow->flowData.mplsFlowEntry.match_criteria.inPortMask = OFDPA_INPORT_EXACT_MASK;
      }
#ifdef ROBS_HACK
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_MPLS_TTL)
      {
        flow->flowData.mplsFlowEntry.match_criteria.mplsTtl = match->fields.ofdpa_mpls_ttl;
        flow->flowData.mplsFlowEntry.match_criteria.mplsTtlMask = match->masks.ofdpa_mpls_ttl;
      }
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_MPLS_DATA_FIRST_NIBBLE)
      {
        flow->flowData.mplsFlowEntry.match_criteria.mplsDataFirstNibble = match->fields.ofdpa_mpls_data_first_nibble;
        flow->flowData.mplsFlowEntry.match_criteria.mplsDataFirstNibbleMask = match->masks.ofdpa_mpls_data_first_nibble;
      }
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_MPLS_ACH_CHANNEL)
      {
        flow->flowData.mplsFlowEntry.match_criteria.mplsAchChannel = match->fields.ofdpa_mpls_ach_channel;
        flow->flowData.mplsFlowEntry.match_criteria.mplsAchChannelMask = match->masks.ofdpa_mpls_ach_channel;
      }
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_MPLS_NEXT_LABEL_IS_GAL)
      {
        flow->flowData.mplsFlowEntry.match_criteria.nextLabelIsGal = match->fields.ofdpa_mpls_next_label_is_gal;
        flow->flowData.mplsFlowEntry.match_criteria.nextLabelIsGalMask = match->masks.ofdpa_mpls_next_label_is_gal;
      }
#endif // ROBS_HACK
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_IPV4_DST)
      {
        flow->flowData.mplsFlowEntry.match_criteria.destIp4 = match->fields.ipv4_dst;
        flow->flowData.mplsFlowEntry.match_criteria.destIp4Mask = match->masks.ipv4_dst;
      }
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_IPV6_DST)
      {
        memcpy(&flow->flowData.mplsFlowEntry.match_criteria.destIp6, &match->fields.ipv6_dst, OF_IPV6_BYTES);
        memcpy(&flow->flowData.mplsFlowEntry.match_criteria.destIp6Mask, &match->masks.ipv6_dst, OF_IPV6_BYTES);
      }
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_IP_PROTO)
      {
        flow->flowData.mplsFlowEntry.match_criteria.ipProto = match->fields.ip_proto;
        flow->flowData.mplsFlowEntry.match_criteria.ipProtoMask = match->masks.ip_proto;
      }
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_UDP_L4_SRC_PORT)
      {
        flow->flowData.mplsFlowEntry.match_criteria.udpSrcPort= match->fields.udp_src;
        flow->flowData.mplsFlowEntry.match_criteria.udpSrcPortMask = match->masks.udp_src;
      }
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_UDP_L4_DST_PORT)
      {
        flow->flowData.mplsFlowEntry.match_criteria.udpDstPort= match->fields.udp_dst;
        flow->flowData.mplsFlowEntry.match_criteria.udpDstPortMask = match->masks.udp_dst;
      }
      break;
      
#ifdef ROBS_HACK
    case OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT:

      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_MPLS_MP_FLOW_MATCH_BITMAP) != IND_OFDPA_MPLS_MP_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }    

      flow->flowData.mplsMpFlowEntry.match_criteria.lmepId = match->fields.ofdpa_lmep_id;

      flow->flowData.mplsMpFlowEntry.match_criteria.oamY1731Opcode = match->fields.ofdpa_oam_y1731_opcode; 

      break;
#endif // ROBS_HACK
    case OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING:
      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_UCAST_ROUTING_FLOW_MATCH_BITMAP) != IND_OFDPA_UCAST_ROUTING_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }

      flow->flowData.unicastRoutingFlowEntry.match_criteria.etherType = match->fields.eth_type;
      
      if (match->fields.eth_type == ETH_P_IP) 
      {
        flow->flowData.unicastRoutingFlowEntry.match_criteria.dstIp4 = match->fields.ipv4_dst;
        flow->flowData.unicastRoutingFlowEntry.match_criteria.dstIp4Mask = match->masks.ipv4_dst;
      }
      else if (match->fields.eth_type == ETH_P_IPV6) 
      {
        memcpy(&flow->flowData.unicastRoutingFlowEntry.match_criteria.dstIp6, &match->fields.ipv6_dst, OF_IPV6_BYTES);
        memcpy(&flow->flowData.unicastRoutingFlowEntry.match_criteria.dstIp6Mask, &match->masks.ipv6_dst, OF_IPV6_BYTES);
      }

      flow->flowData.unicastRoutingFlowEntry.match_criteria.vrf = match->fields.bsn_vrf;
      flow->flowData.unicastRoutingFlowEntry.match_criteria.vrfMask= match->masks.bsn_vrf;
      break;

    case OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING:
      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_MCAST_ROUTING_FLOW_MATCH_BITMAP) != IND_OFDPA_MCAST_ROUTING_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }

      flow->flowData.multicastRoutingFlowEntry.match_criteria.etherType = match->fields.eth_type;
      
      flow->flowData.multicastRoutingFlowEntry.match_criteria.vlanId = match->fields.vlan_vid & OFDPA_VID_EXACT_MASK;
      
      flow->flowData.multicastRoutingFlowEntry.match_criteria.vrf = match->fields.bsn_vrf;
      flow->flowData.multicastRoutingFlowEntry.match_criteria.vrfMask= match->masks.bsn_vrf;

      if (match->fields.eth_type == ETH_P_IP)
      {
        flow->flowData.multicastRoutingFlowEntry.match_criteria.srcIp4 = match->fields.ipv4_src;
        flow->flowData.multicastRoutingFlowEntry.match_criteria.srcIp4Mask = match->masks.ipv4_src;
        flow->flowData.multicastRoutingFlowEntry.match_criteria.dstIp4 = match->fields.ipv4_dst;
      }
      else if (match->fields.eth_type == ETH_P_IPV6)
      {
        memcpy(flow->flowData.multicastRoutingFlowEntry.match_criteria.srcIp6.s6_addr, match->fields.ipv6_src.addr, OF_IPV6_BYTES);
        memcpy(flow->flowData.multicastRoutingFlowEntry.match_criteria.srcIp6Mask.s6_addr, match->masks.ipv6_src.addr, OF_IPV6_BYTES);
        memcpy(flow->flowData.multicastRoutingFlowEntry.match_criteria.dstIp6.s6_addr, match->fields.ipv6_dst.addr, OF_IPV6_BYTES);
      }
      break;

    case OFDPA_FLOW_TABLE_ID_BRIDGING:
      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_BRIDGING_FLOW_MATCH_BITMAP) != IND_OFDPA_BRIDGING_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }

      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_TUNNEL_ID)
      {
        flow->flowData.bridgingFlowEntry.match_criteria.tunnelId = match->fields.tunnel_id; 
        flow->flowData.bridgingFlowEntry.match_criteria.tunnelIdMask = match->masks.tunnel_id; 
      }
      else if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_VLANID)
      {
        flow->flowData.bridgingFlowEntry.match_criteria.vlanId = match->fields.vlan_vid & OFDPA_VID_EXACT_MASK;
        flow->flowData.bridgingFlowEntry.match_criteria.vlanIdMask = match->masks.vlan_vid & OFDPA_VID_EXACT_MASK;
      }
      memcpy(&flow->flowData.bridgingFlowEntry.match_criteria.destMac, &match->fields.eth_dst, OF_MAC_ADDR_BYTES);
      memcpy(&flow->flowData.bridgingFlowEntry.match_criteria.destMacMask, &match->masks.eth_dst, OF_MAC_ADDR_BYTES);
      break;

    case OFDPA_FLOW_TABLE_ID_PORT_DSCP_TRUST:
    case OFDPA_FLOW_TABLE_ID_TUNNEL_DSCP_TRUST:
#ifdef ROBS_HACK
    case OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST:
      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_DSCP_TRUST_FLOW_MATCH_BITMAP) != IND_OFDPA_DSCP_TRUST_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }
      flow->flowData.dscpTrustFlowEntry.match_criteria.qosIndex = match->fields.ofdpa_qos_index;
      flow->flowData.dscpTrustFlowEntry.match_criteria.dscpValue = match->fields.ip_dscp;
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_MPLS_L2_PORT)
      {
        flow->flowData.dscpTrustFlowEntry.match_criteria.mplsL2Port = match->fields.ofdpa_mpls_l2_port;
        flow->flowData.dscpTrustFlowEntry.match_criteria.mplsL2PortMask = match->masks.ofdpa_mpls_l2_port;
      }
      break;

    case OFDPA_FLOW_TABLE_ID_PORT_PCP_TRUST:
    case OFDPA_FLOW_TABLE_ID_TUNNEL_PCP_TRUST:
    case OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST:
      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_PCP_TRUST_FLOW_MATCH_BITMAP) != IND_OFDPA_PCP_TRUST_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }
      flow->flowData.pcpTrustFlowEntry.match_criteria.qosIndex = match->fields.ofdpa_qos_index;
      flow->flowData.pcpTrustFlowEntry.match_criteria.pcpValue = match->fields.vlan_pcp;
      flow->flowData.pcpTrustFlowEntry.match_criteria.dei = match->fields.ofdpa_dei;
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_MPLS_L2_PORT)
      {
        flow->flowData.pcpTrustFlowEntry.match_criteria.mplsL2Port = match->fields.ofdpa_mpls_l2_port;
        flow->flowData.pcpTrustFlowEntry.match_criteria.mplsL2PortMask = match->masks.ofdpa_mpls_l2_port;
      }
      break;

    case OFDPA_FLOW_TABLE_ID_MPLS_QOS:
      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_MPLS_QOS_FLOW_MATCH_BITMAP) != IND_OFDPA_MPLS_QOS_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }
      flow->flowData.mplsQosFlowEntry.match_criteria.qosIndex = match->fields.ofdpa_qos_index;
      flow->flowData.mplsQosFlowEntry.match_criteria.mpls_tc = match->fields.mpls_tc;
      break;
#endif // ROBS_HACK

    case OFDPA_FLOW_TABLE_ID_ACL_POLICY:
      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_ACL_POLICY_FLOW_MATCH_BITMAP) != IND_OFDPA_ACL_POLICY_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }

      /* Validate the pre-requisites for match fields */
      err = ind_ofdpa_match_fields_prerequisite_validate(match, flow->tableId);
      if (err != INDIGO_ERROR_NONE)
      {
        break; 
      }

      /* In Port */      
      if (match->fields.in_port != 0) /* match on a port */
      {
        flow->flowData.policyAclFlowEntry.match_criteria.inPort = match->fields.in_port; 
        if (match->masks.in_port != 0)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.inPortMask = match->masks.in_port;
        }
        else
        {
          flow->flowData.policyAclFlowEntry.match_criteria.inPortMask = OFDPA_INPORT_EXACT_MASK;
        }
      }
      else /* Match on all ports. Applicable to only physical ports */
      {
        ofdpaPortTypeSet(&flow->flowData.policyAclFlowEntry.match_criteria.inPort, OFDPA_PORT_TYPE_PHYSICAL);
        flow->flowData.policyAclFlowEntry.match_criteria.inPortMask = OFDPA_INPORT_TYPE_MASK;
      }

      /* Ethertype */
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_ETHER_TYPE)
      {
        flow->flowData.policyAclFlowEntry.match_criteria.etherType = match->fields.eth_type; 
        flow->flowData.policyAclFlowEntry.match_criteria.etherTypeMask = match->masks.eth_type; 
      }

      /* Src MAC */
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_SRCMAC)
      {
        memcpy(&flow->flowData.policyAclFlowEntry.match_criteria.srcMac, &match->fields.eth_src, OF_MAC_ADDR_BYTES);
        if (memcmp(&match->masks.eth_src, &of_mac_addr_all_zeros, sizeof(match->masks.eth_src)) == 0)
        {
          memcpy(&flow->flowData.policyAclFlowEntry.match_criteria.srcMacMask, &of_mac_addr_all_ones, OF_MAC_ADDR_BYTES);
        }
        else
        {
          memcpy(&flow->flowData.policyAclFlowEntry.match_criteria.srcMacMask, &match->masks.eth_src, OF_MAC_ADDR_BYTES);
        }
      }

      /* Dst MAC */
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_DSTMAC)
      {
        memcpy(&flow->flowData.policyAclFlowEntry.match_criteria.destMac, &match->fields.eth_dst, OF_MAC_ADDR_BYTES);
        if (memcmp(&match->masks.eth_dst, &of_mac_addr_all_zeros, sizeof(match->masks.eth_src)) == 0)
        {
          memcpy(&flow->flowData.policyAclFlowEntry.match_criteria.destMacMask, &of_mac_addr_all_ones, OF_MAC_ADDR_BYTES);
        }
        else
        {
          memcpy(&flow->flowData.policyAclFlowEntry.match_criteria.destMacMask, &match->masks.eth_dst, OF_MAC_ADDR_BYTES);
        }
      }

      /* Vlan ID */
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_VLANID)
      {
        flow->flowData.policyAclFlowEntry.match_criteria.vlanId = match->fields.vlan_vid & OFDPA_VID_EXACT_MASK;
        if (match->masks.vlan_vid != 0)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.vlanIdMask = match->masks.vlan_vid & OFDPA_VID_EXACT_MASK;
        }
        else
        {
          flow->flowData.policyAclFlowEntry.match_criteria.vlanIdMask = OFDPA_VID_FIELD_MASK;
        }
        /* To be removed once tunnel Id match condition is implemented */
        /* flow->flowData.policyAclFlowEntry.match_criteria.tunnelId = 0; */
      }

      /* Tunnel ID */
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_TUNNEL_ID)
      {
        flow->flowData.policyAclFlowEntry.match_criteria.tunnelId = match->fields.tunnel_id;
        flow->flowData.policyAclFlowEntry.match_criteria.tunnelIdMask = match->masks.tunnel_id;
      }

      /* Vlan PCP */
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_VLAN_PCP)
      {
        flow->flowData.policyAclFlowEntry.match_criteria.vlanPcp = match->fields.vlan_pcp;
        if (match->masks.vlan_pcp != 0)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.vlanPcpMask = match->masks.vlan_pcp;
        }
        else
        {
          flow->flowData.policyAclFlowEntry.match_criteria.vlanPcpMask = 0x7;
        }
      }

#ifdef ROBS_HACK
      /* Vlan DEI */
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_VLAN_DEI)
      {
        flow->flowData.policyAclFlowEntry.match_criteria.vlanDei = match->fields.ofdpa_dei;
        if (match->masks.ofdpa_dei != 0)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.vlanDeiMask = match->masks.ofdpa_dei & OFDPA_VLAN_DEI_VALUE_MASK;
        }
        else
        {
          flow->flowData.policyAclFlowEntry.match_criteria.vlanDeiMask = OFDPA_VLAN_DEI_VALUE_MASK;
        }
      }
#endif
      /* VRF */
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_VRF)
      {
        flow->flowData.policyAclFlowEntry.match_criteria.vrf = match->fields.bsn_vrf;
        flow->flowData.policyAclFlowEntry.match_criteria.vrfMask = match->masks.bsn_vrf;
      }

#ifdef ROBS_HACK
      /* MPLS L2 PORT */
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_MPLS_L2_PORT)
      {
        flow->flowData.policyAclFlowEntry.match_criteria.mplsL2Port = match->fields.ofdpa_mpls_l2_port;
        flow->flowData.policyAclFlowEntry.match_criteria.mplsL2PortMask = match->masks.ofdpa_mpls_l2_port;
      }
#endif // ROBS_HACK
      if (match->fields.eth_type == ETH_P_IP) 
      {
        /* IPv4 SRC */
        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_IPV4_SRC)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.sourceIp4 = match->fields.ipv4_src;
          if (match->masks.ipv4_src != 0)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.sourceIp4Mask = match->masks.ipv4_src;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.sourceIp4Mask = IND_OFDPA_DEFAULT_SOURCEIP4MASK;
          }
        }

        /* IPv4 DST */
        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_IPV4_DST)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.destIp4 = match->fields.ipv4_dst;
          if (match->masks.ipv4_dst != 0)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.destIp4Mask = match->masks.ipv4_dst;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.destIp4Mask = IND_OFDPA_DEFAULT_DESTIP4MASK;
          }
        }
      }
      else if (match->fields.eth_type == ETH_P_IPV6)
      {
        /* IPv6 SRC */
        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_IPV6_SRC)
        {
          memcpy(flow->flowData.policyAclFlowEntry.match_criteria.sourceIp6.s6_addr, match->fields.ipv6_src.addr, OF_IPV6_BYTES);
          if (memcmp(&match->masks.ipv6_src.addr, &of_ipv6_all_zeros, OF_IPV6_BYTES) == 0)
          {
            int i;
            for (i = 0; i < 4; i++) /* Prefix length as 128*/
            {
              flow->flowData.policyAclFlowEntry.match_criteria.sourceIp6Mask.s6_addr32[i] = ~0;
            }
          }
          else
          {
            memcpy(flow->flowData.policyAclFlowEntry.match_criteria.sourceIp6Mask.s6_addr, match->masks.ipv6_src.addr, OF_IPV6_BYTES);
          }
        }

        /* IPv6 DST */
        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_IPV6_DST)
        {
          memcpy(flow->flowData.policyAclFlowEntry.match_criteria.destIp6.s6_addr, match->fields.ipv6_dst.addr, OF_IPV6_BYTES);
          if (memcmp(&(match->masks.ipv6_dst), &of_ipv6_all_zeros, OF_IPV6_BYTES) == 0)
          {
            int i;
            for (i = 0; i < 4; i++) /* Prefix length as 128*/
            {
              flow->flowData.policyAclFlowEntry.match_criteria.destIp6Mask.s6_addr32[i] = ~0;
            }
          }
          else
          {
            memcpy(flow->flowData.policyAclFlowEntry.match_criteria.destIp6Mask.s6_addr, match->masks.ipv6_dst.addr, OF_IPV6_BYTES);
          }
        }

        /* IPv6 flow label */
        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_IPV6_FLOW_LABEL)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.ipv6FlowLabel = match->fields.ipv6_flabel;
          if (match->masks.ipv6_flabel != 0)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.ipv6FlowLabelMask = match->masks.ipv6_flabel;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.ipv6FlowLabelMask = ~0;
          }
        }
      }

      if (match->fields.eth_type == ETH_P_ARP)
      {
#if 0
        /* ARP Source IP Address */
        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_IPV4_ARP_SPA)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.ipv4ArpSpa = match->fields.arp_spa;
          if (match->masks.arp_spa != 0)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.ipv4ArpSpaMask = match->masks.arp_spa;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.ipv4ArpSpaMask = IND_OFDPA_DEFAULT_SOURCEIP4MASK;
          }
        }

        /* ARP IP Protocol */
        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_IP_PROTO)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.ipProto = match->fields.arp_op & 0xff;
          if ((match->masks.arp_op & 0xff))
          {
            flow->flowData.policyAclFlowEntry.match_criteria.ipProtoMask = match->masks.arp_op & 0xff;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.ipProtoMask = 0xff;
          }
        }
#endif
        LOG_ERROR("ARP Source IP Address is unsupported.");
        return INDIGO_ERROR_COMPAT;
      }
      else
      {
        if (match->fields.eth_type == ETH_P_IP || match->fields.eth_type == ETH_P_IPV6)
        {
          /* IP Protocol */
          if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_IP_PROTO)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.ipProto = match->fields.ip_proto;
            if (match->masks.ip_proto != 0)
            {
              flow->flowData.policyAclFlowEntry.match_criteria.ipProtoMask = match->masks.ip_proto;
            }
            else
            {
              flow->flowData.policyAclFlowEntry.match_criteria.ipProtoMask = 0xff; 
            }
          }

          /* IP DSCP */
          if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_IP_DSCP)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.dscp = match->fields.ip_dscp;
            if (match->masks.ip_dscp != 0)
            {
              flow->flowData.policyAclFlowEntry.match_criteria.dscpMask = match->masks.ip_dscp;
            }
            else
            {
              flow->flowData.policyAclFlowEntry.match_criteria.dscpMask = 0xff;
            }
          }

          if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_IP_ECN)
          {
#if 0
            flow->flowData.policyAclFlowEntry.match_criteria.ecn = match->fields.ip_ecn;
            if (match->masks.ip_ecn !=0)
            {
              flow->flowData.policyAclFlowEntry.match_criteria.ecnMask = match->masks.ip_ecn;
            }
            else
            {
              flow->flowData.policyAclFlowEntry.match_criteria.ecnMask = 0xff;
            }
#endif
            LOG_ERROR("ECN match field is unsupported.");
          }
        }
      }

      if (match->fields.ip_proto == IPPROTO_TCP) 
      {
        /* TCP L4 source port */
        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_TCP_L4_SRC_PORT)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.srcL4Port = match->fields.tcp_src;
          if (match->masks.tcp_src != 0)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.srcL4PortMask = match->masks.tcp_src;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.srcL4PortMask = 0xff;
          }
        }

        /* TCP L4 destination port */
        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_TCP_L4_DST_PORT)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.destL4Port = match->fields.tcp_dst;
          if (match->masks.tcp_dst != 0)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.destL4PortMask = match->masks.tcp_dst;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.destL4PortMask = 0xff;
          }
        }
      }
      else if (match->fields.ip_proto == IPPROTO_UDP) 
      {
        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_UDP_L4_SRC_PORT)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.srcL4Port = match->fields.udp_src;
          if (match->masks.udp_src != 0)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.srcL4PortMask = match->masks.udp_src;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.srcL4PortMask = 0xff;
          }
        }

        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_UDP_L4_DST_PORT)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.destL4Port = match->fields.udp_dst;
          if (match->masks.udp_dst != 0)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.destL4PortMask = match->masks.udp_dst;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.destL4PortMask = 0xff;
          }
        }
      }
      else if (match->fields.ip_proto == IPPROTO_SCTP)
      {
        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_SCTP_L4_SRC_PORT)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.srcL4Port = match->fields.sctp_src;
          if (match->masks.sctp_src != 0)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.srcL4PortMask = match->masks.sctp_src;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.srcL4PortMask = 0xff;
          }
        }

        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_SCTP_L4_DST_PORT)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.destL4Port = match->fields.sctp_dst;
          if (match->masks.sctp_dst != 0)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.destL4PortMask = match->masks.sctp_dst;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.destL4PortMask = 0xff;
          }
        }
      }
      else if (match->fields.ip_proto == IPPROTO_ICMP)
      {
        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_ICMPV4_TYPE)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.icmpType = match->fields.icmpv4_type;
          if (match->masks.icmpv4_type != 0)
          {
          flow->flowData.policyAclFlowEntry.match_criteria.icmpTypeMask = match->masks.icmpv4_type;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.icmpTypeMask = 0xff;
          }
        }

        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_ICMPV4_CODE)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.icmpCode = match->fields.icmpv4_code;
          if (match->masks.icmpv4_code != 0)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.icmpCodeMask = match->masks.icmpv4_code;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.icmpCodeMask = 0xff;
          }
        }
      }
      else if (match->fields.ip_proto == IPPROTO_ICMPV6)
      {
        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_ICMPV6_TYPE)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.icmpType = match->fields.icmpv6_type;
          if (match->masks.icmpv6_type != 0)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.icmpTypeMask = match->masks.icmpv6_type;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.icmpTypeMask = 0xff;
          }
        }

        if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_ICMPV6_CODE)
        {
          flow->flowData.policyAclFlowEntry.match_criteria.icmpCode = match->fields.icmpv6_code;
          if (match->masks.icmpv6_code != 0)
          {
            flow->flowData.policyAclFlowEntry.match_criteria.icmpCodeMask = match->masks.icmpv6_code;
          }
          else
          {
            flow->flowData.policyAclFlowEntry.match_criteria.icmpCodeMask = 0xff;
          }
        }
      }
      break;
    case OFDPA_FLOW_TABLE_ID_EGRESS_VLAN:

      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_EGRESS_VLAN_FLOW_MATCH_BITMAP) != IND_OFDPA_EGRESS_VLAN_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }    

#ifdef ROBS_HACK
      flow->flowData.egressVlanFlowEntry.match_criteria.outPort = match->fields.ofdpa_actset_output;
#endif
      flow->flowData.egressVlanFlowEntry.match_criteria.vlanId = match->fields.vlan_vid; 

      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_ETHER_TYPE)
      {
        flow->flowData.egressVlanFlowEntry.match_criteria.etherType = match->fields.eth_type;
        flow->flowData.egressVlanFlowEntry.match_criteria.etherTypeMask = match->masks.eth_type;
      }
      
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_DSTMAC)
      {
        memcpy(&flow->flowData.egressVlanFlowEntry.match_criteria.destMac, &match->fields.eth_dst, OF_MAC_ADDR_BYTES);
        memcpy(&flow->flowData.egressVlanFlowEntry.match_criteria.destMacMask, &match->masks.eth_dst, OF_MAC_ADDR_BYTES);
      }
      break;
   
    case OFDPA_FLOW_TABLE_ID_EGRESS_VLAN_1:

      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_EGRESS_VLAN1_FLOW_MATCH_BITMAP) != IND_OFDPA_EGRESS_VLAN1_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }    

#ifdef ROBS_HACK
      flow->flowData.egressVlan1FlowEntry.match_criteria.outPort = match->fields.ofdpa_actset_output;
#endif // ROBS_HACK
      flow->flowData.egressVlan1FlowEntry.match_criteria.vlanId = match->fields.vlan_vid; 

#ifdef ROBS_HACK
      flow->flowData.egressVlan1FlowEntry.match_criteria.brcmOvid = match->fields.ofdpa_ovid; 
#endif // ROBS_HACK

      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_ETHER_TYPE)
      {
        flow->flowData.egressVlan1FlowEntry.match_criteria.etherType = match->fields.eth_type;
        flow->flowData.egressVlan1FlowEntry.match_criteria.etherTypeMask = match->masks.eth_type;
      }
      
      if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_DSTMAC)
      {
        memcpy(&flow->flowData.egressVlan1FlowEntry.match_criteria.destMac, &match->fields.eth_dst, OF_MAC_ADDR_BYTES);
        memcpy(&flow->flowData.egressVlan1FlowEntry.match_criteria.destMacMask, &match->masks.eth_dst, OF_MAC_ADDR_BYTES);
      }
      break;
   
    case OFDPA_FLOW_TABLE_ID_EGRESS_MAINTENANCE_POINT:

      if ((ind_ofdpa_match_fields_bitmask | IND_OFDPA_EGRESS_MP_FLOW_MATCH_BITMAP) != IND_OFDPA_EGRESS_MP_FLOW_MATCH_BITMAP)
      {
        err = INDIGO_ERROR_COMPAT;
        break;
      }    

#ifdef ROBS_HACK
      flow->flowData.egressMpFlowEntry.match_criteria.lmepId = match->fields.ofdpa_lmep_id;
      flow->flowData.egressMpFlowEntry.match_criteria.oamY1731Opcode = match->fields.ofdpa_oam_y1731_opcode; 

      flow->flowData.egressMpFlowEntry.match_criteria.oamY1731Mdl = match->fields.ofdpa_oam_y1731_mdl; 
#endif // ROBS_HACK
      break;
   
    default:
      LOG_ERROR("Invalid table id %d", flow->tableId);
      err = INDIGO_ERROR_PARAM; 
      break;
  }

  if (err == INDIGO_ERROR_COMPAT)
  {
    LOG_ERROR("Incompatible match field(s) for table %d.", flow->tableId);
  }

  return err;
}

static indigo_error_t ind_ofdpa_translate_openflow_actions(of_list_action_t *actions, ofdpaFlowEntry_t *flow)
{
  of_action_t act;
  of_port_no_t port_no;
  uint32_t invalidPort = 0; /* Flag to check if the output port is valid*/
  int rv;

  OF_LIST_ACTION_ITER(actions, &act, rv) 
  {
    LOG_TRACE("action %s for table %d", of_object_id_str[act.object_id], flow->tableId);
    switch (act.object_id) 
    {
      case OF_ACTION_OUTPUT: 
      {
        of_action_output_port_get(&act, &port_no);
        switch (port_no) 
        {
          case OF_PORT_DEST_CONTROLLER: 
          {
            switch(flow->tableId)
            {
              case OFDPA_FLOW_TABLE_ID_TERMINATION_MAC:
                flow->flowData.terminationMacFlowEntry.outputPort = OFDPA_PORT_CONTROLLER; 
                break;
              case OFDPA_FLOW_TABLE_ID_BRIDGING:
                flow->flowData.bridgingFlowEntry.outputPort = OFDPA_PORT_CONTROLLER;
                break;
              case OFDPA_FLOW_TABLE_ID_MAINTENANCE_POINT:
                flow->flowData.mpFlowEntry.outputPort = OFDPA_PORT_CONTROLLER;
                break;
              case OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT:
                flow->flowData.mplsMpFlowEntry.outputPort = OFDPA_PORT_CONTROLLER;
                break;
              case OFDPA_FLOW_TABLE_ID_ACL_POLICY:
                flow->flowData.policyAclFlowEntry.outputPort = OFDPA_PORT_CONTROLLER;
                break;
              case OFDPA_FLOW_TABLE_ID_EGRESS_MAINTENANCE_POINT:
                flow->flowData.egressMpFlowEntry.outputPort = OFDPA_PORT_CONTROLLER;
                break;
              default:
                LOG_ERROR("Upsupported output port action (OFPP_CONTROLLER) for Table: %d", flow->tableId);
                return INDIGO_ERROR_COMPAT;
            }
            break;
          }
          case OF_PORT_DEST_LOCAL:
          {
            switch(flow->tableId)
            {
              case OFDPA_FLOW_TABLE_ID_MAINTENANCE_POINT:
                flow->flowData.mpFlowEntry.outputPort = OF_PORT_DEST_LOCAL;
                break;
              case OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT:
                flow->flowData.mplsMpFlowEntry.outputPort = OF_PORT_DEST_LOCAL;
                break;
              case OFDPA_FLOW_TABLE_ID_EGRESS_MAINTENANCE_POINT:
                flow->flowData.egressMpFlowEntry.outputPort = OF_PORT_DEST_LOCAL;
                break;
              default:
                LOG_ERROR("Upsupported output port action (OFPP_LOCAL) for Table: %d", flow->tableId);
                return INDIGO_ERROR_COMPAT;
            }
            break;
          }
          case OF_PORT_DEST_FLOOD: 
          case OF_PORT_DEST_ALL:
          case OF_PORT_DEST_USE_TABLE:
          case OF_PORT_DEST_IN_PORT:
          case OF_PORT_DEST_NORMAL:
            LOG_ERROR("Unsupported output port 0x%x", port_no);
            return INDIGO_ERROR_NOT_SUPPORTED;
          default:
            /* Physical or logical port as output port */ 
            /* If the port is tunnel logical port */ 
            if (ind_ofdpa_match_fields_bitmask & IND_OFDPA_TUNNEL_ID)
            {
              if (flow->tableId == OFDPA_FLOW_TABLE_ID_BRIDGING)
              {
                flow->flowData.bridgingFlowEntry.tunnelLogicalPort = port_no;
              }
              else if (flow->tableId == OFDPA_FLOW_TABLE_ID_ACL_POLICY)
              { 
                flow->flowData.policyAclFlowEntry.outputPort = port_no;
              }
              else
              {
                invalidPort = 1;
              }
            }
            else
            {
              invalidPort = 1;
            }

            if (invalidPort)
            {
              LOG_ERROR("Unsupported output port %d for Table %d", port_no, flow->tableId);
              return INDIGO_ERROR_NOT_SUPPORTED;
            }
            break;
        }
        break;
      }
      case OF_ACTION_SET_FIELD: 
      {
        /* HACK loci does not yet support the OXM field in the set-field action */
        of_oxm_t oxm;
        of_action_set_field_field_bind(&act, &oxm);
        if (oxm.length == 0) 
        {
          LOG_ERROR("Failed to parse set-field action");
          return INDIGO_ERROR_COMPAT;
        }
        LOG_TRACE("set-field oxm %s for table %d", of_object_id_str[oxm.object_id], flow->tableId);
        switch (oxm.object_id) 
        {
          case OF_OXM_TUNNEL_ID: 
          {
            uint64_t tunnel_id;
            of_oxm_tunnel_id_value_get(&oxm, &tunnel_id);
            if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN)
            {
              flow->flowData.vlanFlowEntry.tunnelIdAction = 1;
              flow->flowData.vlanFlowEntry.tunnelId = tunnel_id;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN_1)
            {
              flow->flowData.vlan1FlowEntry.tunnelIdAction = 1;
              flow->flowData.vlan1FlowEntry.tunnelId = tunnel_id;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
                    flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
                    flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
            {
              flow->flowData.mplsFlowEntry.tunnelIdAction = 1;
              flow->flowData.mplsFlowEntry.tunnelId = tunnel_id;
            }
            else
            {
              LOG_ERROR("Unsupported set-field oxm %s for table %d", of_object_id_str[oxm.object_id], flow->tableId);
              return INDIGO_ERROR_COMPAT;
            }
            break;
          }
#ifdef ROBS_HACK
          case OF_OXM_OFDPA_MPLS_L2_PORT: 
          {
            uint32_t mpls_l2_port;
            of_oxm_ofdpa_mpls_l2_port_value_get(&oxm.ofdpa_mpls_l2_port, &mpls_l2_port);
            if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN)
            {
              flow->flowData.vlanFlowEntry.mplsL2PortAction= 1;
              flow->flowData.vlanFlowEntry.mplsL2Port = mpls_l2_port;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN_1)
            {
              flow->flowData.vlan1FlowEntry.mplsL2PortAction= 1;
              flow->flowData.vlan1FlowEntry.mplsL2Port = mpls_l2_port;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
                    flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
                    flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
            {
              flow->flowData.mplsFlowEntry.mplsL2PortAction= 1;
              flow->flowData.mplsFlowEntry.mplsL2Port = mpls_l2_port;
            }
            else
            {
              LOG_ERROR("Unsupported set-field oxm %s for table %d", of_object_id_str[oxm.header.object_id], flow->tableId);
              return INDIGO_ERROR_COMPAT;
            }
            break;
          }
#endif // ROBS_HACK
          case OF_OXM_BSN_VRF: 
          {
            uint32_t vrf;
            of_oxm_bsn_vrf_value_get(&oxm, &vrf);
            if (flow->tableId == OFDPA_FLOW_TABLE_ID_INGRESS_PORT)
            {
              flow->flowData.ingressPortFlowEntry.vrfAction = 1;
              flow->flowData.ingressPortFlowEntry.vrf = (uint16_t) vrf & 0x00ff;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN)
            {
              flow->flowData.vlanFlowEntry.vrfAction = 1;
              flow->flowData.vlanFlowEntry.vrf = vrf;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN_1)
            {
              flow->flowData.vlan1FlowEntry.vrfAction = 1;
              flow->flowData.vlan1FlowEntry.vrf = vrf;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
                    flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
                    flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
            {
              flow->flowData.mplsFlowEntry.vrfAction = 1;
              flow->flowData.mplsFlowEntry.vrf = vrf;
            }
            else
            {
              LOG_ERROR("Unsupported set-field oxm %s for table %d", of_object_id_str[oxm.object_id], flow->tableId);
              return INDIGO_ERROR_COMPAT;
            }
            break;
          }
#ifdef ROBS_HACK
          case OF_OXM_OFDPA_OVID: 
          {
            uint16_t vlan_vid;
            of_oxm_ofdpa_ovid_value_get(&oxm.ofdpa_ovid, &vlan_vid);
            if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN)
            {
              flow->flowData.vlanFlowEntry.brcmOvidAction = 1;
              flow->flowData.vlanFlowEntry.brcmOvid = vlan_vid;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_EGRESS_VLAN)
            {
              flow->flowData.egressVlanFlowEntry.brcmOvidAction = 1;
              flow->flowData.egressVlanFlowEntry.brcmOvid = vlan_vid;
            }
            else
            {
              LOG_ERROR("Unsupported set-field oxm %s for table %d", of_object_id_str[oxm.header.object_id], flow->tableId);
              return INDIGO_ERROR_COMPAT;
            }
            break;
          }
#endif // ROBS_HACK
          case OF_OXM_VLAN_VID: 
          {
            uint16_t vlan_vid;
            of_oxm_vlan_vid_value_get(&oxm, &vlan_vid);
            if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN)
            {
              if (flow->flowData.vlanFlowEntry.pushVlan2Action == 1)
              {
                flow->flowData.vlanFlowEntry.newVlanId2 = vlan_vid & OFDPA_VID_EXACT_MASK;
                flow->flowData.vlanFlowEntry.setVlanId2Action = 1;
              }
              else
              {
                flow->flowData.vlanFlowEntry.newVlanId = vlan_vid & OFDPA_VID_EXACT_MASK;
                flow->flowData.vlanFlowEntry.setVlanIdAction = 1;
              }
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_EGRESS_VLAN)
            {
              if (flow->flowData.egressVlanFlowEntry.pushVlan2Action == 1)
              {
                flow->flowData.egressVlanFlowEntry.newVlanId2 = vlan_vid & OFDPA_VID_EXACT_MASK;
                flow->flowData.egressVlanFlowEntry.setVlanId2Action = 1;
              }
              else
              {
                flow->flowData.egressVlanFlowEntry.newVlanId = vlan_vid & OFDPA_VID_EXACT_MASK;
                flow->flowData.egressVlanFlowEntry.setVlanIdAction = 1;
              }
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN_1)
            {
              flow->flowData.vlan1FlowEntry.newVlanId = vlan_vid & OFDPA_VID_EXACT_MASK;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_EGRESS_VLAN_1)
            {
              if (flow->flowData.egressVlan1FlowEntry.pushVlan2Action == 1)
              {
                flow->flowData.egressVlan1FlowEntry.newVlanId2 = vlan_vid & OFDPA_VID_EXACT_MASK;
                flow->flowData.egressVlan1FlowEntry.setVlanId2Action = 1;
              }
              else
              {
                flow->flowData.egressVlan1FlowEntry.newVlanId = vlan_vid & OFDPA_VID_EXACT_MASK;
                flow->flowData.egressVlan1FlowEntry.setVlanIdAction = 1;
              }
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
                    flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
                    flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
            {
              flow->flowData.mplsFlowEntry.vlanIdAction = 1;
              flow->flowData.mplsFlowEntry.vlanId = vlan_vid & OFDPA_VID_EXACT_MASK;
            }
            else
            {
              LOG_ERROR("Unsupported set-field oxm %s for table %d", of_object_id_str[oxm.object_id], flow->tableId);
              return INDIGO_ERROR_COMPAT;
            }
            break;
          }
          case OF_OXM_VLAN_PCP: 
          {
            uint8_t vlan_pcp;
            of_oxm_vlan_pcp_value_get(&oxm, &vlan_pcp);
            if (flow->tableId == OFDPA_FLOW_TABLE_ID_ACL_POLICY)
            {
              /*
              flow->flowData.policyAclFlowEntry.vlanPcpAction = 1;
              flow->flowData.policyAclFlowEntry.vlanPcp = vlan_pcp; 
              */
            } 
            else
            {
              LOG_ERROR("Unsupported set-field oxm %s for table %d", of_object_id_str[oxm.object_id], flow->tableId);
              return INDIGO_ERROR_COMPAT;
            }
            break;
          }
#ifdef ROBS_HACK
          case OF_OXM_OFDPA_DEI: 
          {
            uint8_t vlan_dei;
            of_oxm_ofdpa_dei_value_get(&oxm.ofdpa_dei, &vlan_dei);
            if (flow->tableId == OFDPA_FLOW_TABLE_ID_ACL_POLICY)
            {
              /*
              flow->flowData.policyAclFlowEntry.vlanDeiAction = 1;
              flow->flowData.policyAclFlowEntry.vlanDei = vlan_dei; 
              */ 
            } 
            else
            {
              LOG_ERROR("Unsupported set-field oxm %s for table %d", of_object_id_str[oxm.header.object_id], flow->tableId);
              return INDIGO_ERROR_COMPAT;
            }
            break;
          }
#endif // ROBS_HACK
          case OF_OXM_ETH_SRC: 
          {
            of_mac_addr_t mac;
            of_oxm_eth_src_value_get(&oxm, &mac);
            break;
          }
          case OF_OXM_ETH_DST: 
          {
            of_mac_addr_t mac;
            of_oxm_eth_dst_value_get(&oxm, &mac);
            break;
          }
          case OF_OXM_IPV4_SRC: 
          {
            uint32_t ipv4;
            of_oxm_ipv4_src_value_get(&oxm, &ipv4);
            break;
          }
          case OF_OXM_IPV4_DST: 
          {
            uint32_t ipv4;
            of_oxm_ipv4_dst_value_get(&oxm, &ipv4);
            break;
          }
          case OF_OXM_IP_DSCP: 
          {
            uint8_t ip_dscp;
            of_oxm_ip_dscp_value_get(&oxm, &ip_dscp);
            if (ip_dscp > ((uint8_t)IND_OFDPA_IP_DSCP_MASK >> 2)) 
            {
              LOG_ERROR("invalid dscp %d in action %s", ip_dscp,
                        of_object_id_str[act.object_id]);
              return INDIGO_ERROR_COMPAT;
            }
            if (flow->tableId == OFDPA_FLOW_TABLE_ID_ACL_POLICY)
            {
              /*
              flow->flowData.policyAclFlowEntry.dscpAction = 1;
              flow->flowData.policyAclFlowEntry.dscp = ip_dscp; 
              */ 
            }
            else
            {
              LOG_ERROR("Unsupported set-field oxm %s for table %d", of_object_id_str[oxm.object_id], flow->tableId);
              return INDIGO_ERROR_COMPAT;
            }
            break;
          }
          case OF_OXM_IP_ECN: 
          {
            uint8_t ip_ecn;
            of_oxm_ip_ecn_value_get(&oxm, &ip_ecn);

            if (ip_ecn > IND_OFDPA_IP_ECN_MASK) 
            {
              LOG_ERROR("invalid ecn %d in action %s", ip_ecn,
                        of_object_id_str[act.object_id]);
              return INDIGO_ERROR_COMPAT;
            }
            if (flow->tableId == OFDPA_FLOW_TABLE_ID_ACL_POLICY)
            {
              /*
              flow->flowData.policyAclFlowEntry.ecnAction = 1;
              flow->flowData.policyAclFlowEntry.ecn = ip_ecn; 
              */ 
            }
            else
            {
              LOG_ERROR("Unsupported set-field oxm %s for table %d", of_object_id_str[oxm.object_id], flow->tableId);
              return INDIGO_ERROR_COMPAT;
            }
            break;
          }
          case OF_OXM_IPV6_SRC: 
          {
            of_ipv6_t ipv6;
            of_oxm_ipv6_src_value_get(&oxm, &ipv6);
            break;
          }
          case OF_OXM_IPV6_DST: 
          {
            of_ipv6_t ipv6;
            of_oxm_ipv6_dst_value_get(&oxm, &ipv6);
            break;
          }
          case OF_OXM_IPV6_FLABEL: 
          {
            uint32_t flabel;
            of_oxm_ipv6_flabel_value_get(&oxm, &flabel);
            if (flabel > IND_OFDPA_IPV6_FLABEL_MASK) 
            {
              LOG_ERROR("invalid flabel 0x%04x in action %s", flabel,
                        of_object_id_str[act.object_id]);
              return INDIGO_ERROR_COMPAT;
            }
            break;
          }
          case OF_OXM_TCP_SRC: 
          {
            uint16_t port;
            of_oxm_tcp_src_value_get(&oxm, &port);
            break;
          }
          case OF_OXM_TCP_DST: 
          {
            uint16_t port;
            of_oxm_tcp_dst_value_get(&oxm, &port);
            break;
          }
          case OF_OXM_UDP_SRC:
          {
            uint16_t port;
            of_oxm_udp_src_value_get(&oxm, &port);
            break;
          }
          case OF_OXM_UDP_DST: 
          {
            uint16_t port;
            of_oxm_udp_dst_value_get(&oxm, &port);
            break;
          }
#ifdef ROBS_HACK
          case OF_OXM_OFDPA_TC: 
          {
            uint8_t tc;
            of_oxm_ofdpa_tc_value_get(&oxm.ofdpa_tc, &tc);
            if ((flow->tableId == OFDPA_FLOW_TABLE_ID_PORT_DSCP_TRUST) ||
                     (flow->tableId == OFDPA_FLOW_TABLE_ID_TUNNEL_DSCP_TRUST) ||
                     (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST))
            {
              flow->flowData.dscpTrustFlowEntry.trafficClass = tc;
            }
            else if ((flow->tableId == OFDPA_FLOW_TABLE_ID_PORT_PCP_TRUST) ||
                     (flow->tableId == OFDPA_FLOW_TABLE_ID_TUNNEL_PCP_TRUST) ||
                     (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST))
            {
              flow->flowData.pcpTrustFlowEntry.trafficClass = tc;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
                    flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
                    flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
            {
              flow->flowData.mplsFlowEntry.trafficClass = tc;
              flow->flowData.mplsFlowEntry.trafficClassAction = 1;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_ACL_POLICY)
            {
              /*
              flow->flowData.policyAclFlowEntry.trafficClass = tc;
              flow->flowData.policyAclFlowEntry.trafficClassAction = 1; 
              */ 
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_QOS)
            {
              flow->flowData.mplsQosFlowEntry.trafficClass = tc;
            }
            else
            {
              LOG_ERROR("Unsupported set-field oxm %s for table %d", of_object_id_str[oxm.header.object_id], flow->tableId);
              return INDIGO_ERROR_COMPAT;
            }
            break;
          }
          case OF_OXM_OFDPA_COLOR: 
          {
            uint8_t color;
            of_oxm_ofdpa_color_value_get(&oxm.ofdpa_color, &color);
            if ((flow->tableId == OFDPA_FLOW_TABLE_ID_PORT_DSCP_TRUST) ||
                     (flow->tableId == OFDPA_FLOW_TABLE_ID_TUNNEL_DSCP_TRUST) ||
                     (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST))
            {
              flow->flowData.dscpTrustFlowEntry.color = color;
            }
            else if ((flow->tableId == OFDPA_FLOW_TABLE_ID_PORT_PCP_TRUST) ||
                     (flow->tableId == OFDPA_FLOW_TABLE_ID_TUNNEL_PCP_TRUST) ||
                     (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST))
            {
              flow->flowData.pcpTrustFlowEntry.color = color;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_ACL_POLICY)
            {
              flow->flowData.policyAclFlowEntry.color = color;
              flow->flowData.policyAclFlowEntry.colorAction = 1;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_QOS)
            {
              flow->flowData.mplsQosFlowEntry.color = color;
            }
            else
            {
              LOG_ERROR("Unsupported set-field oxm %s for table %d", of_object_id_str[oxm.header.object_id], flow->tableId);
              return INDIGO_ERROR_COMPAT;
            }
            break;
          }
          case OF_OXM_OFDPA_QOS_INDEX: 
          {
            uint8_t qos_index;
            of_oxm_ofdpa_qos_index_value_get(&oxm.ofdpa_qos_index, &qos_index);
            if (flow->tableId == OFDPA_FLOW_TABLE_ID_INGRESS_PORT)
            {
              flow->flowData.ingressPortFlowEntry.qosIndex = qos_index;
              flow->flowData.ingressPortFlowEntry.qosIndexAction = 1;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT)
            {
              flow->flowData.mplsL2PortFlowEntry.qosIndex = qos_index;
              flow->flowData.mplsL2PortFlowEntry.qosIndexAction = 1;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
                    flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
                    flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
            {
              flow->flowData.mplsFlowEntry.qosIndex = qos_index;
              flow->flowData.mplsFlowEntry.qosIndexAction = 1;
            }
            else
            {
              LOG_ERROR("Unsupported set-field oxm %s for table %d", of_object_id_str[oxm.header.object_id], flow->tableId);
              return INDIGO_ERROR_COMPAT;
            }
            break;
          }
          case OF_OXM_OFDPA_LMEP_ID: 
          {
            uint32_t lmep_id;
            of_oxm_ofdpa_lmep_id_value_get(&oxm.ofdpa_lmep_id, &lmep_id);
            if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN)
            {
              flow->flowData.vlanFlowEntry.lmepId = lmep_id;
              flow->flowData.vlanFlowEntry.lmepIdAction = 1;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN_1)
            {
              flow->flowData.vlan1FlowEntry.lmepId = lmep_id;
              flow->flowData.vlan1FlowEntry.lmepIdAction = 1;
            }
            else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
                    flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
                    flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
            {
              flow->flowData.mplsFlowEntry.lmepId = lmep_id;
              flow->flowData.mplsFlowEntry.lmepIdAction = 1;
            }
            else
            {
              LOG_ERROR("Unsupported set-field oxm %s for table %d", of_object_id_str[oxm.header.object_id], flow->tableId);
              return INDIGO_ERROR_COMPAT;
            }
            break;
          }
         
#endif // ROBS_HACK
          default:
            LOG_ERROR("unsupported set-field oxm %s for table %d", of_object_id_str[oxm.object_id], flow->tableId);
            return INDIGO_ERROR_COMPAT;
        }
        break;
      }
      case OF_ACTION_SET_QUEUE:
      {
        uint32_t queue_id;
        of_action_set_queue_queue_id_get(&act, &queue_id);
        if (flow->tableId == OFDPA_FLOW_TABLE_ID_ACL_POLICY)
        {
          flow->flowData.policyAclFlowEntry.queueIDAction = 1;
          flow->flowData.policyAclFlowEntry.queueID = queue_id;
        }
        else
        {
          LOG_ERROR("Unsupported action %s for table %d", of_object_id_str[act.object_id], flow->tableId);
          return INDIGO_ERROR_COMPAT;
        }
        break;
      } 
      case OF_ACTION_SET_DL_DST: 
      {
        of_mac_addr_t mac;
        of_action_set_dl_dst_dl_addr_get(&act, &mac);
        break;
      }
      case OF_ACTION_SET_DL_SRC: 
      {
        of_mac_addr_t mac;
        of_action_set_dl_src_dl_addr_get(&act, &mac);
        break;
      }
      case OF_ACTION_SET_NW_DST: 
      {
        uint32_t ipv4;
        of_action_set_nw_dst_nw_addr_get(&act, &ipv4);
        break;
      }
      case OF_ACTION_SET_NW_SRC: 
      {
        uint32_t ipv4;
        of_action_set_nw_src_nw_addr_get(&act, &ipv4);
        break;
      }
      case OF_ACTION_SET_NW_TOS: 
      {
        uint8_t tos;
        of_action_set_nw_tos_nw_tos_get(&act, &tos);
        break;
      }
      case OF_ACTION_SET_TP_DST: 
      {
        uint16_t port;
        of_action_set_tp_dst_tp_port_get(&act, &port);
        break;
      }
      case OF_ACTION_SET_TP_SRC: 
      {
        uint16_t port;
        of_action_set_tp_src_tp_port_get(&act, &port);
        break;
      }
      case OF_ACTION_SET_VLAN_VID: 
      {
        uint16_t vlan_vid;
        of_action_set_vlan_vid_vlan_vid_get(&act, &vlan_vid);
        break;
      }
      case OF_ACTION_SET_VLAN_PCP: 
      {
        uint8_t vlan_pcp;
        of_action_set_vlan_pcp_vlan_pcp_get(&act, &vlan_pcp);
        break;
      }
      case OF_ACTION_POP_VLAN:
        if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN)
        {
          flow->flowData.vlanFlowEntry.popVlanAction = 1;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_EGRESS_VLAN)
        {
          flow->flowData.egressVlanFlowEntry.popVlanAction = 1;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN_1)
        {
          flow->flowData.vlan1FlowEntry.popVlanAction = 1;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_EGRESS_VLAN_1)
        {
          flow->flowData.egressVlan1FlowEntry.popVlanAction = 1;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
                flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
                flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
        {
          flow->flowData.mplsFlowEntry.popVlanAction = 1;
        }
        else
        {
          LOG_ERROR("Unsupported action %s for table %d", of_object_id_str[act.object_id], flow->tableId);
          return INDIGO_ERROR_COMPAT;
        }
        break;
      case OF_ACTION_STRIP_VLAN: 
      {
        break;
      }
      case OF_ACTION_PUSH_VLAN: 
      {
        uint16_t eth_type;
        of_action_push_vlan_ethertype_get(&act, &eth_type);

        if (eth_type != ETH_P_8021Q && eth_type != 0x88a8) 
        {
          LOG_ERROR("unsupported eth_type 0x%04x in action %s", eth_type,
                    of_object_id_str[act.object_id]);
          return INDIGO_ERROR_COMPAT;
        }
        if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN)
        {
          flow->flowData.vlanFlowEntry.pushVlan2Action = 1;
          flow->flowData.vlanFlowEntry.newTpid2 = eth_type;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_EGRESS_VLAN)
        {
          flow->flowData.egressVlanFlowEntry.pushVlan2Action = 1;
          flow->flowData.egressVlanFlowEntry.newTpid2 = eth_type;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN_1)
        {
          flow->flowData.vlan1FlowEntry.pushVlanAction = 1;
          flow->flowData.vlan1FlowEntry.newTpid = eth_type;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_EGRESS_VLAN_1)
        {
          flow->flowData.egressVlan1FlowEntry.pushVlan2Action = 1;
          flow->flowData.egressVlan1FlowEntry.newTpid2 = eth_type;
        }
        else
        {
          LOG_ERROR("Unsupported action %s for table %d", of_object_id_str[act.object_id], flow->tableId);
          return INDIGO_ERROR_COMPAT;
        }
        break;
      }
      case OF_ACTION_DEC_NW_TTL:
      case OF_ACTION_NICIRA_DEC_TTL: 
      {
        break;
      }
      case OF_ACTION_SET_NW_TTL: 
      {
        uint8_t ttl;
        of_action_set_nw_ttl_nw_ttl_get(&act, &ttl);
        break;
      }
      case OF_ACTION_POP_MPLS: 
      {
        if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
        {
          flow->flowData.mplsFlowEntry.popLabelAction = 1;
          uint16_t ether_type;
          of_action_pop_mpls_ethertype_get(&act, &ether_type);
          flow->flowData.mplsFlowEntry.newEtherType = ether_type;
        }
        else
        {
          LOG_ERROR("Unsupported action %s for table %d", of_object_id_str[act.object_id], flow->tableId);
          return INDIGO_ERROR_COMPAT;
        }
        break;
      }
      case OF_ACTION_DEC_MPLS_TTL: 
      {
        if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
        {
          flow->flowData.mplsFlowEntry.decrementTtlAction = 1;
        }
        else
        {
          LOG_ERROR("Unsupported action %s for table %d", of_object_id_str[act.object_id], flow->tableId);
          return INDIGO_ERROR_COMPAT;
        }
        break;
      }
      case OF_ACTION_COPY_TTL_IN: 
      {
        if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
        {
          flow->flowData.mplsFlowEntry.copyTtlInAction = 1;
        }
        else
        {
          LOG_ERROR("Unsupported action %s for table %d", of_object_id_str[act.object_id], flow->tableId);
          return INDIGO_ERROR_COMPAT;
        }
        break;
      }
#ifdef ROBS_HACK
      case OF_ACTION_OFDPA_POP_L2HDR: 
      {
        if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
        {
          flow->flowData.mplsFlowEntry.popL2HeaderAction = 1;
        }
        else
        {
          LOG_ERROR("Unsupported action %s for table %d", of_object_id_str[act.header.object_id], flow->tableId);
          return INDIGO_ERROR_COMPAT;
        }
        break;
      }
      case OF_ACTION_OFDPA_POP_CW: 
      {
        if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
        {
          flow->flowData.mplsFlowEntry.popCwAction = 1;
        }
        else
        {
          LOG_ERROR("Unsupported action %s for table %d", of_object_id_str[act.header.object_id], flow->tableId);
          return INDIGO_ERROR_COMPAT;
        }
        break;
      }
      case OF_ACTION_OFDPA_COPY_TC_IN: 
      {
        if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
        {
          flow->flowData.mplsFlowEntry.copyTcInAction = 1;
        }
        else
        {
          LOG_ERROR("Unsupported action %s for table %d", of_object_id_str[act.header.object_id], flow->tableId);
          return INDIGO_ERROR_COMPAT;
        }
        break;
      }
      case OF_ACTION_OFDPA_OAM_LM_RX_COUNT: 
      {
        uint32_t lmepId;
        of_action_ofdpa_oam_lm_rx_count_lmep_id_get(&act.ofdpa_oam_lm_rx_count, &lmepId);
        if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
        {
          flow->flowData.mplsFlowEntry.oamLmRxCountAction = 1;
          flow->flowData.mplsFlowEntry.lmepId = lmepId;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT)
        {
          flow->flowData.mplsMpFlowEntry.oamLmRxCountAction = 1;
          flow->flowData.mplsMpFlowEntry.lmepId = lmepId;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_EGRESS_VLAN)
        {
          flow->flowData.egressVlanFlowEntry.oamLmRxCountAction = 1;
          flow->flowData.egressVlanFlowEntry.lmepId = lmepId;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_EGRESS_VLAN_1)
        {
          flow->flowData.egressVlan1FlowEntry.oamLmRxCountAction = 1;
          flow->flowData.egressVlan1FlowEntry.lmepId = lmepId;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_EGRESS_MAINTENANCE_POINT)
        {
          flow->flowData.egressMpFlowEntry.oamLmRxCountAction = 1;
          flow->flowData.egressMpFlowEntry.lmepId = lmepId;
        }
        else
        {
          LOG_ERROR("Unsupported action %s for table %d", of_object_id_str[act.header.object_id], flow->tableId);
          return INDIGO_ERROR_COMPAT;
        }
        break;
      }
      case OF_ACTION_OFDPA_OAM_LM_TX_COUNT: 
      {
        uint32_t lmepId;
        of_action_ofdpa_oam_lm_tx_count_lmep_id_get(&act.ofdpa_oam_lm_tx_count, &lmepId);
        if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN)
        {
          flow->flowData.vlanFlowEntry.oamLmTxCountAction = 1;
          flow->flowData.vlanFlowEntry.lmepId = lmepId;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_VLAN_1)
        {
          flow->flowData.vlan1FlowEntry.oamLmTxCountAction = 1;
          flow->flowData.vlan1FlowEntry.lmepId = lmepId;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MAINTENANCE_POINT)
        {
          flow->flowData.mpFlowEntry.oamLmTxCountAction = 1;
          flow->flowData.mpFlowEntry.lmepId = lmepId;
        }
        else
        {
          LOG_ERROR("Unsupported action %s for table %d", of_object_id_str[act.header.object_id], flow->tableId);
          return INDIGO_ERROR_COMPAT;
        }
        break;
      }
      case OF_ACTION_OFDPA_SET_COUNTER_FIELDS: 
      {
        uint32_t lmepId;
        of_action_ofdpa_set_counter_fields_lmep_id_get(&act.ofdpa_set_counter_fields, &lmepId);
        if (flow->tableId == OFDPA_FLOW_TABLE_ID_MAINTENANCE_POINT) /* No such action for Eth UpMep, required for CE-PE OAM */
        {
          flow->flowData.mpFlowEntry.oamSetCounterFieldsAction = 1;
          flow->flowData.mpFlowEntry.lmepId = lmepId;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT)
        {
          flow->flowData.mplsMpFlowEntry.oamSetCounterFieldsAction = 1;
          flow->flowData.mplsMpFlowEntry.lmepId = lmepId;
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_EGRESS_MAINTENANCE_POINT)
        {
          flow->flowData.egressMpFlowEntry.oamSetCounterFieldsAction = 1;
          flow->flowData.egressMpFlowEntry.lmepId = lmepId;
        }
        else
        {
          LOG_ERROR("Unsupported action %s for table %d", of_object_id_str[act.header.object_id], flow->tableId);
          return INDIGO_ERROR_COMPAT;
        }
        break;
      }
      case OF_ACTION_OFDPA_CHECK_DROP_STATUS: 
      {
        uint32_t drop_index;
        uint8_t drop_type;
        of_action_ofdpa_check_drop_status_drop_index_get(&act.ofdpa_check_drop_status, &drop_index);
        of_action_ofdpa_check_drop_status_drop_type_get(&act.ofdpa_check_drop_status, &drop_type);
        if (flow->tableId == OFDPA_FLOW_TABLE_ID_MAINTENANCE_POINT)
        {
          if (0 == drop_type)
          {
            flow->flowData.mpFlowEntry.checkDropStatusAction = 1;
            flow->flowData.mpFlowEntry.lmepId = drop_index;
          }
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_0 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_1 ||
            flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_2)
        {
          if (0 == drop_type)
          {
            flow->flowData.mplsFlowEntry.checkDropStatusAction = 1;
            flow->flowData.mplsFlowEntry.lmepId = drop_index;
          }
          else if (1 == drop_type)
          {
            flow->flowData.mplsFlowEntry.checkDropStatus2Action = 1;
            flow->flowData.mplsFlowEntry.dropIndex = drop_index;
            flow->flowData.mplsFlowEntry.dropType = drop_type;
          }
        }
        else if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT)
        {
          if (0 == drop_type)
          {
            flow->flowData.mplsMpFlowEntry.checkDropStatusAction = 1;
            flow->flowData.mplsMpFlowEntry.lmepId = drop_index;
          }
        }
        else
        {
          LOG_ERROR("Unsupported action %s for table %d", of_object_id_str[act.header.object_id], flow->tableId);
          return INDIGO_ERROR_COMPAT;
        }
        break;
      }
#endif // ROBS_HACK
      case OF_ACTION_GROUP: 
      {
        uint32_t group_id;
        of_action_group_group_id_get(&act, &group_id);
        switch(flow->tableId)
        {
          case OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT:
            flow->flowData.mplsL2PortFlowEntry.groupId = group_id;
            break;

          case OFDPA_FLOW_TABLE_ID_MPLS_0:
          case OFDPA_FLOW_TABLE_ID_MPLS_1:
          case OFDPA_FLOW_TABLE_ID_MPLS_2:
            flow->flowData.mplsFlowEntry.groupID = group_id;
            break;

          case OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING:
            flow->flowData.unicastRoutingFlowEntry.groupID = group_id;
            break;

          case OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING:
            flow->flowData.multicastRoutingFlowEntry.groupID = group_id;
            break;

          case OFDPA_FLOW_TABLE_ID_BRIDGING:
            flow->flowData.bridgingFlowEntry.groupID = group_id;
            break;
        
          case OFDPA_FLOW_TABLE_ID_ACL_POLICY:
            flow->flowData.policyAclFlowEntry.groupID = group_id;
            break;

          default:
            LOG_ERROR("Unsupported action %s for table %d", of_object_id_str[act.object_id], flow->tableId);
            return INDIGO_ERROR_COMPAT;
        }
        break;
      }
      default:
       LOG_ERROR("unsupported action %s", of_object_id_str[act.object_id]);
       return INDIGO_ERROR_COMPAT;
    }
  }

  return INDIGO_ERROR_NONE;
}

static indigo_error_t
ind_ofdpa_instructions_get(of_flow_modify_t *flow_mod, ofdpaFlowEntry_t *flow)
{
  of_list_action_t openflow_actions;
  indigo_error_t err;
  uint8_t next_table_id;
  uint32_t meter_id;
  int rv;
  of_list_instruction_t insts;
  of_instruction_t inst;
  uint8_t table_id;


  of_flow_modify_instructions_bind(flow_mod, &insts);

  of_flow_modify_table_id_get(flow_mod, &table_id);

  OF_LIST_INSTRUCTION_ITER(&insts, &inst, rv) 
  {
    switch (inst.object_id) 
    {
      case OF_INSTRUCTION_APPLY_ACTIONS:
        switch(flow->tableId)
        {
          case OFDPA_FLOW_TABLE_ID_INGRESS_PORT:
          case OFDPA_FLOW_TABLE_ID_PORT_DSCP_TRUST:
          case OFDPA_FLOW_TABLE_ID_PORT_PCP_TRUST:
          case OFDPA_FLOW_TABLE_ID_TUNNEL_DSCP_TRUST:
          case OFDPA_FLOW_TABLE_ID_TUNNEL_PCP_TRUST:
          case OFDPA_FLOW_TABLE_ID_VLAN:
          case OFDPA_FLOW_TABLE_ID_VLAN_1:
          case OFDPA_FLOW_TABLE_ID_MAINTENANCE_POINT:
          case OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT:
          case OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST:
          case OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST:
          case OFDPA_FLOW_TABLE_ID_TERMINATION_MAC:
          case OFDPA_FLOW_TABLE_ID_MPLS_0:
          case OFDPA_FLOW_TABLE_ID_MPLS_1:
          case OFDPA_FLOW_TABLE_ID_MPLS_2:
          case OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT:
          case OFDPA_FLOW_TABLE_ID_BRIDGING:
          case OFDPA_FLOW_TABLE_ID_ACL_POLICY:
          case OFDPA_FLOW_TABLE_ID_MPLS_QOS:
          case OFDPA_FLOW_TABLE_ID_EGRESS_VLAN:
          case OFDPA_FLOW_TABLE_ID_EGRESS_VLAN_1:
          case OFDPA_FLOW_TABLE_ID_EGRESS_MAINTENANCE_POINT:
            break;
          case OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING:
          case OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING:
          default:
            LOG_ERROR("Unsupported instruction %s for flow table %d.", of_object_id_str[inst.object_id], flow->tableId);
            return INDIGO_ERROR_COMPAT;
        }

        of_instruction_apply_actions_actions_bind(&inst, &openflow_actions);
        if ((err = ind_ofdpa_translate_openflow_actions(&openflow_actions,
                                                        flow)) < 0) 
        {
          return err;
        }
        break;
      case OF_INSTRUCTION_WRITE_ACTIONS:
        switch(flow->tableId)
        {
          case OFDPA_FLOW_TABLE_ID_VLAN:
          case OFDPA_FLOW_TABLE_ID_VLAN_1:
          case OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT:
          case OFDPA_FLOW_TABLE_ID_MPLS_0:
          case OFDPA_FLOW_TABLE_ID_MPLS_1:
          case OFDPA_FLOW_TABLE_ID_MPLS_2:
          case OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING:
          case OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING:
          case OFDPA_FLOW_TABLE_ID_BRIDGING:
          case OFDPA_FLOW_TABLE_ID_ACL_POLICY:
          case OFDPA_FLOW_TABLE_ID_EGRESS_MAINTENANCE_POINT:
            break;
          case OFDPA_FLOW_TABLE_ID_INGRESS_PORT:
          case OFDPA_FLOW_TABLE_ID_TERMINATION_MAC:
          default:
            LOG_ERROR("Unsupported instruction %s for flow table %d.", of_object_id_str[inst.object_id], flow->tableId);
            return INDIGO_ERROR_COMPAT;
        }
        of_instruction_write_actions_actions_bind(&inst, &openflow_actions);
        if ((err = ind_ofdpa_translate_openflow_actions(&openflow_actions,
                                                        flow)) < 0) 
        {
          return err;
        }
        break;
      case OF_INSTRUCTION_CLEAR_ACTIONS:
        if (flow->tableId == OFDPA_FLOW_TABLE_ID_ACL_POLICY)
        {
            flow->flowData.policyAclFlowEntry.clearActions = 1;
        }
        else
        {
          LOG_ERROR("Unsupported instruction %s for flow table %d.", of_object_id_str[inst.object_id], flow->tableId);
          return INDIGO_ERROR_COMPAT;
        }
        break;
      case OF_INSTRUCTION_GOTO_TABLE:
        of_instruction_goto_table_table_id_get(&inst, &next_table_id);

        switch(flow->tableId)
        {
          case OFDPA_FLOW_TABLE_ID_INGRESS_PORT:
            flow->flowData.ingressPortFlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_VLAN:     
            flow->flowData.vlanFlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_VLAN_1:     
            flow->flowData.vlan1FlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_MAINTENANCE_POINT:     
            flow->flowData.mpFlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT:     
            flow->flowData.mplsL2PortFlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_TERMINATION_MAC:
            flow->flowData.terminationMacFlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_MPLS_0:
          case OFDPA_FLOW_TABLE_ID_MPLS_1:
          case OFDPA_FLOW_TABLE_ID_MPLS_2:
            flow->flowData.mplsFlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT:     
            flow->flowData.mplsMpFlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING:
            flow->flowData.unicastRoutingFlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING:
            flow->flowData.multicastRoutingFlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_BRIDGING:
            flow->flowData.bridgingFlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_EGRESS_VLAN:     
            flow->flowData.egressVlanFlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_EGRESS_VLAN_1:     
            flow->flowData.egressVlan1FlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_PORT_DSCP_TRUST:
          case OFDPA_FLOW_TABLE_ID_TUNNEL_DSCP_TRUST:
          case OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST:
            flow->flowData.dscpTrustFlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_PORT_PCP_TRUST:
          case OFDPA_FLOW_TABLE_ID_TUNNEL_PCP_TRUST:
          case OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST:
            flow->flowData.pcpTrustFlowEntry.gotoTableId = next_table_id;
            break;
          case OFDPA_FLOW_TABLE_ID_ACL_POLICY:
            LOG_ERROR("Unsupported instruction %s for flow table %d.", of_object_id_str[inst.object_id], flow->tableId);
            return INDIGO_ERROR_COMPAT;
          default:
            LOG_ERROR("Unsupported instruction %s for flow table %d.", of_object_id_str[inst.object_id], flow->tableId);
            return INDIGO_ERROR_COMPAT;
            break;
        }
        break;
      case OF_INSTRUCTION_METER:
        of_instruction_meter_meter_id_get(&inst, &meter_id);
        LOG_ERROR("Unsupported instruction: meter_id.");
        break;
      default:
        LOG_ERROR("Invalid instruction.");
        return INDIGO_ERROR_COMPAT;
    }
  }
  return INDIGO_ERROR_NONE;
}

static indigo_error_t ind_ofdpa_packet_out_actions_get(of_list_action_t *of_list_actions, 
                                                       indPacketOutActions_t *packetOutActions)
{
  of_action_t act;
  indigo_error_t err = INDIGO_ERROR_NONE;
  int rv;


  OF_LIST_ACTION_ITER(of_list_actions, &act, rv)
  {
    switch (act.object_id)
    {
      case OF_ACTION_OUTPUT:
      {
        of_port_no_t port_no;
        of_action_output_port_get(&act, &port_no);
        switch (port_no)
        {
          case OF_PORT_DEST_CONTROLLER:
          case OF_PORT_DEST_FLOOD:
          case OF_PORT_DEST_ALL:
          case OF_PORT_DEST_LOCAL:
          case OF_PORT_DEST_IN_PORT:
          case OF_PORT_DEST_NORMAL:
            LOG_ERROR("Unsupported output port 0x%x", port_no);
            err = INDIGO_ERROR_NOT_SUPPORTED;
            break;
          case OF_PORT_DEST_USE_TABLE:
            packetOutActions->pipeline = 1;
            break;
          default:
            packetOutActions->outputPort = port_no;
            break;
        }
        break;
      }
      default:
        LOG_ERROR("Unsupported action for packet out: %s", of_object_id_str[act.object_id]);
        err = INDIGO_ERROR_NOT_SUPPORTED;
        break;
    }
  } 

  return err; 
}


indigo_error_t indigo_fwd_forwarding_features_get(of_features_reply_t *features_reply)
{
  uint32_t capabilities = 0;

  LOG_TRACE("%s() called", __FUNCTION__);

  if (features_reply->version < OF_VERSION_1_3)
  {
    LOG_ERROR("Unsupported OpenFlow version 0x%x.", features_reply->version);
    return INDIGO_ERROR_VERSION;
  }

  /* Number of tables supported by datapath. */
  of_features_reply_n_tables_set(features_reply, TABLE_NAME_LIST_SIZE);

  OF_CAPABILITIES_FLAG_FLOW_STATS_SET(capabilities, features_reply->version);
  OF_CAPABILITIES_FLAG_TABLE_STATS_SET(capabilities, features_reply->version);
  OF_CAPABILITIES_FLAG_PORT_STATS_SET(capabilities, features_reply->version);
  OF_CAPABILITIES_FLAG_QUEUE_STATS_SET(capabilities, features_reply->version);
  of_features_reply_capabilities_set(features_reply, capabilities);

  return INDIGO_ERROR_NONE;
}

indigo_error_t indigo_fwd_flow_create(indigo_cookie_t flow_id,
                                      of_flow_add_t *flow_add,
                                      uint8_t *table_id)
{
  indigo_error_t err = INDIGO_ERROR_NONE;
  OFDPA_ERROR_t ofdpa_rv = OFDPA_E_NONE;
  ofdpaFlowEntry_t flow;
  ofdpaFlowEntryStats_t  flowStats;
  uint16_t priority;
  uint16_t idle_timeout, hard_timeout; 
  of_match_t of_match;

  LOG_TRACE("Flow create called");

  if (flow_add->version < OF_VERSION_1_3) 
  {
    LOG_ERROR("OpenFlow version 0x%x unsupported", flow_add->version);
    return INDIGO_ERROR_VERSION;
  }

  memset(&flowStats, 0, sizeof(flowStats));
  memset(&flow, 0, sizeof(flow));
    
  flow.cookie = flow_id;

  /* Get the Flow Table ID */
  of_flow_add_table_id_get(flow_add, table_id);
  flow.tableId = (uint32_t)*table_id;

  /* ofdpa Flow priority */
  of_flow_add_priority_get(flow_add, &priority);
  flow.priority = (uint32_t)priority;

  /* Get the idle time and hard time */
  (void)of_flow_modify_idle_timeout_get((of_flow_modify_t *)flow_add, &idle_timeout);
  (void)of_flow_modify_hard_timeout_get((of_flow_modify_t *)flow_add, &hard_timeout);
  flow.idle_time = (uint32_t)idle_timeout;
  flow.hard_time = (uint32_t)hard_timeout;

  memset(&of_match, 0, sizeof(of_match));
  ind_ofdpa_match_fields_bitmask = 0; /* Set the bit mask to 0 before being set in of_flow_add_match_get() */
  if (of_flow_add_match_get(flow_add, &of_match) < 0) 
  {
    LOG_ERROR("Error getting openflow match criteria.");
    return INDIGO_ERROR_UNKNOWN;
  }

  /* Get the match fields and masks from LOCI match structure */
  err = ind_ofdpa_match_fields_masks_get(&of_match, &flow);
  if (err != INDIGO_ERROR_NONE)
  {
    LOG_ERROR("Error getting match fields and masks. (err = %d)", err);
    return err;
  }
  
  /* Get the instructions set from the LOCI flow add object */
  err = ind_ofdpa_instructions_get(flow_add, &flow); 
  if (err != INDIGO_ERROR_NONE)
  {
    LOG_ERROR("Failed to get flow instructions. (err = %d)", err);
    return err; 
  }

  /* Submit the changes to ofdpa */
  ofdpa_rv = ofdpaFlowAdd(&flow);
  if (ofdpa_rv != OFDPA_E_NONE)
  {
    LOG_ERROR("Failed to add flow. (ofdpa_rv = %d)", ofdpa_rv);
  }
  else
  {
    LOG_TRACE("Flow added successfully. (ofdpa_rv = %d)", ofdpa_rv);
  }
  

  return (indigoConvertOfdpaRv(ofdpa_rv));
}

indigo_error_t indigo_fwd_flow_modify(indigo_cookie_t flow_id,
                                      of_flow_modify_t *flow_modify)
{
  indigo_error_t err = INDIGO_ERROR_NONE;
  ofdpaFlowEntry_t flow;
  ofdpaFlowEntryStats_t flowStats;
  OFDPA_ERROR_t ofdpa_rv = OFDPA_E_NONE;  
  of_match_t of_match;

  LOG_TRACE("Flow modify called");      

  if (flow_modify->version < OF_VERSION_1_3)
  {
    LOG_ERROR("OpenFlow version 0x%x unsupported", flow_modify->version);
    return INDIGO_ERROR_VERSION;
  }

  memset(&flow, 0, sizeof(flow));
  memset(&flowStats, 0, sizeof(flowStats));

  /* Get the flow entries and flow stats from the indigo cookie */
  ofdpa_rv = ofdpaFlowByCookieGet(flow_id, &flow, &flowStats);
  if (ofdpa_rv != OFDPA_E_NONE)
  {
    if (ofdpa_rv == OFDPA_E_NOT_FOUND)
    {
      LOG_ERROR("Request to modify non-existent flow. (ofdpa_rv = %d)", ofdpa_rv);
    }
    else
    {
      LOG_ERROR("Invalid flow. (ofdpa_rv = %d)", ofdpa_rv);
    }
    return (indigoConvertOfdpaRv(ofdpa_rv));   
  }

  memset(&of_match, 0, sizeof(of_match));
  if (of_flow_add_match_get(flow_modify, &of_match) < 0)
  {
    LOG_ERROR("Error getting openflow match criteria.");
    return INDIGO_ERROR_UNKNOWN;
  }
  
  memset(&flow.flowData, 0, sizeof(flow.flowData));

  /* Get the match fields and masks from LOCI match structure */
  err = ind_ofdpa_match_fields_masks_get(&of_match, &flow);
  if (err != INDIGO_ERROR_NONE)
  {
    LOG_ERROR("Error getting match fields and masks. (err = %d)", err);
    return err;
  }

  /* Get the modified instructions set from the LOCI flow add object */
  err = ind_ofdpa_instructions_get(flow_modify, &flow);
  if (err != INDIGO_ERROR_NONE)  
  {
    LOG_ERROR("Failed to get flow instructions. (err = %d)", err);
    return err;
  } 

  /* Submit the changes to ofdpa */
  ofdpa_rv = ofdpaFlowModify(&flow);
  if (ofdpa_rv!= OFDPA_E_NONE)
  {
    LOG_ERROR("Failed to modify flow. (ofdpa_rv = %d)", ofdpa_rv);
  }
  else
  {
    LOG_TRACE("Flow modified successfully. (ofdpa_rv = %d)", ofdpa_rv);
  }

  return (indigoConvertOfdpaRv(ofdpa_rv));
}

indigo_error_t indigo_fwd_flow_delete(indigo_cookie_t flow_id,
                                      indigo_fi_flow_stats_t *flow_stats)
{
  ofdpaFlowEntry_t flow;
  ofdpaFlowEntryStats_t flowStats;
  OFDPA_ERROR_t ofdpa_rv = OFDPA_E_NONE;


  LOG_TRACE("Flow delete called");

  memset(&flow, 0, sizeof(flow));
  memset(&flowStats, 0, sizeof(flowStats));
        
  ofdpa_rv = ofdpaFlowByCookieGet(flow_id, &flow, &flowStats);
  if (ofdpa_rv != OFDPA_E_NONE)
  {
    if (ofdpa_rv == OFDPA_E_NOT_FOUND)
    {
      LOG_ERROR("Request to delete non-existent flow. (ofdpa_rv = %d)", ofdpa_rv);
    }
    else
    {
      LOG_ERROR("Invalid flow. (ofdpa_rv = %d)", ofdpa_rv);
    }

    return (indigoConvertOfdpaRv(ofdpa_rv));
  }

#ifdef ROBS_HACK
  flow_stats->flow_id = flow_id;
#endif // ROBS_HACK
  flow_stats->packets = flowStats.receivedPackets;
  flow_stats->bytes = flowStats.receivedBytes;
#ifdef ROBS_HACK
  flow_stats->duration_ns = (flowStats.durationSec)*(IND_OFDPA_NANO_SEC); /* Convert to nano seconds*/
#endif // ROBS_HACK

  /* Delete the flow entry */
  ofdpa_rv = ofdpaFlowByCookieDelete(flow_id);
  if (ofdpa_rv != OFDPA_E_NONE)
  {
    LOG_ERROR("Failed to delete flow. (ofdpa_rv = %d)", ofdpa_rv);
  }
  else
  {
    LOG_TRACE("Flow deleted successfully. (ofdpa_rv = %d)", ofdpa_rv);
  }

  return (indigoConvertOfdpaRv(ofdpa_rv));;
}

indigo_error_t indigo_fwd_flow_stats_get(indigo_cookie_t flow_id,
                                         indigo_fi_flow_stats_t *flow_stats)
{
  OFDPA_ERROR_t ofdpa_rv = OFDPA_E_NONE;
  ofdpaFlowEntry_t flow;
  ofdpaFlowEntryStats_t flowStats;

  memset(&flow, 0, sizeof(flow));
  memset(&flowStats, 0, sizeof(flowStats));

  /* Get the flow and flow stats from flow id */        
  ofdpa_rv = ofdpaFlowByCookieGet(flow_id, &flow, &flowStats);
  if (ofdpa_rv == OFDPA_E_NONE)
  {
#ifdef ROBS_HACK
    flow_stats->flow_id = flow_id;
    flow_stats->duration_ns = (flowStats.durationSec) * (IND_OFDPA_NANO_SEC); /* Convert to nsecs */
#endif // ROBS_HACK
    flow_stats->packets = flowStats.receivedPackets;
    flow_stats->bytes = flowStats.receivedBytes;

    LOG_TRACE("Flow stats get successful. (ofdpa_rv = %d)", ofdpa_rv);
  }
  else if (ofdpa_rv == OFDPA_E_NOT_FOUND)
  {
    LOG_ERROR("Request to get stats of a non-existent flow. (ofdpa_rv = %d)", ofdpa_rv);
  }
  else
  {
    LOG_ERROR("Failed to get flow stats. (ofdpa_rv = %d)", ofdpa_rv);
  }

  return (indigoConvertOfdpaRv(ofdpa_rv));
}

void indigo_fwd_table_mod(of_table_mod_t *of_table_mod,
                          indigo_cookie_t callback_cookie)
{
  LOG_ERROR("indigo_fwd_table_mod() unsupported.");
  return;
}

indigo_error_t indigo_fwd_table_stats_get(of_table_stats_request_t *table_stats_request,
                                          of_table_stats_reply_t **table_stats_reply)
{
  of_version_t version = table_stats_request->version;
  OFDPA_ERROR_t ofdpa_rv = OFDPA_E_NONE;
  uint32_t xid;
  uint32_t i;
  ofdpaFlowTableInfo_t tableInfo;
  of_table_stats_entry_t entry[1];
  of_table_stats_reply_t *reply;
  

  if (version < OF_VERSION_1_3)
  {
    LOG_ERROR("Unsupported OpenFlow version 0x%x.", version);
    return INDIGO_ERROR_VERSION;
  }

  reply = of_table_stats_reply_new(version);
  if (reply == NULL) 
  {
    LOG_ERROR("Error allocating memory");  
    return INDIGO_ERROR_RESOURCE; 
  }

  *table_stats_reply = reply;

  of_table_stats_request_xid_get(table_stats_request, &xid);
  of_table_stats_reply_xid_set(*table_stats_reply, xid);

  of_list_table_stats_entry_t list[1];
  of_table_stats_reply_entries_bind(*table_stats_reply, list);

  
  for (i = 0; i < TABLE_NAME_LIST_SIZE; i++)
  {
    of_table_stats_entry_init(entry, version, -1, 1);
    (void) of_list_table_stats_entry_append_bind(list, entry);

    ofdpa_rv = ofdpaFlowTableInfoGet(tableNameList[i].type, &tableInfo);
    if (ofdpa_rv != OFDPA_E_NONE)
    {
      LOG_ERROR("Error getting flow table info. (ofdpa_rv = %d)", ofdpa_rv);
      return (indigoConvertOfdpaRv(ofdpa_rv));
    }

    /* Table Id */
    of_table_stats_entry_table_id_set(entry, tableNameList[i].type);

    /* Number of entries in the table */
    of_table_stats_entry_active_count_set(entry, tableInfo.numEntries);

    /* Number of packets looked up in table. */
    of_table_stats_entry_lookup_count_set(entry, 0);

    /* Number of packets that hit table. */
    of_table_stats_entry_matched_count_set(entry, 0);
  }

  return (indigoConvertOfdpaRv(ofdpa_rv));
}

indigo_error_t indigo_fwd_packet_out(of_packet_out_t *packet_out)
{
  OFDPA_ERROR_t  ofdpa_rv = OFDPA_E_NONE;
  indigo_error_t err = INDIGO_ERROR_NONE;
  indPacketOutActions_t packetOutActions;
  ofdpa_buffdesc pkt;

  of_port_no_t   of_port_num;
  of_list_action_t of_list_action[1];
  of_octets_t    of_octets[1];

  of_packet_out_in_port_get(packet_out, &of_port_num);
  of_packet_out_data_get(packet_out, of_octets);
  of_packet_out_actions_bind(packet_out, of_list_action);

        
  pkt.pstart = (char *)of_octets->data;
  pkt.size = of_octets->bytes; 

  memset(&packetOutActions, 0, sizeof(packetOutActions)); 
  err = ind_ofdpa_packet_out_actions_get(of_list_action, &packetOutActions);
  if (err != INDIGO_ERROR_NONE)
  {
    LOG_ERROR("Failed to get packet out actions. (err = %d)", err);
    return err;
  }


  if (packetOutActions.pipeline)
  {
    ofdpa_rv = ofdpaPktSend(&pkt, OFDPA_PKT_LOOKUP, packetOutActions.outputPort, of_port_num);
  }
  else
  {
    ofdpa_rv = ofdpaPktSend(&pkt, 0, packetOutActions.outputPort, 0);
  }

  if (ofdpa_rv != OFDPA_E_NONE)
  {
    LOG_ERROR("Packet send failed. (ofdpa_rv = %d)", ofdpa_rv);
  }
  else
  {
    LOG_TRACE("Packet sent out of output port (%d) successfully. (ofdpa_rv = %d)", packetOutActions.outputPort, ofdpa_rv);
  }

  return (indigoConvertOfdpaRv(ofdpa_rv));
}

indigo_error_t indigo_fwd_experimenter(of_experimenter_t *experimenter,
                                       indigo_cxn_id_t cxn_id)
{
  LOG_ERROR("indigo_fwd_experimenter() unsupported.");
  return INDIGO_ERROR_NOT_SUPPORTED;
}

indigo_error_t indigo_fwd_expiration_enable_set(int is_enabled)
{
  LOG_ERROR("indigo_fwd_expiration_enable_set() unsupported.");
  return INDIGO_ERROR_NOT_SUPPORTED;
}

indigo_error_t indigo_fwd_expiration_enable_get(int *is_enabled)
{
  LOG_ERROR("indigo_fwd_expiration_enable_get() unsupported.");
  return INDIGO_ERROR_NOT_SUPPORTED;
}

void ind_ofdpa_flow_event_receive(void)
{
  ofdpaFlowEvent_t flowEventData;

  LOG_TRACE("Reading Flow Events");

  memset(&flowEventData, 0, sizeof(flowEventData));
  flowEventData.flowMatch.tableId = OFDPA_FLOW_TABLE_ID_VLAN;

  while (ofdpaFlowEventNextGet(&flowEventData) == OFDPA_E_NONE)
  {
    if (flowEventData.eventMask & OFDPA_FLOW_EVENT_HARD_TIMEOUT)
    {
      LOG_TRACE("Received flow event on hard timeout.");
      ind_core_flow_expiry_handler(flowEventData.flowMatch.cookie,
                                   INDIGO_FLOW_REMOVED_HARD_TIMEOUT);
    }
    else
    {
      LOG_TRACE("Received flow event on idle timeout.");
      ind_core_flow_expiry_handler(flowEventData.flowMatch.cookie,
                                   INDIGO_FLOW_REMOVED_IDLE_TIMEOUT);
    }
  }
  return;
}

static void ind_ofdpa_key_to_match(uint32_t portNum, of_match_t *match)
{
  memset(match, 0, sizeof(*match));

  /* We only populate the masks for this OF version */
  match->version = ofagent_of_version;

  of_match_fields_t *fields = &match->fields;

  fields->in_port = portNum;
  OF_MATCH_MASK_IN_PORT_EXACT_SET(match);
}

static indigo_error_t
ind_ofdpa_fwd_pkt_in(of_port_no_t in_port,
               uint8_t *data, unsigned int len, unsigned reason,
               of_match_t *match, OFDPA_FLOW_TABLE_ID_t tableId)
{
  of_octets_t of_octets = { .data = data, .bytes = len };
  of_packet_in_t *of_packet_in;

  LOG_TRACE("Sending packet-in");

  of_packet_in = of_packet_in_new(ofagent_of_version);
  if (of_packet_in == NULL) 
  {
    return INDIGO_ERROR_RESOURCE;
  }

  of_packet_in_total_len_set(of_packet_in, len);
  of_packet_in_reason_set(of_packet_in, reason);
  of_packet_in_table_id_set(of_packet_in, tableId);
  of_packet_in_cookie_set(of_packet_in, 0xffffffffffffffff);

  if (of_packet_in_match_set(of_packet_in, match) != OF_ERROR_NONE) 
  {
    LOG_ERROR("Failed to write match to packet-in message");
    of_packet_in_delete(of_packet_in);
    return INDIGO_ERROR_UNKNOWN;
  }

  if (of_packet_in_data_set(of_packet_in, &of_octets) != OF_ERROR_NONE) 
  {
    LOG_ERROR("Failed to write packet data to packet-in message");
    of_packet_in_delete(of_packet_in);
    return INDIGO_ERROR_UNKNOWN;
  }

  return indigo_core_packet_in(of_packet_in);
}

void ind_ofdpa_pkt_receive(void)
{
  indigo_error_t rc;
  uint32_t i;
  uint32_t maxPktSize;
  ofdpaPacket_t rxPkt;
  of_match_t match;
  struct timeval timeout;

  /* Determine how large receive buffer must be */
  if (ofdpaMaxPktSizeGet(&maxPktSize) != OFDPA_E_NONE)
  {
    LOG_ERROR("\nFailed to determine maximum receive packet size.\r\n");
    return;
  }

  memset(&rxPkt, 0, sizeof(ofdpaPacket_t));
  rxPkt.pktData.pstart = (char*) malloc(maxPktSize);
  if (rxPkt.pktData.pstart == NULL)
  {
    LOG_ERROR("\nFailed to allocate receive packet buffer\r\n");
    return;
  }
  rxPkt.pktData.size = maxPktSize;

  timeout.tv_sec = 0;
  timeout.tv_usec = 0;

  while (ofdpaPktReceive(&timeout, &rxPkt) == OFDPA_E_NONE)
  {
    LOG_TRACE("Client received packet");
    LOG_TRACE("Reason:  %d", rxPkt.reason);
    LOG_TRACE("Table ID:  %d", rxPkt.tableId);
    LOG_TRACE("Ingress port:  %u", rxPkt.inPortNum);
    LOG_TRACE("Size:  %u\r\n", rxPkt.pktData.size);
    for (i = 0; i < rxPkt.pktData.size; i++)
    {
      if (i && ((i % 16) == 0))
        LOG_TRACE("\r\n");
      LOG_TRACE("%02x ", (unsigned int) *(rxPkt.pktData.pstart + i));
    }
    LOG_TRACE("\r\n");

    ind_ofdpa_key_to_match(rxPkt.inPortNum, &match);

    rc = ind_ofdpa_fwd_pkt_in(rxPkt.inPortNum, rxPkt.pktData.pstart, 
                         (rxPkt.pktData.size - 4), rxPkt.reason, 
                         &match, rxPkt.tableId);

    if (rc != INDIGO_ERROR_NONE)
    {
      LOG_ERROR("Could not send Packet-in message, rc = 0x%x", rc);
    }
  }
  free(rxPkt.pktData.pstart);
  return;
}

/* It has been copied from modules/OFStateManager/utest/main.c */

void
indigo_fwd_pipeline_get(of_desc_str_t pipeline)
{
    LOG_TRACE("fwd switch pipeline get");
    strcpy(pipeline, "ofdpa_pipeline");
}

indigo_error_t
indigo_fwd_pipeline_set(of_desc_str_t pipeline)
{
    LOG_ERROR("fwd switch pipeline set: %s", pipeline);
    return INDIGO_ERROR_NOT_SUPPORTED;
}

void
indigo_fwd_pipeline_stats_get(of_desc_str_t **pipeline, int *num_pipelines)
{
    LOG_TRACE("fwd switch pipeline stats get");
    *num_pipelines = 0;
}
