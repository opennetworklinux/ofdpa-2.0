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
* @filename     ind_ofdpa_groups.c
*
* @purpose      OF-DPA Driver for Indigo
*
* @component    OF-DPA
*
* @comments     none
*
* @create       6 Nov 2013
*
* @end
*
**********************************************************************/

#include <indigo/forwarding.h>
#include <indigo/of_state_manager.h>
#include <indigo_ofdpa_driver/ind_ofdpa_util.h>
#include <indigo_ofdpa_driver/ind_ofdpa_log.h>

static indigo_error_t
ind_ofdpa_translate_group_actions(of_list_action_t *actions, 
                                  ind_ofdpa_group_bucket_t *group_bucket,
                                  uint64_t *group_action_bitmap,
                                  uint64_t *group_action_sf_bitmap)
{
    of_action_t act;
    int rv;
    uint16_t vlanId;
    of_oxm_t oxm;   // of_oxm_t == of_object_t

    OF_LIST_ACTION_ITER(actions, &act, rv) {
        switch (act.object_id) {
        case OF_ACTION_OUTPUT: {
            of_port_no_t port_no;
            of_action_output_port_get(&act, &port_no);
            switch (port_no) {
                case OF_PORT_DEST_CONTROLLER:
                case OF_PORT_DEST_FLOOD:
                case OF_PORT_DEST_ALL:
                case OF_PORT_DEST_USE_TABLE:
                case OF_PORT_DEST_LOCAL:
                case OF_PORT_DEST_IN_PORT:
                case OF_PORT_DEST_NORMAL:
                    LOG_ERROR("unsupported output port 0x%x", port_no);
                    return INDIGO_ERROR_COMPAT;
                default: 
                    group_bucket->outputPort = port_no;
                    *group_action_bitmap |= IND_OFDPA_OUTPUT;
                  break;
            }
            break;
        }
        case OF_ACTION_SET_FIELD: {
            of_action_set_field_field_bind(&act, &oxm);
            switch (oxm.object_id) {
                case OF_OXM_VLAN_VID: 
                    of_oxm_vlan_vid_value_get(&oxm, &vlanId);
                    group_bucket->vlanId = vlanId & OFDPA_VID_EXACT_MASK;
                    *group_action_sf_bitmap |= IND_OFDPA_VLANID;
                    break;
                
                case OF_OXM_ETH_SRC: 
                    of_oxm_eth_src_value_get(&oxm, &group_bucket->srcMac);
                    *group_action_sf_bitmap |= IND_OFDPA_SRCMAC;
                    break;
                
                case OF_OXM_ETH_DST: 
                    of_oxm_eth_dst_value_get(&oxm, &group_bucket->dstMac);
                    *group_action_sf_bitmap |= IND_OFDPA_DSTMAC;
                    break;
                
                case OF_OXM_MPLS_LABEL: 
                    of_oxm_mpls_label_value_get(&oxm, &group_bucket->mplsLabel);
                    *group_action_sf_bitmap |= IND_OFDPA_MPLS_LABEL;
                    break;
                
                case OF_OXM_VLAN_PCP:
                {
                    uint8_t pcp;
                    of_oxm_vlan_pcp_value_get(&oxm, &pcp);
                    group_bucket->vlanPcp = pcp;
                    *group_action_sf_bitmap |= IND_OFDPA_VLAN_PCP;
                    break;
                }
#ifdef ROBS_HACK
                case OF_OXM_OFDPA_DEI:
                {
                    uint8_t dei;
                    of_oxm_ofdpa_dei_value_get(&oxm.ofdpa_dei, &dei);
                    group_bucket->vlanCfi = dei;
                    *group_action_sf_bitmap |= IND_OFDPA_VLAN_DEI;
                    break;
                }
#endif // ROBS_HACK
                case OF_OXM_IP_DSCP:
                {
                    uint8_t dscp;
                    of_oxm_ip_dscp_value_get(&oxm, &dscp);
                    group_bucket->dscp = dscp;
                    *group_action_sf_bitmap |= IND_OFDPA_IP_DSCP;
                    break;
                }
                case OF_OXM_MPLS_BOS:
                {
                    uint8_t bos;
                    of_oxm_mpls_bos_value_get(&oxm, &bos);
                    group_bucket->mplsBOS = bos;
                    *group_action_sf_bitmap |= IND_OFDPA_MPLS_BOS;
                    break;
                }
                case OF_OXM_MPLS_TC:
                {
                    uint8_t tc;
                    of_oxm_mpls_tc_value_get(&oxm, &tc);
                    group_bucket->mplsEXP = tc;
                    *group_action_sf_bitmap |= IND_OFDPA_MPLS_TC;
                    break;
                }
#ifdef ROBS_HACK
                case OF_OXM_OFDPA_MPLS_TTL:
                {
                    uint8_t ttl;
                    of_oxm_ofdpa_mpls_ttl_value_get(&oxm.ofdpa_mpls_ttl, &ttl);
                    group_bucket->mplsTTL = ttl;
                    *group_action_sf_bitmap |= IND_OFDPA_MPLS_TTL;
                    break;
                }
#endif // ROBS_HACK
                default:
                    LOG_ERROR("unsupported set-field oxm %s", of_object_id_str[oxm.object_id]);
                    return INDIGO_ERROR_COMPAT;
            }
            break;
        }
        case OF_ACTION_SET_DL_SRC: 
            break;

        case OF_ACTION_SET_DL_DST: 
            break;
        
        case OF_ACTION_SET_VLAN_VID: 
            break;
        
        case OF_ACTION_POP_VLAN:
            group_bucket->popVlanTag = 1;
            *group_action_bitmap |= IND_OFDPA_POP_VLAN;
            break;
        case OF_ACTION_STRIP_VLAN: 
            break;
            
        case OF_ACTION_PUSH_VLAN:
        {
            uint16_t eth_type;
            of_action_push_vlan_ethertype_get(&act, &eth_type);
            group_bucket->pushVlan = 1;
            group_bucket->newTpid = eth_type;
            *group_action_bitmap |= IND_OFDPA_PUSH_VLAN;
            break;
        }
        case OF_ACTION_PUSH_MPLS:
        {
            uint16_t ether_type;
            of_action_push_mpls_ethertype_get(&act, &ether_type);
            group_bucket->pushMplsHdr = 1;
            group_bucket->mplsEtherType = ether_type;
            *group_action_bitmap |= IND_OFDPA_PUSH_MPLS;
            break;
        }
        case OF_ACTION_SET_MPLS_TTL:
        {
            uint8_t ttl;
            of_action_set_mpls_ttl_mpls_ttl_get(&act, &ttl);
            group_bucket->mplsTTL = ttl;
            *group_action_bitmap |= IND_OFDPA_SET_MPLS_TTL;
            break;
        }
        case OF_ACTION_COPY_TTL_OUT:
            group_bucket->mplsCopyTTLOutwards = 1;
            *group_action_bitmap |= IND_OFDPA_COPY_TTL_OUT;
            break;
#ifdef ROBS_HACK
        case OF_ACTION_OFDPA_PUSH_L2HDR:
            group_bucket->pushL2Hdr = 1;
            *group_action_bitmap |= IND_OFDPA_PUSH_L2_HDR;
            break;
        case OF_ACTION_OFDPA_PUSH_CW:
            group_bucket->pushCW = 1;
            *group_action_bitmap |= IND_OFDPA_PUSH_CW;
            break;
        
        case OF_ACTION_OFDPA_COPY_TC_OUT:
            group_bucket->mplsCopyEXPOutwards = 1;
            *group_action_bitmap |= IND_OFDPA_COPY_MPLS_TC_OUT;
            break;
        
        case OF_ACTION_OFDPA_SET_TC_FROM_TABLE:
        {
            uint8_t qosIndex;
            of_action_ofdpa_set_tc_from_table_qos_index_get(&act.ofdpa_set_tc_from_table, &qosIndex);
            group_bucket->mplsEXPRemarkTableIndex = qosIndex;
            *group_action_bitmap |= IND_OFDPA_MPLS_TC_REMARK_TABLE_INDEX;
            break;
        }
        case OF_ACTION_OFDPA_SET_PCPDEI_FROM_TABLE:
        {
            uint8_t qosIndex;
            of_action_ofdpa_set_pcpdei_from_table_qos_index_get(&act.ofdpa_set_pcpdei_from_table, &qosIndex);
            group_bucket->priorityRemarkTableIndex = qosIndex;
            *group_action_bitmap |= IND_OFDPA_PCP_REMARK_TABLE_INDEX;
            break;
        }
        case OF_ACTION_OFDPA_SET_DSCP_FROM_TABLE:
        {
            uint8_t qosIndex;
            of_action_ofdpa_set_dscp_from_table_qos_index_get(&act.ofdpa_set_dscp_from_table, &qosIndex);
            group_bucket->dscpRemarkTableIndex = qosIndex;
            *group_action_bitmap |= IND_OFDPA_DSCP_REMARK_TABLE_INDEX;
            break;
        }
#endif // ROBS_HACK        
        case OF_ACTION_GROUP: 
            of_action_group_group_id_get(&act, &group_bucket->referenceGroupId);
            *group_action_bitmap |= IND_OFDPA_REFGROUP;
            break;
#ifdef ROBS_HACK
        case OF_ACTION_OFDPA_OAM_LM_TX_COUNT:
        {
            uint32_t lmepId;
            of_action_ofdpa_oam_lm_tx_count_lmep_id_get(&act.ofdpa_oam_lm_tx_count, &lmepId);
            group_bucket->lmepId = lmepId;
            *group_action_bitmap |= IND_OFDPA_OAM_LM_TX_COUNT;
            break;
        }
#endif // ROBS_HACK
        
        default:
            LOG_ERROR("unsupported action %s", of_object_id_str[act.object_id]);
            return INDIGO_ERROR_COMPAT;
        }
    }

    LOG_TRACE("group_action_bitmap is 0x%llX, group_action_sf_bitmap is 0x%llX", 
        *group_action_bitmap, *group_action_sf_bitmap);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
ind_ofdpa_translate_group_buckets(uint32_t group_id, 
                                  of_list_bucket_t *of_buckets,
                                  uint16_t command)
{
  indigo_error_t err;
  uint16_t bucket_index = 0;
  of_list_action_t of_actions;
  of_bucket_t of_bucket;
  ind_ofdpa_group_bucket_t group_bucket;
  int rv;
  uint32_t group_type, sub_group_type;
  uint64_t group_action_bitmap = 0;
  uint64_t group_action_sf_bitmap = 0;
  ofdpaGroupEntry_t group_entry;
  ofdpaGroupBucketEntry_t group_bucket_entry;
  OFDPA_ERROR_t ofdpa_rv = OFDPA_E_FAIL;
  int group_added = 0;
  of_port_no_t watch_port;

  OF_LIST_BUCKET_ITER(of_buckets, &of_bucket, rv) 
  {
    of_bucket_watch_port_get(&of_bucket,&watch_port);
    
    of_bucket_actions_bind(&of_bucket, &of_actions);

    memset(&group_bucket, 0, sizeof(group_bucket));

    err = ind_ofdpa_translate_group_actions(
        &of_actions, &group_bucket, &group_action_bitmap, &group_action_sf_bitmap);
    if (err < 0) 
    {
      LOG_ERROR("Error in translating group actions");
      if (group_added == 1) 
      {
        /* Delete the added group */
        (void)ofdpaGroupDelete(group_id);
      }
      return err;
    }

    ofdpaGroupTypeGet(group_id, &group_type);

    memset(&group_bucket_entry, 0, sizeof(group_bucket_entry));
    group_bucket_entry.groupId = group_id;
    group_bucket_entry.bucketIndex = bucket_index;

    err = INDIGO_ERROR_NONE;

    switch (group_type)
    {
      case OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE:
        if((group_action_bitmap | IND_OFDPA_L2INTF_BITMAP) != IND_OFDPA_L2INTF_BITMAP)
        {
          err = INDIGO_ERROR_COMPAT;
          break;
        }
        if((group_action_sf_bitmap | IND_OFDPA_L2INTF_SF_BITMAP) != IND_OFDPA_L2INTF_SF_BITMAP)
        {
          err = INDIGO_ERROR_COMPAT;
          break;
        }
        group_bucket_entry.bucketData.l2Interface.outputPort = group_bucket.outputPort;
        group_bucket_entry.bucketData.l2Interface.popVlanTag = group_bucket.popVlanTag;

        if (group_action_sf_bitmap & IND_OFDPA_VLAN_PCP)
        {
          group_bucket_entry.bucketData.l2Interface.vlanPcpAction = 1;
          group_bucket_entry.bucketData.l2Interface.vlanPcp = group_bucket.vlanPcp;
        }
        if (group_action_sf_bitmap & IND_OFDPA_VLAN_DEI)
        {
          group_bucket_entry.bucketData.l2Interface.vlanCfiAction = 1;
          group_bucket_entry.bucketData.l2Interface.vlanCfi = group_bucket.vlanCfi;
        }
        if (group_action_bitmap & IND_OFDPA_PCP_REMARK_TABLE_INDEX)
        {
          group_bucket_entry.bucketData.l2Interface.priorityRemarkTableIndexAction = 1;
          group_bucket_entry.bucketData.l2Interface.priorityRemarkTableIndex = group_bucket.priorityRemarkTableIndex;
        }

        if (group_action_sf_bitmap & IND_OFDPA_IP_DSCP)
        {
          group_bucket_entry.bucketData.l2Interface.dscpAction = 1;
          group_bucket_entry.bucketData.l2Interface.dscp = group_bucket.dscp;
        }
        if (group_action_bitmap & IND_OFDPA_DSCP_REMARK_TABLE_INDEX)
        {
          group_bucket_entry.bucketData.l2Interface.dscpRemarkTableIndexAction = 1;
          group_bucket_entry.bucketData.l2Interface.dscpRemarkTableIndex = group_bucket.dscpRemarkTableIndex;
        }
        
        break;

      case OFDPA_GROUP_ENTRY_TYPE_L2_UNFILTERED_INTERFACE:
        if((group_action_bitmap | IND_OFDPA_L2_UNFILTERED_INTF_BITMAP) != IND_OFDPA_L2_UNFILTERED_INTF_BITMAP)
        {
          err = INDIGO_ERROR_COMPAT;
          break;
        }
        if((group_action_sf_bitmap | IND_OFDPA_L2_UNFILTERED_INTF_SF_BITMAP) != IND_OFDPA_L2_UNFILTERED_INTF_SF_BITMAP)
        {
          err = INDIGO_ERROR_COMPAT;
          break;
        }
        group_bucket_entry.bucketData.l2UnfilteredInterface.outputPort = group_bucket.outputPort;

        
        if (group_action_sf_bitmap & IND_OFDPA_VLAN_PCP)
        {
          group_bucket_entry.bucketData.l2UnfilteredInterface.vlanPcpAction = 1;
          group_bucket_entry.bucketData.l2UnfilteredInterface.vlanPcp = group_bucket.vlanPcp;
        }
        if (group_action_sf_bitmap & IND_OFDPA_VLAN_DEI)
        {
          group_bucket_entry.bucketData.l2UnfilteredInterface.vlanCfiAction = 1;
          group_bucket_entry.bucketData.l2UnfilteredInterface.vlanCfi = group_bucket.vlanCfi;
        }
        if (group_action_bitmap & IND_OFDPA_PCP_REMARK_TABLE_INDEX)
        {
          group_bucket_entry.bucketData.l2UnfilteredInterface.priorityRemarkTableIndexAction = 1;
          group_bucket_entry.bucketData.l2UnfilteredInterface.priorityRemarkTableIndex = group_bucket.priorityRemarkTableIndex;
        }

        if (group_action_sf_bitmap & IND_OFDPA_IP_DSCP)
        {
          group_bucket_entry.bucketData.l2UnfilteredInterface.dscpAction = 1;
          group_bucket_entry.bucketData.l2UnfilteredInterface.dscp = group_bucket.dscp;
        }
        if (group_action_bitmap & IND_OFDPA_DSCP_REMARK_TABLE_INDEX)
        {
          group_bucket_entry.bucketData.l2UnfilteredInterface.dscpRemarkTableIndexAction = 1;
          group_bucket_entry.bucketData.l2UnfilteredInterface.dscpRemarkTableIndex = group_bucket.dscpRemarkTableIndex;
        }

        break;

      case OFDPA_GROUP_ENTRY_TYPE_L2_REWRITE:
        if((group_action_bitmap | IND_OFDPA_L2REWRITE_BITMAP) != IND_OFDPA_L2REWRITE_BITMAP)
        {
          err = INDIGO_ERROR_COMPAT;
          break;
        }
        if((group_action_sf_bitmap | IND_OFDPA_L2REWRITE_SF_BITMAP) != IND_OFDPA_L2REWRITE_SF_BITMAP)
        {
          err = INDIGO_ERROR_COMPAT;
          break;
        }

        group_bucket_entry.bucketData.l2Rewrite.vlanId = group_bucket.vlanId;

        memcpy(&group_bucket_entry.bucketData.l2Rewrite.srcMac,
               &group_bucket.srcMac, sizeof(group_bucket_entry.bucketData.l2Rewrite.srcMac));

        memcpy(&group_bucket_entry.bucketData.l2Rewrite.dstMac,
               &group_bucket.dstMac, sizeof(group_bucket_entry.bucketData.l2Rewrite.dstMac));

        group_bucket_entry.referenceGroupId = group_bucket.referenceGroupId;

        break;

      case OFDPA_GROUP_ENTRY_TYPE_L3_UNICAST:
        if((group_action_bitmap | IND_OFDPA_L3UNICAST_BITMAP) != IND_OFDPA_L3UNICAST_BITMAP)
        {
          err = INDIGO_ERROR_COMPAT;
          break;
        }
        if((group_action_sf_bitmap | IND_OFDPA_L3UNICAST_SF_BITMAP) != IND_OFDPA_L3UNICAST_SF_BITMAP)
        {
          err = INDIGO_ERROR_COMPAT;
          break;
        }

        group_bucket_entry.bucketData.l3Unicast.vlanId = group_bucket.vlanId;

        memcpy(&group_bucket_entry.bucketData.l3Unicast.srcMac,
               &group_bucket.srcMac, sizeof(group_bucket_entry.bucketData.l3Unicast.srcMac));

        memcpy(&group_bucket_entry.bucketData.l3Unicast.dstMac,
               &group_bucket.dstMac, sizeof(group_bucket_entry.bucketData.l3Unicast.dstMac));

        group_bucket_entry.referenceGroupId = group_bucket.referenceGroupId;

        break;

      case OFDPA_GROUP_ENTRY_TYPE_L3_INTERFACE:
        if((group_action_bitmap | IND_OFDPA_L3INTERFACE_BITMAP) != IND_OFDPA_L3INTERFACE_BITMAP)
        {
          err = INDIGO_ERROR_COMPAT;
          break;
        }
        if((group_action_sf_bitmap | IND_OFDPA_L3INTERFACE_SF_BITMAP) != IND_OFDPA_L3INTERFACE_SF_BITMAP)
        {
          err = INDIGO_ERROR_COMPAT;
          break;
        }

        group_bucket_entry.bucketData.l3Interface.vlanId = group_bucket.vlanId;

        memcpy(&group_bucket_entry.bucketData.l3Interface.srcMac,
               &group_bucket.srcMac, sizeof(group_bucket_entry.bucketData.l3Interface.srcMac));

        group_bucket_entry.referenceGroupId = group_bucket.referenceGroupId;

        break;

      case OFDPA_GROUP_ENTRY_TYPE_L2_MULTICAST:
      case OFDPA_GROUP_ENTRY_TYPE_L2_FLOOD:
      case OFDPA_GROUP_ENTRY_TYPE_L3_MULTICAST:
      case OFDPA_GROUP_ENTRY_TYPE_L3_ECMP:
        if((group_action_bitmap | IND_OFDPA_REFGROUP) != IND_OFDPA_REFGROUP)
        {
          err = INDIGO_ERROR_COMPAT;
          break;
        }

        group_bucket_entry.referenceGroupId = group_bucket.referenceGroupId;
        break;

      case OFDPA_GROUP_ENTRY_TYPE_L2_OVERLAY:
        if((group_action_bitmap | IND_OFDPA_L2OVERLAY_BITMAP) != IND_OFDPA_L2OVERLAY_BITMAP)
        {
          err = INDIGO_ERROR_COMPAT;
          break;
        }

        group_bucket_entry.bucketData.l2Overlay.outputPort = group_bucket.outputPort;
        break;

      case OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL:
        ofdpaGroupMplsSubTypeGet(group_id, &sub_group_type);
        switch (sub_group_type)
        {
          case OFDPA_MPLS_INTERFACE:
            if((group_action_bitmap | IND_OFDPA_MPLSINTERFACE_BITMAP) != IND_OFDPA_MPLSINTERFACE_BITMAP)
            {
              err = INDIGO_ERROR_COMPAT;
              break;
            }
            
            memcpy(&group_bucket_entry.bucketData.mplsInterface.srcMac,
                   &group_bucket.srcMac, sizeof(group_bucket_entry.bucketData.mplsInterface.srcMac));
            memcpy(&group_bucket_entry.bucketData.mplsInterface.dstMac,
                   &group_bucket.dstMac, sizeof(group_bucket_entry.bucketData.mplsInterface.dstMac));
            group_bucket_entry.bucketData.mplsInterface.vlanId = group_bucket.vlanId;

            if (group_action_bitmap & IND_OFDPA_OAM_LM_TX_COUNT)
            {
              group_bucket_entry.bucketData.mplsInterface.oamLmTxCountAction = 1;
              group_bucket_entry.bucketData.mplsInterface.lmepId = group_bucket.lmepId;
            }

            group_bucket_entry.referenceGroupId = group_bucket.referenceGroupId;
            break;
            
          case OFDPA_MPLS_L2_VPN_LABEL:
          case OFDPA_MPLS_L3_VPN_LABEL:
          case OFDPA_MPLS_TUNNEL_LABEL1:
          case OFDPA_MPLS_TUNNEL_LABEL2:
          case OFDPA_MPLS_SWAP_LABEL:
            if((group_action_bitmap | IND_OFDPA_MPLSLABEL_BITMAP) != IND_OFDPA_MPLSLABEL_BITMAP)
            {
              err = INDIGO_ERROR_COMPAT;
              break;
            }
            if((group_action_sf_bitmap | IND_OFDPA_MPLSLABEL_SF_BITMAP) != IND_OFDPA_MPLSLABEL_SF_BITMAP)
            {
              err = INDIGO_ERROR_COMPAT;
              break;
            }
            
            group_bucket_entry.bucketData.mplsLabel.pushL2Hdr = group_bucket.pushL2Hdr;
            
            if (group_action_bitmap & IND_OFDPA_PUSH_VLAN)
            {
              group_bucket_entry.bucketData.mplsLabel.pushVlan = 1;
              group_bucket_entry.bucketData.mplsLabel.newTpid = group_bucket.newTpid;
            }
            
            if (group_action_bitmap & IND_OFDPA_PUSH_MPLS)
            {
              group_bucket_entry.bucketData.mplsLabel.pushMplsHdr = 1;
              group_bucket_entry.bucketData.mplsLabel.mplsEtherType = group_bucket.mplsEtherType;
            }
            
            group_bucket_entry.bucketData.mplsLabel.pushCW = group_bucket.pushCW;
            
            group_bucket_entry.bucketData.mplsLabel.mplsLabel = group_bucket.mplsLabel;
            
            group_bucket_entry.bucketData.mplsLabel.mplsBOS = group_bucket.mplsBOS;
            
            group_bucket_entry.bucketData.mplsLabel.mplsCopyEXPOutwards = group_bucket.mplsCopyEXPOutwards;
            if (group_action_sf_bitmap & IND_OFDPA_MPLS_TC)
            {
              group_bucket_entry.bucketData.mplsLabel.mplsEXPAction = 1;
              group_bucket_entry.bucketData.mplsLabel.mplsEXP = group_bucket.mplsEXP;
            }
            if (group_action_bitmap & IND_OFDPA_MPLS_TC_REMARK_TABLE_INDEX)
            {
              group_bucket_entry.bucketData.mplsLabel.mplsEXPRemarkTableIndexAction = 1;
              group_bucket_entry.bucketData.mplsLabel.mplsEXPRemarkTableIndex = group_bucket.mplsEXPRemarkTableIndex;
            }
            
            group_bucket_entry.bucketData.mplsLabel.mplsCopyTTLOutwards = group_bucket.mplsCopyTTLOutwards;
            if (group_action_bitmap & IND_OFDPA_SET_MPLS_TTL)
            {
              group_bucket_entry.bucketData.mplsLabel.mplsTTLAction = 1;
              group_bucket_entry.bucketData.mplsLabel.mplsTTL = group_bucket.mplsTTL;
            }
            if (group_action_sf_bitmap & IND_OFDPA_MPLS_TTL)
            {
              group_bucket_entry.bucketData.mplsLabel.mplsTTLAction = 1;
              group_bucket_entry.bucketData.mplsLabel.mplsTTL = group_bucket.mplsTTL;
            }
            
            if (group_action_bitmap & IND_OFDPA_PCP_REMARK_TABLE_INDEX)
            {
              group_bucket_entry.bucketData.mplsLabel.mplsPriorityRemarkTableIndexAction = 1;
              group_bucket_entry.bucketData.mplsLabel.mplsPriorityRemarkTableIndex = group_bucket.priorityRemarkTableIndex;
            }

            if (group_action_bitmap & IND_OFDPA_OAM_LM_TX_COUNT)
            {
              group_bucket_entry.bucketData.mplsLabel.oamLmTxCountAction = 1;
              group_bucket_entry.bucketData.mplsLabel.lmepId = group_bucket.lmepId;
            }

            group_bucket_entry.referenceGroupId = group_bucket.referenceGroupId;
            break;
            
          default:
            LOG_ERROR("unsupported MPLS_SUBTYPE %d for GROUP_TYPE %d", sub_group_type, group_type);
            return INDIGO_ERROR_COMPAT;
        }
        break;
        
      case OFDPA_GROUP_ENTRY_TYPE_MPLS_FORWARDING:
        ofdpaGroupMplsSubTypeGet(group_id, &sub_group_type);
        switch (sub_group_type)
        {
          case OFDPA_MPLS_FAST_FAILOVER:
            if((group_action_bitmap | IND_OFDPA_MPLSFF_BITMAP) != IND_OFDPA_MPLSFF_BITMAP)
            {
              err = INDIGO_ERROR_COMPAT;
              break;
            }
            
            group_bucket_entry.referenceGroupId = group_bucket.referenceGroupId;
            group_bucket_entry.bucketData.mplsFastFailOver.watchPort = watch_port;
            break;
            
          case OFDPA_MPLS_L2_TAG:
            if((group_action_bitmap | IND_OFDPA_MPLSL2TAG_BITMAP) != IND_OFDPA_MPLSL2TAG_BITMAP)
            {
              err = INDIGO_ERROR_COMPAT;
              break;
            }
            if((group_action_sf_bitmap | IND_OFDPA_MPLSL2TAG_SF_BITMAP) != IND_OFDPA_MPLSL2TAG_SF_BITMAP)
            {
              err = INDIGO_ERROR_COMPAT;
              break;
            }
            
            if (group_action_bitmap & IND_OFDPA_POP_VLAN)
            {
              group_bucket_entry.bucketData.mplsL2Tag.popVlan = 1;
            }
            if (group_action_bitmap & IND_OFDPA_PUSH_VLAN)
            {
              group_bucket_entry.bucketData.mplsL2Tag.pushVlan = 1;
              group_bucket_entry.bucketData.mplsL2Tag.newTpid = group_bucket.newTpid;
            }
            group_bucket_entry.bucketData.mplsL2Tag.vlanId = group_bucket.vlanId;
            
            group_bucket_entry.referenceGroupId = group_bucket.referenceGroupId;
            
            break;
            
          case OFDPA_MPLS_L2_FLOOD:
          case OFDPA_MPLS_L2_MULTICAST:
          case OFDPA_MPLS_L2_LOCAL_FLOOD:
          case OFDPA_MPLS_L2_LOCAL_MULTICAST:
          case OFDPA_MPLS_L2_FLOOD_SPLIT_HORIZON:
          case OFDPA_MPLS_L2_MULTICAST_SPLIT_HORIZON:
          case OFDPA_MPLS_1_1_HEAD_END_PROTECT:
          case OFDPA_MPLS_ECMP: 
            if((group_action_bitmap | IND_OFDPA_REFGROUP) != IND_OFDPA_REFGROUP)
            {
              err = INDIGO_ERROR_COMPAT;
              break;
            }
            
            group_bucket_entry.referenceGroupId = group_bucket.referenceGroupId;
            
            break;
            
          default:
            LOG_ERROR("unsupported MPLS_SUBTYPE %d for GROUP_TYPE %d", sub_group_type, group_type);
            return INDIGO_ERROR_COMPAT;
        }
        break;

      default:
        err = INDIGO_ERROR_PARAM;
        LOG_ERROR("Invalid GROUP_TYPE %d", group_type);
        break;
    }

    if (err != INDIGO_ERROR_NONE)
    {
      if (err == INDIGO_ERROR_COMPAT)
      {
        LOG_ERROR("Incompatible fields for Group Type");
      }
      if (group_added == 1) 
      {
        /* Delete the added group */
        (void)ofdpaGroupDelete(group_id);
      }
      return err; 
    }

    if (command == OF_GROUP_ADD) 
    {
      if (bucket_index == 0)
      {
        /* First Bucket; Add Group first*/
        group_entry.groupId = group_id;
        ofdpa_rv = ofdpaGroupAdd(&group_entry);
        if (ofdpa_rv != OFDPA_E_NONE)
        {
          LOG_ERROR("Error in adding Group, rv = %d",ofdpa_rv);
          break;
        }
        group_added = 1;
      }
    }
    else /* OF_GROUP_MODIFY */
    {
      if (bucket_index == 0)
      {
        /* First Bucket; Delete all buckets first */
        ofdpa_rv = ofdpaGroupBucketsDeleteAll(group_id);
        if (ofdpa_rv != OFDPA_E_NONE)
        {
          LOG_ERROR("Error in deleting Group buckets, rv = %d",ofdpa_rv);
          break;
        }
      }
    }

    ofdpa_rv = ofdpaGroupBucketEntryAdd(&group_bucket_entry);
    if (ofdpa_rv != OFDPA_E_NONE)
    {
      LOG_ERROR("Error in adding Group bucket, rv = %d",ofdpa_rv);
      if (group_added == 1) 
      {
        /* Delete the added group */
        (void)ofdpaGroupDelete(group_id);
      }
      else /* OF_GROUP_MODIFY */
      {
        /* Need to clean up and delete Group here as well.
           Will be done by the caller as the Group also needs to
           be deleted from the Indigo database. */
      }
      break;
    }

    bucket_index++;
  }

  return indigoConvertOfdpaRv(ofdpa_rv);
}

static indigo_error_t
group_create(void *table_priv, indigo_cxn_id_t cxn_id,
             uint32_t group_id, uint8_t group_type, of_list_bucket_t *buckets,
             void **entry_priv)
{
  indigo_error_t err;

  if ((group_type != OF_GROUP_TYPE_INDIRECT) &&
      (group_type != OF_GROUP_TYPE_SELECT) &&
      (group_type != OF_GROUP_TYPE_FF) &&
      (group_type != OF_GROUP_TYPE_ALL)) 
  {
    return INDIGO_ERROR_NOT_SUPPORTED;
  }

  err = ind_ofdpa_translate_group_buckets(group_id, buckets, OF_GROUP_ADD);

  *entry_priv = INDIGO_COOKIE_TO_POINTER(group_id);

  return err;
}

static indigo_error_t
group_modify(void *table_priv,
             indigo_cxn_id_t cxn_id,
             void *entry_priv,
             of_list_bucket_t *buckets)
{
  indigo_error_t err;
  uint32_t id = INDIGO_POINTER_TO_COOKIE(entry_priv);

  err = ind_ofdpa_translate_group_buckets(id, buckets, OF_GROUP_MODIFY);

  return err;
}

static indigo_error_t
group_delete(void *table_priv, indigo_cxn_id_t cxn_id,
             void *entry_priv)
{
  OFDPA_ERROR_t ofdpa_rv;
  uint32_t id = INDIGO_POINTER_TO_COOKIE(entry_priv);

  ofdpa_rv = ofdpaGroupDelete(id);

  if (ofdpa_rv != OFDPA_E_NONE)
  {
    LOG_ERROR("Group Delete failed, rv = %d",ofdpa_rv);
  }
  
  return indigoConvertOfdpaRv(ofdpa_rv);
}

static indigo_error_t
group_stats_get(void *table_priv, void *entry_priv,
                of_group_stats_entry_t *entry)
{
  OFDPA_ERROR_t ofdpa_rv;
  ofdpaGroupEntryStats_t groupStats;
  uint32_t id = INDIGO_POINTER_TO_COOKIE(entry_priv);

  memset(&groupStats, 0, sizeof(groupStats));
  ofdpa_rv = ofdpaGroupStatsGet(id, &groupStats);

  if (ofdpa_rv != OFDPA_E_NONE)
  {
    LOG_ERROR("Failed to get Group stats, rv = %d",ofdpa_rv);
  }
  else
  {
    of_group_stats_entry_ref_count_set(entry, groupStats.refCount);
    of_group_stats_entry_duration_sec_set(entry, groupStats.duration);
  }

  return indigoConvertOfdpaRv(ofdpa_rv);
}

static const indigo_core_group_table_ops_t group_table_ops = {
    .entry_create = group_create,
    .entry_modify = group_modify,
    .entry_delete = group_delete,
    .entry_stats_get = group_stats_get,
};

void
ind_ofdpa_group_init(void)
{
    /*
     * OFDPA uses the top 4 bits as the group table ID, where Indigo
     * uses the top 8 bits. The ops for every table are the same
     * so we just register all 256 tables.
     */
    int i;
    for (i = 0; i < 256; i++) {
        indigo_core_group_table_register(i, "group", &group_table_ops, NULL);
    }
}

