#include <stdio.h>
#include <string.h>

#include "patch.h"


/**
 * Assumes that OFDPA has already been connected/initialized
 */

int DEFAULT_VLAN = 100;

int set_vlan(uint32_t port, int vlan, OFDPA_ERROR_t *rc);
int set_acl(int vlan, uint32_t src_port, uint32_t dst_port, OFDPA_ERROR_t *rc);

int
patch(uint32_t port1, uint32_t port2)
{
    int vlan = DEFAULT_VLAN;
    OFDPA_ERROR_t rc;
    int ret;

    if ((ret = set_vlan(port1, vlan, &rc)))
    {
        fprintf(stderr, "Failed to create vlan on port %d :: (%d,%d)\n", 
                port1, ret, rc);
        return -1;
    }
    if ((ret = set_vlan(port2, vlan, &rc)))
    {
        fprintf(stderr, "Failed to create vlan on port %d :: (%d,%d)\n", 
                port2, ret, rc);
        return -2;
    }

    if ((ret = set_acl(vlan, port1, port2, &rc)))
    {
        fprintf(stderr, "Failed to create ACL entry on port %d :: (%d,%d)\n", 
                port1, ret, rc);
        return -3;
    }
    if ((ret = set_acl(vlan, port2, port1, &rc)))
    {
        fprintf(stderr, "Failed to create ACL entry on port %d :: (%d,%d)\n", 
                port2, ret, rc);
        return -4;
    }

    return 0;
}


int
set_vlan(uint32_t port, int vlan, OFDPA_ERROR_t * rc)
{
    ofdpaFlowEntry_t flow;
    const int ACTION = 1;

    if ((*rc = ofdpaFlowEntryInit (OFDPA_FLOW_TABLE_ID_VLAN, &flow)) 
                != OFDPA_E_NONE)
    {
        return -1;
    } 

    /** First setup tagged traffic through */
    memset(&flow.flowData, 0, sizeof(flow.flowData));
    flow.flowData.vlanFlowEntry.match_criteria.inPort = port;
    flow.flowData.vlanFlowEntry.match_criteria.vlanId = vlan | OFDPA_VID_PRESENT;
    flow.flowData.vlanFlowEntry.match_criteria.vlanIdMask = 0x1fff; /* vid present */

    flow.flowData.vlanFlowEntry.gotoTableId = OFDPA_FLOW_TABLE_ID_TERMINATION_MAC;

    flow.flowData.vlanFlowEntry.setVlanIdAction = ACTION;
    flow.flowData.vlanFlowEntry.newVlanId = vlan;

    if ((*rc = ofdpaFlowAdd(&flow)) != OFDPA_E_NONE)
    {
        return -2;
    }

    /** Second setup untagged traffic */
    memset(&flow.flowData, 0, sizeof(flow.flowData));
    flow.flowData.vlanFlowEntry.match_criteria.inPort = port;
    flow.flowData.vlanFlowEntry.match_criteria.vlanIdMask = 0xfff; /* vid present */

    flow.flowData.vlanFlowEntry.gotoTableId = OFDPA_FLOW_TABLE_ID_TERMINATION_MAC;

    flow.flowData.vlanFlowEntry.setVlanIdAction = ACTION;
    flow.flowData.vlanFlowEntry.newVlanId = vlan;

    if ((*rc = ofdpaFlowAdd(&flow)) != OFDPA_E_NONE)
    {
        return -3;
    }

    return 0;
}


int
set_acl(int vlan, uint32_t src_port, uint32_t dst_port, OFDPA_ERROR_t * rc)
{
    ofdpaFlowEntry_t flow;
    ofdpaGroupEntry_t group;
    ofdpaGroupBucketEntry_t bucket;
    uint32_t groupID;

    if ((*rc = ofdpaFlowEntryInit (OFDPA_FLOW_TABLE_ID_ACL_POLICY, &flow)) 
                != OFDPA_E_NONE)
        return -1;

    if ((*rc = ofdpaGroupBucketEntryInit (OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE,
            &bucket)) != OFDPA_E_NONE)
        return -2;

    /** setup the group ID **/
    if ((*rc = ofdpaGroupTypeSet(&groupID,
                    OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE)) !=
                    OFDPA_E_NONE)
        return -3;

    /* yes, OFDPA encodes the vlan in the groupID */
    if ((*rc = ofdpaGroupVlanSet(&groupID, vlan)))  
        return -4;

    /* yes, OFDPA encodes the port in the groupID */
    if ((*rc = ofdpaGroupPortIdSet(&groupID, dst_port)))  
        return -5;

    if ((*rc = ofdpaGroupEntryInit(OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE, &group)))
        return -6;
           
    group.groupId = groupID;
    if ((*rc = ofdpaGroupAdd(&group)))
        return -7;
                    

    bucket.groupId = groupID;
    bucket.bucketData.l2Interface.outputPort = dst_port;
    bucket.bucketData.l2Interface.popVlanTag = 1;
    /* add group before bucket entry; else error */
    if ((*rc = ofdpaGroupBucketEntryAdd(&bucket)))
        return -8;



    /** Send all traffic from src_port to dst_port */
    memset(&flow.flowData, 0, sizeof(flow.flowData));
    flow.flowData.policyAclFlowEntry.match_criteria.inPort = src_port;
    flow.flowData.policyAclFlowEntry.match_criteria.inPortMask = OFDPA_INPORT_EXACT_MASK;

    flow.flowData.policyAclFlowEntry.groupID = groupID;

    if ((*rc = ofdpaFlowAdd(&flow)) != OFDPA_E_NONE)
    {
        return -6;
    }



    return 0;
}
