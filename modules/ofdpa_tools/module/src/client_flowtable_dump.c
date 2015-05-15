/*********************************************************************
*
* (C) Copyright Broadcom Corporation 2003-2014
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
* @filename     client_flowtable_dump.c
*
* @purpose      Dump flow tables. Uses RPC calls.
*
* @component    Unit Test
*
* @comments
*
* @create
*
* @end
*
**********************************************************************/
#include "ofdpa_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_COUNT        0

const char *argp_program_version = "client_flowtable_dump v1.1";

/* The options we understand. */
static struct argp_option options[] =
{
  { "count",               'c', "COUNT",     0, "Number of entries from start of table. (0 for all)",       0 },
  { "verbose",             'v',       0,     0, "Print stats for empty flow tables.",                       0 },
  { "list",                'l',       0,     0, "Lists table IDs for supported flow tables and exits.",     0 },
  { 0 }
};

static int count;
static OFDPA_FLOW_TABLE_ID_t tableId;
static int tableIdSpecified = 0;
static int showEmptyTables = 0;
static int showValidTableIds = 0;

/* forward references */
void printIngressPortFlow(ofdpaFlowEntry_t *flow);
void printDscpTrustFlow(ofdpaFlowEntry_t *flow);
void printPcpTrustFlow(ofdpaFlowEntry_t *flow);
void printVlanFlow(ofdpaFlowEntry_t *flow);
void printVlan1Flow(ofdpaFlowEntry_t *flow);
void printMplsL2PortFlow(ofdpaFlowEntry_t *flow);
void printTermMacFlow(ofdpaFlowEntry_t *flow);
void printMplsFlow(ofdpaFlowEntry_t *flow);
void printMplsMaintenencePointFlow(ofdpaFlowEntry_t *flow);
void printUnicastRoutingFlow(ofdpaFlowEntry_t *flow);
void printMulticastRoutingFlow(ofdpaFlowEntry_t *flow);
void printBridgingFlow(ofdpaFlowEntry_t *flow);
void printPolicyAclFlow(ofdpaFlowEntry_t *flow);
void printEgressVlanFlow(ofdpaFlowEntry_t *flow);
void printEgressVlan1Flow(ofdpaFlowEntry_t *flow);
void printMplsQosFlow(ofdpaFlowEntry_t *flow);

typedef void flowPrintFcn_t(ofdpaFlowEntry_t *flow);

typedef struct
{
  OFDPA_FLOW_TABLE_ID_t type;
  char *name;
  flowPrintFcn_t *flowEntryPrintFcn;
} tableList_t;

tableList_t tableList[] =
{
  { OFDPA_FLOW_TABLE_ID_INGRESS_PORT,      "Ingress Port",                    printIngressPortFlow },
  { OFDPA_FLOW_TABLE_ID_PORT_DSCP_TRUST,   "Port DSCP Trust",                 printDscpTrustFlow },
  { OFDPA_FLOW_TABLE_ID_PORT_PCP_TRUST,    "Port PCP Trust",                  printPcpTrustFlow },
  { OFDPA_FLOW_TABLE_ID_TUNNEL_DSCP_TRUST, "Tunnel DSCP Trust",               printDscpTrustFlow },
  { OFDPA_FLOW_TABLE_ID_TUNNEL_PCP_TRUST,  "Tunnel PCP Trust",                printPcpTrustFlow },
  { OFDPA_FLOW_TABLE_ID_VLAN,              "VLAN",                            printVlanFlow },
  { OFDPA_FLOW_TABLE_ID_VLAN_1,            "VLAN 1",                          printVlan1Flow },
  { OFDPA_FLOW_TABLE_ID_MAINTENANCE_POINT, "Maintenance Point",               NULL },
  { OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT,      "MPLS L2 Port",                    printMplsL2PortFlow },
  { OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST,   "MPLS DSCP Trust",                 printDscpTrustFlow },
  { OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST,    "MPLS PCP Trust",                  printPcpTrustFlow },
  { OFDPA_FLOW_TABLE_ID_TERMINATION_MAC,   "Termination MAC",                 printTermMacFlow },
  { OFDPA_FLOW_TABLE_ID_MPLS_0,            "MPLS 0",                          printMplsFlow },
  { OFDPA_FLOW_TABLE_ID_MPLS_1,            "MPLS 1",                          printMplsFlow },
  { OFDPA_FLOW_TABLE_ID_MPLS_2,            "MPLS 2",                          printMplsFlow },
  { OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT, "MPLS Maintenance Point",     printMplsMaintenencePointFlow },
  { OFDPA_FLOW_TABLE_ID_BFD,               "BFD",                             NULL },
  { OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING,   "Unicast Routing",                 printUnicastRoutingFlow },
  { OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING, "Multicast Routing",               printMulticastRoutingFlow },
  { OFDPA_FLOW_TABLE_ID_BRIDGING,          "Bridging",                        printBridgingFlow },
  { OFDPA_FLOW_TABLE_ID_ACL_POLICY,        "ACL Policy",                      printPolicyAclFlow },
  { OFDPA_FLOW_TABLE_ID_EGRESS_VLAN,       "Egress VLAN",                     printEgressVlanFlow },
  { OFDPA_FLOW_TABLE_ID_EGRESS_VLAN_1,     "Egress VLAN 1",                   printEgressVlan1Flow },
  { OFDPA_FLOW_TABLE_ID_EGRESS_MAINTENANCE_POINT, "Egress Maintenance Point", NULL },
  { OFDPA_FLOW_TABLE_ID_MPLS_QOS,          "MPLS QOS",                        printMplsQosFlow }
};
#define TABLE_NAME_LIST_SIZE (sizeof(tableList)/sizeof(tableList[0]))

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  OFDPA_ERROR_t rc;

  switch (key)
  {
    case 'c':                           /* count */
      errno = 0;
      count = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid count \"%s\"", arg);
        return errno;
      }
      break;

    case 'l':
      showValidTableIds = 1;
      break;

    case 'v':
      showEmptyTables = 1;
      break;

    case ARGP_KEY_ARG:
      errno = 0;
      tableId = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid table ID argument\"%s\"", arg);
        return errno;
      }
      rc = ofdpaFlowTableSupported(tableId);
      if (rc != OFDPA_E_NONE)
      {
        argp_error(state, "Unsupported table ID (%d) (ofdpaFlowTableSupported() returns %d)", tableId, rc);
        return ENOTSUP;
      }

      tableIdSpecified = 1;
      break;

    case ARGP_KEY_NO_ARGS:
      break;

    case ARGP_KEY_END:
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

char *flowTableNameGet(OFDPA_FLOW_TABLE_ID_t tableId)
{
  int i;

  for (i = 0; i < TABLE_NAME_LIST_SIZE; i++)
  {
    if (tableList[i].type == tableId)
    {
      return(tableList[i].name);
    }
  }
  return("[Table name not found]");
}

flowPrintFcn_t *flowEntryPrintFcnGet(OFDPA_FLOW_TABLE_ID_t tableId)
{
  int i;

  for (i = 0; i < TABLE_NAME_LIST_SIZE; i++)
  {
    if (tableList[i].type == tableId)
    {
      return(tableList[i].flowEntryPrintFcn);
    }
  }
  return(NULL);
}

char *gotoFlowTableNameGet(OFDPA_FLOW_TABLE_ID_t tableId)
{
  /* when used as a Goto table value, return "None" instead of the name for TableId == 0 */
  return(tableId ? flowTableNameGet(tableId) : "None");
}

void qosColorNameGet(OFDPA_QOS_COLORS_t color, char *name)
{
  switch (color)
  {
    case OFDPA_QOS_GREEN:
      strcpy(name, "green");
      break;

    case OFDPA_QOS_YELLOW:
      strcpy(name, "yellow");
      break;

    case OFDPA_QOS_RED:
      strcpy(name, "red");
      break;

    default:
      strcpy(name, "Invalid color");
      break;
  }
}

int isMacZero(ofdpaMacAddr_t *macAddr)
{
  int i;

  for (i = 0; i < sizeof(macAddr->addr); i++)
  {
    if (macAddr->addr[i] != 0)
    {
      return 0;
    }
  }
  return 1;
}

void printIngressPortFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaIngressPortFlowEntry_t *flowData;
  ofdpaIngressPortFlowMatch_t *match;

  flowData = &flow->flowData.ingressPortFlowEntry;
  match = &flowData->match_criteria;

  /* match criteria */
  printf(" inPort:mask = 0x%08x:0x%08x", match->inPort, match->inPortMask);
  printf(" etherType:mask = 0x%04x:0x%04x", match->etherType, match->etherTypeMask);
  printf(" tunnelId:mask = 0x%08x:0x%08x", match->tunnelId, match->tunnelIdMask);

  /* instructions */
  printf(" |");
  printf(" GoTo = %d (%s)", flowData->gotoTableId, gotoFlowTableNameGet(flowData->gotoTableId));
}

void printDscpTrustFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaDscpTrustFlowEntry_t *flowData;
  ofdpaDscpTrustFlowMatch_t *match;
  char colorName[20];

  flowData = &flow->flowData.dscpTrustFlowEntry;
  match = &flowData->match_criteria;

  /* match criteria */
  printf(" qosIndex = %d", match->qosIndex);
  printf(" dscpValue = %d", match->dscpValue);

  if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST)
  {
    printf(" mplsL2Port:mask = 0x%08x:0x%08x", match->mplsL2Port, match->mplsL2PortMask);
  }

  /* instructions */
  printf(" |");
  printf(" GoTo = %d (%s)", flowData->gotoTableId, gotoFlowTableNameGet(flowData->gotoTableId));
  printf(" Traffic Class = %d", flowData->trafficClass);
  qosColorNameGet(flowData->color, colorName);
  printf(" Color = %d (%s)", flowData->color, colorName);
}

void printPcpTrustFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaPcpTrustFlowEntry_t *flowData;
  ofdpaPcpTrustFlowMatch_t *match;
  char colorName[20];

  /* match criteria */
  flowData = &flow->flowData.pcpTrustFlowEntry;
  match = &flowData->match_criteria;

  /* match criteria */
  printf(" qosIndex = %d", match->qosIndex);
  printf(" pcpValue = %d", match->pcpValue);
  printf(" dei = %d", match->dei);

  if (flow->tableId == OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST)
  {
    printf(" mplsL2Port:mask = 0x%08x:0x%08x", match->mplsL2Port, match->mplsL2PortMask);
  }

  /* instructions */
  printf(" |");
  printf(" GoTo = %d (%s)", flowData->gotoTableId, gotoFlowTableNameGet(flowData->gotoTableId));
  printf(" Traffic Class = %d", flowData->trafficClass);
  qosColorNameGet(flowData->color, colorName);
  printf(" Color = %d (%s)", flowData->color, colorName);
}

void printVlanFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaVlanFlowEntry_t *flowData;
  ofdpaVlanFlowMatch_t *match;

  flowData = &flow->flowData.vlanFlowEntry;
  match = &flowData->match_criteria;

  printf(" inPort = %d", match->inPort);
  printf(" vlanId:mask = 0x%04x:0x%04x (VLAN %d)", match->vlanId, match->vlanIdMask, match->vlanId & OFDPA_VID_EXACT_MASK);
  if (0 != match->etherTypeMask)
  {
    printf(" etherType:mask = 0x%04x:0x%04x", match->etherType, match->etherTypeMask);
  }
  if (!isMacZero(&match->destMacMask))
  {
    printf(" destMac:mask = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x:%2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x",
           match->destMac.addr[0], match->destMac.addr[1],
           match->destMac.addr[2], match->destMac.addr[3],
           match->destMac.addr[4], match->destMac.addr[5],
           match->destMacMask.addr[0], match->destMacMask.addr[1],
           match->destMacMask.addr[2], match->destMacMask.addr[3],
           match->destMacMask.addr[4], match->destMacMask.addr[5]);
  }

  /* instructions */
  printf(" |");
  printf(" GoTo = %d (%s)", flowData->gotoTableId, gotoFlowTableNameGet(flowData->gotoTableId));

  if (flowData->setVlanIdAction)
  {
    printf(" newVlanId = %d", flowData->newVlanId);
  }
  if (flowData->vrfAction)
  {
    printf(" vrf = %d", flowData->vrf);
  }
  if (flowData->brcmOvidAction)
  {
    printf(" brcmOvid = %d", flowData->brcmOvid);
  }
  if (flowData->pushVlan2Action)
  {
    printf(" newTpid2 = 0x%x", flowData->newTpid2);
  }
  if (flowData->setVlanId2Action)
  {
    printf(" newVlanId2 = %d", flowData->newVlanId2);
  }
  if (flowData->popVlanAction)
  {
    printf(" popVlanAction");
  }
  if (flowData->mplsL2PortAction)
  {
    printf(" mplsL2Port = 0x%x", flowData->mplsL2Port);
  }
  if (flowData->tunnelIdAction)
  {
    printf(" tunnelId = 0x%x", flowData->tunnelId);
  }
}

void printVlan1Flow(ofdpaFlowEntry_t *flow)
{
  ofdpaVlan1FlowEntry_t *flowData;
  ofdpaVlan1FlowMatch_t *match;

  flowData = &flow->flowData.vlan1FlowEntry;
  match = &flowData->match_criteria;

  printf(" inPort = %d", match->inPort);
  printf(" vlanId = 0x%04x (VLAN %d)", match->vlanId, match->vlanId & OFDPA_VID_EXACT_MASK);
  printf(" brcmOvid = 0x%04x (VLAN %d)", match->brcmOvid, match->brcmOvid & OFDPA_VID_EXACT_MASK);
  if (0 != match->etherTypeMask)
  {
    printf(" etherType:mask = 0x%04x:0x%04x", match->etherType, match->etherTypeMask);
  }
  if (!isMacZero(&match->destMacMask))
  {
    printf(" destMac:mask = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x:%2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x",
           match->destMac.addr[0], match->destMac.addr[1],
           match->destMac.addr[2], match->destMac.addr[3],
           match->destMac.addr[4], match->destMac.addr[5],
           match->destMacMask.addr[0], match->destMacMask.addr[1],
           match->destMacMask.addr[2], match->destMacMask.addr[3],
           match->destMacMask.addr[4], match->destMacMask.addr[5]);
  }

  /* instructions */
  printf(" |");
  printf(" GoTo = %d (%s)", flowData->gotoTableId, gotoFlowTableNameGet(flowData->gotoTableId));

  if (flowData->vrfAction)
  {
    printf(" vrf = %d", flowData->vrf);
  }
  if (flowData->pushVlanAction)
  {
    printf(" newTpid = 0x%x", flowData->newTpid);
  }
  if (flowData->setVlanIdAction)
  {
    printf(" newVlanId = %d", flowData->newVlanId);
  }
  if (flowData->popVlanAction)
  {
    printf(" popVlanAction");
  }
  if (flowData->mplsL2PortAction)
  {
    printf(" mplsL2Port = 0x%x", flowData->mplsL2Port);
  }
  if (flowData->tunnelIdAction)
  {
    printf(" tunnelId = 0x%x", flowData->tunnelId);
  }
}

void printMplsL2PortFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaMplsL2PortFlowEntry_t *flowData;
  ofdpaMplsL2PortFlowMatch_t *match;

  flowData = &flow->flowData.mplsL2PortFlowEntry;
  match = &flowData->match_criteria;

  printf(" mplsL2Port:mask = 0x%08x:0x%08x", match->mplsL2Port, match->mplsL2PortMask);
  printf(" tunnelId = 0x%x", match->tunnelId);

  if (OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST == flowData->gotoTableId)
  {
    printf(" etherType = 0x%4.4x", match->etherType);
  }

  /* instructions */
  printf(" |");
  printf(" GoTo = %d (%s)", flowData->gotoTableId, gotoFlowTableNameGet(flowData->gotoTableId));
  /* Apply actions */
  if (0 != flowData->qosIndexAction)
  {
    printf(" QOS Index = %d", flowData->qosIndex);
  }
  /* Write actions */
  if (flowData->groupId != 0)
  {
    printf(" groupId = 0x%08x", flowData->groupId);
  }
}

void printTermMacFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaTerminationMacFlowEntry_t *flowData;
  ofdpaTerminationMacFlowMatch_t *match;

  flowData = &flow->flowData.terminationMacFlowEntry;
  match = &flowData->match_criteria;

  printf(" inPort:mask = %d:0x%x", match->inPort, match->inPortMask);
  printf(" etherType = 0x%04x", match->etherType);
  printf(" destMac:mask = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x:%2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x",
         match->destMac.addr[0], match->destMac.addr[1],
         match->destMac.addr[2], match->destMac.addr[3],
         match->destMac.addr[4], match->destMac.addr[5],
         match->destMacMask.addr[0], match->destMacMask.addr[1],
         match->destMacMask.addr[2], match->destMacMask.addr[3],
         match->destMacMask.addr[4], match->destMacMask.addr[5]);
  printf(" vlanId:mask = %d:0x%x", match->vlanId, match->vlanIdMask);

  /* instructions */
  printf(" |");
  printf(" GoTo = %d (%s)", flowData->gotoTableId, gotoFlowTableNameGet(flowData->gotoTableId));

  printf(" outPort = %d", flowData->outputPort);
}

void printMplsFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaMplsFlowEntry_t *flowData;
  ofdpaMplsFlowMatch_t *match;
  struct in_addr ipv4Addr;
  char addrBuf[20];
  char addrMaskBuf[20];

  flowData = &flow->flowData.mplsFlowEntry;
  match = &flowData->match_criteria;

  /* MPLS flow tables are folded into a single flow table, display the table ID used to add flow */
  printf(" tableId = %d", flow->tableId);

  printf(" etherType = 0x%04x", match->etherType);
  printf(" BoS = %s", (match->mplsBos != 0) ? "TRUE" : "FALSE");
  printf(" mplsLabel = 0x%x", match->mplsLabel);
  printf(" inPort:mask = %d:0x%x", match->inPort, match->inPortMask);
  printf(" mplsTtl:mask = %d:0x%x", match->mplsTtl, match->mplsTtlMask);
  printf(" mplsDataFirstNibble:mask = %d:0x%x", match->mplsDataFirstNibble, match->mplsDataFirstNibbleMask);
  printf(" mplsAchChannel:mask = %d:0x%x", match->mplsAchChannel, match->mplsAchChannelMask);
  printf(" nextLabelIsGal:mask = %d:0x%x", match->nextLabelIsGal, match->nextLabelIsGalMask);

  ipv4Addr.s_addr = htonl(match->destIp4);
  inet_ntop(AF_INET, &ipv4Addr, addrBuf, sizeof(addrBuf));
  ipv4Addr.s_addr = htonl(match->destIp4Mask);
  inet_ntop(AF_INET, &ipv4Addr, addrMaskBuf, sizeof(addrMaskBuf));
  printf(" dstIp4 = %s/%s", addrBuf, addrMaskBuf);

  inet_ntop(AF_INET6, &match->destIp6, addrBuf, sizeof(addrBuf));
  inet_ntop(AF_INET6, &match->destIp6Mask, addrMaskBuf, sizeof(addrMaskBuf));
  printf(" dstIp6 = %s/%s", addrBuf, addrMaskBuf);

  printf(" ipProto:mask = %d:0x%x", match->ipProto, match->ipProtoMask);
  printf(" udpSrcPort:mask = %d:0x%x", match->udpSrcPort, match->udpSrcPortMask);
  printf(" udpDstPort:mask = %d:0x%x", match->udpDstPort, match->udpDstPortMask);

  /* instructions */
  printf(" |");
  printf(" GoTo = %d (%s)", flowData->gotoTableId, gotoFlowTableNameGet(flowData->gotoTableId));

  if (flowData->popLabelAction)
  {
    printf(" popLabel");
    printf(" newEtherType = 0x%04x", flowData->newEtherType);
  }
  if (flowData->decrementTtlAction)
  {
    printf(" decrementTtl");
  }
  if (flowData->copyTtlInAction)
  {
    printf(" copyTtlIn");
  }
  if (flowData->copyTcInAction)
  {
    printf(" copyTcIn");
  }
  if (flowData->vrfAction)
  {
    printf(" vrf = %d", flowData->vrf);
  }
  if (flowData->mplsL2PortAction)
  {
    printf(" mplsL2Port = 0x%8x", flowData->mplsL2Port);
  }
  if (flowData->tunnelIdAction)
  {
    printf(" tunnelId = %d", flowData->tunnelId);
  }

  if (flowData->qosIndexAction)
  {
    printf(" qosIndex = %d", flowData->qosIndex);
  }
  if (flowData->trafficClassAction)
  {
    printf(" trafficClass %d", flowData->trafficClass);
  }
  if (flowData->vlanIdAction)
  {
    printf(" vlanId %d", flowData->vlanId);
  }
  if (flowData->popCwAction)
  {
    printf(" popCw");
  }
  if (flowData->popVlanAction)
  {
    printf(" popVlan");
  }
  if (flowData->popL2HeaderAction)
  {
    printf(" popL2Header");
  }
  if (flowData->lmepIdAction)
  {
    printf(" lmepId = %d", flowData->lmepId);
  }
  if (0 != flowData->oamLmRxCountAction)
  {
    printf("oamLmRxCountAction = %d", flowData->oamLmRxCountAction);
  }

  printf(" groupId = 0x%08x", flowData->groupID);
  printf(" outPort = %d", flowData->outputPort);
}

void printMplsMaintenencePointFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaMplsMpFlowEntry_t *flowData;
  ofdpaMplsMpFlowMatch_t *match;

  flowData = &flow->flowData.mplsMpFlowEntry;
  match = &flowData->match_criteria;

  printf(" lmepId = %d (0x%04x)", match->lmepId, match->lmepId);
  printf(" oamY1731Opcode = %d (0x%x)", match->oamY1731Opcode, match->oamY1731Opcode);

  /* instructions */
  printf(" |");
  if (flowData->clearAction)
  {
    printf(" clearAction");
  }
  printf(" GoTo = %d (%s)", flowData->gotoTableId, gotoFlowTableNameGet(flowData->gotoTableId));

  if (flowData->oamSetCounterFieldsAction)
  {
    printf(" oamSetCounterFieldsAction");
  }
  if (flowData->oamLmRxCountAction)
  {
    printf(" oamLmRxCountAction");
  }
  if (flowData->checkDropStatusAction)
  {
    printf(" checkDropStatusAction");
  }
  printf(" lmepId = %d (0x%04x)", flowData->lmepId, flowData->lmepId);

  printf(" outPort = %d (0x%x)", flowData->outputPort, flowData->outputPort);
}

void printUnicastRoutingFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaUnicastRoutingFlowEntry_t *flowData;
  ofdpaUnicastRoutingFlowMatch_t *match;
  struct in_addr ipv4Addr;
  char addrBuf[20];
  char addrMaskBuf[20];

  flowData = &flow->flowData.unicastRoutingFlowEntry;
  match = &flowData->match_criteria;

  /* match criteria */
  printf(" etherType = 0x%04x", match->etherType);
  printf(" vrf:mask = 0x%04x:0x%04x", match->vrf, match->vrfMask);

  ipv4Addr.s_addr = htonl(match->dstIp4);
  inet_ntop(AF_INET, &ipv4Addr, addrBuf, sizeof(addrBuf));
  ipv4Addr.s_addr = htonl(match->dstIp4Mask);
  inet_ntop(AF_INET, &ipv4Addr, addrMaskBuf, sizeof(addrMaskBuf));
  printf(" dstIp4 = %s/%s", addrBuf, addrMaskBuf);

  inet_ntop(AF_INET6, &match->dstIp6, addrBuf, sizeof(addrBuf));
  inet_ntop(AF_INET6, &match->dstIp6Mask, addrMaskBuf, sizeof(addrMaskBuf));
  printf(" dstIp6 = %s/%s", addrBuf, addrMaskBuf);

  /* instructions */
  printf(" |");
  printf(" GoTo = %d (%s)", flowData->gotoTableId, gotoFlowTableNameGet(flowData->gotoTableId));
  printf(" groupId = 0x%08x", flowData->groupID);
}

void printMulticastRoutingFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaMulticastRoutingFlowEntry_t *flowData;
  ofdpaMulticastRoutingFlowMatch_t *match;
  struct in_addr ipv4Addr;
  char addrBuf[20];
  char addrMaskBuf[20];

  flowData = &flow->flowData.multicastRoutingFlowEntry;
  match = &flowData->match_criteria;

  /* match criteria */
  printf(" etherType = 0x%04x", match->etherType);
  printf(" vlanId = %d", match->vlanId);
  printf(" vrf:mask = 0x%04x:0x%04x", match->vrf, match->vrfMask);

  ipv4Addr.s_addr = htonl(match->srcIp4);
  inet_ntop(AF_INET, &ipv4Addr, addrBuf, sizeof(addrBuf));
  ipv4Addr.s_addr = htonl(match->srcIp4Mask);
  inet_ntop(AF_INET, &ipv4Addr, addrMaskBuf, sizeof(addrMaskBuf));
  printf(" srcIp4 = %s/%s", addrBuf, addrMaskBuf);

  ipv4Addr.s_addr = htonl(match->dstIp4);
  inet_ntop(AF_INET, &ipv4Addr, addrBuf, sizeof(addrBuf));
  printf(" dstIp4 = %s", addrBuf);

  inet_ntop(AF_INET6, &match->srcIp6, addrBuf, sizeof(addrBuf));
  inet_ntop(AF_INET6, &match->srcIp6Mask, addrMaskBuf, sizeof(addrMaskBuf));
  printf(" srcIp6 = %s/%s", addrBuf, addrMaskBuf);

  inet_ntop(AF_INET6, &match->dstIp6, addrBuf, sizeof(addrBuf));
  printf(" dstIp6 = %s", addrBuf);

  /* instructions */
  printf(" |");
  printf(" GoTo = %d (%s)", flowData->gotoTableId, gotoFlowTableNameGet(flowData->gotoTableId));
  printf(" groupId = 0x%08x", flowData->groupID);
}

void printBridgingFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaBridgingFlowEntry_t *flowData;
  ofdpaBridgingFlowMatch_t *match;

  flowData = &flow->flowData.bridgingFlowEntry;
  match = &flowData->match_criteria;

  /* match criteria */
  if (match->vlanId) printf(" vlanId:mask = %d:0x%x", match->vlanId, match->vlanIdMask);
  else printf(" tunnelId:mask = 0x%x:0x%x", match->tunnelId, match->tunnelIdMask);

  printf(" destMac:mask = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x:%2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x",
         match->destMac.addr[0], match->destMac.addr[1],
         match->destMac.addr[2], match->destMac.addr[3],
         match->destMac.addr[4], match->destMac.addr[5],
         match->destMacMask.addr[0], match->destMacMask.addr[1],
         match->destMacMask.addr[2], match->destMacMask.addr[3],
         match->destMacMask.addr[4], match->destMacMask.addr[5]);

  /* instructions */
  printf(" |");
  printf(" GoTo = %d (%s)", flowData->gotoTableId, gotoFlowTableNameGet(flowData->gotoTableId));
  printf(" groupId = 0x%08x", flowData->groupID);
  if (flowData->tunnelLogicalPort)
  {
    printf(" tunnelLogicalPort = 0x%08x", flowData->tunnelLogicalPort);
  }
  printf(" outPort = %d", flowData->outputPort);
}

void printPolicyAclFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaPolicyAclFlowEntry_t *flowData;
  ofdpaPolicyAclFlowMatch_t *match;
  struct in_addr ipv4Addr;
  char addrBuf[20];
  char addrMaskBuf[20];

  flowData = &flow->flowData.policyAclFlowEntry;
  match = &flowData->match_criteria;

  /* match criteria */

  printf(" inPort:mask = %d:0x%x", match->inPort, match->inPortMask);
  printf(" srcMac:mask = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x:%2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x",
         match->srcMac.addr[0], match->srcMac.addr[1],
         match->srcMac.addr[2], match->srcMac.addr[3],
         match->srcMac.addr[4], match->srcMac.addr[5],
         match->srcMacMask.addr[0], match->srcMacMask.addr[1],
         match->srcMacMask.addr[2], match->srcMacMask.addr[3],
         match->srcMacMask.addr[4], match->srcMacMask.addr[5]);
  printf(" destMac:mask = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x:%2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x",
         match->destMac.addr[0], match->destMac.addr[1],
         match->destMac.addr[2], match->destMac.addr[3],
         match->destMac.addr[4], match->destMac.addr[5],
         match->destMacMask.addr[0], match->destMacMask.addr[1],
         match->destMacMask.addr[2], match->destMacMask.addr[3],
         match->destMacMask.addr[4], match->destMacMask.addr[5]);
  printf(" etherType = %04x", match->etherType);
  if (match->mplsL2Port) printf(" mplsL2Port:mask = %d:0x%x", match->mplsL2Port, match->mplsL2PortMask);
  if (match->vlanId) printf(" vlanId:mask = %d:0x%x", match->vlanId, match->vlanIdMask);
  else printf(" tunnelId = %d", match->tunnelId);
  if (match->vlanPcp) printf(" vlanPcp:mask = %d:0x%x", match->vlanPcp, match->vlanPcpMask);

  ipv4Addr.s_addr = htonl(match->sourceIp4);
  inet_ntop(AF_INET, &ipv4Addr, addrBuf, sizeof(addrBuf));
  ipv4Addr.s_addr = htonl(match->sourceIp4Mask);
  inet_ntop(AF_INET, &ipv4Addr, addrMaskBuf, sizeof(addrMaskBuf));
  printf(" srcIp4 = %s/%s", addrBuf, addrMaskBuf);

  ipv4Addr.s_addr = htonl(match->destIp4);
  inet_ntop(AF_INET, &ipv4Addr, addrBuf, sizeof(addrBuf));
  ipv4Addr.s_addr = htonl(match->destIp4Mask);
  inet_ntop(AF_INET, &ipv4Addr, addrMaskBuf, sizeof(addrMaskBuf));
  printf(" dstIp4 = %s/%s", addrBuf, addrMaskBuf);

  inet_ntop(AF_INET6, &match->sourceIp6, addrBuf, sizeof(addrBuf));
  inet_ntop(AF_INET6, &match->sourceIp6Mask, addrMaskBuf, sizeof(addrMaskBuf));
  printf(" srcIp6 = %s/%s", addrBuf, addrMaskBuf);

  inet_ntop(AF_INET6, &match->destIp6, addrBuf, sizeof(addrBuf));
  inet_ntop(AF_INET6, &match->destIp6Mask, addrMaskBuf, sizeof(addrMaskBuf));
  printf(" dstIp6 = %s/%s", addrBuf, addrMaskBuf);

  printf(" DSCP = %u", match->dscp);
  printf(" VRF = %u", match->vrf);
  printf(" DEI = %u", match->vlanDei);
  printf(" ECN = %u", match->ecn);
  printf(" IP Protocol = 0x%2.2x", match->ipProto);
  printf(" Source L4 Port = %u", match->srcL4Port);
  printf(" Destination L4 Port = %u", match->destL4Port);
  printf(" ICMP Type = %u", match->icmpType);
  printf(" ICMP Code = %u", match->icmpCode);

  /* instructions */
  printf(" |");
  if (flowData->groupID)
  {
    printf(" Set output group ID = 0x%8x", flowData->groupID);
  }
  if (flowData->queueIDAction)
  {
    printf(" Set CoS queue = %d", flowData->queueID);
  }
  if (flowData->colorAction)
  {
    switch (flowData->color)
    {
      case OFDPA_QOS_GREEN:
        printf(" Set Color = green:0");
        break;
      case OFDPA_QOS_YELLOW:
        printf(" Set Color = yellow:1");
        break;
      case OFDPA_QOS_RED:
        printf(" Set Color = red:2");
        break;
      default:
        printf(" Set Color = incorrect value:%d", flowData->color);
        break;
    }
  }

  if (flowData->meterIdAction)
  {
    printf(" Set Meter ID = %d", flowData->meterId);
  }

  printf(" outPort = %d", flowData->outputPort);
}

void printEgressVlanFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaEgressVlanFlowEntry_t *flowData;
  ofdpaEgressVlanFlowMatch_t *match;

  flowData = &flow->flowData.egressVlanFlowEntry;
  match = &flowData->match_criteria;

  printf(" outPort = %d", match->outPort);
  printf(" vlanId = 0x%04x (VLAN %d)", match->vlanId, match->vlanId & OFDPA_VID_EXACT_MASK);
  if (0 != match->etherTypeMask)
  {
    printf(" etherType:mask = 0x%04x:0x%04x", match->etherType, match->etherTypeMask);
  }
  if (!isMacZero(&match->destMacMask))
  {
    printf(" destMac:mask = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x:%2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x",
           match->destMac.addr[0], match->destMac.addr[1],
           match->destMac.addr[2], match->destMac.addr[3],
           match->destMac.addr[4], match->destMac.addr[5],
           match->destMacMask.addr[0], match->destMacMask.addr[1],
           match->destMacMask.addr[2], match->destMacMask.addr[3],
           match->destMacMask.addr[4], match->destMacMask.addr[5]);
  }

  /* instructions */
  printf(" |");
  printf(" GoTo = %d (%s)", flowData->gotoTableId, gotoFlowTableNameGet(flowData->gotoTableId));

  if (flowData->setVlanIdAction)
  {
    printf(" newVlanId = %d", flowData->newVlanId);
  }
  if (flowData->brcmOvidAction)
  {
    printf(" brcmOvid = %d", flowData->brcmOvid);
  }
  if (flowData->pushVlan2Action)
  {
    printf(" newTpid2 = 0x%x", flowData->newTpid2);
  }
  if (flowData->setVlanId2Action)
  {
    printf(" newVlanId2 = %d", flowData->newVlanId2);
  }
  if (flowData->popVlanAction)
  {
    printf(" popVlanAction");
  }
}

void printEgressVlan1Flow(ofdpaFlowEntry_t *flow)
{
  ofdpaEgressVlan1FlowEntry_t *flowData;
  ofdpaEgressVlan1FlowMatch_t *match;

  flowData = &flow->flowData.egressVlan1FlowEntry;
  match = &flowData->match_criteria;

  printf(" outPort = %d", match->outPort);
  printf(" vlanId = 0x%04x (VLAN %d)", match->vlanId, match->vlanId & OFDPA_VID_EXACT_MASK);
  printf(" brcmOvid = 0x%04x (VLAN %d)", match->brcmOvid, match->brcmOvid & OFDPA_VID_EXACT_MASK);
  if (0 != match->etherTypeMask)
  {
    printf(" etherType:mask = 0x%04x:0x%04x", match->etherType, match->etherTypeMask);
  }
  if (!isMacZero(&match->destMacMask))
  {
    printf(" destMac:mask = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x:%2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x",
           match->destMac.addr[0], match->destMac.addr[1],
           match->destMac.addr[2], match->destMac.addr[3],
           match->destMac.addr[4], match->destMac.addr[5],
           match->destMacMask.addr[0], match->destMacMask.addr[1],
           match->destMacMask.addr[2], match->destMacMask.addr[3],
           match->destMacMask.addr[4], match->destMacMask.addr[5]);
  }

  /* instructions */
  printf(" |");
  printf(" GoTo = %d (%s)", flowData->gotoTableId, gotoFlowTableNameGet(flowData->gotoTableId));

  if (flowData->setVlanIdAction)
  {
    printf(" newVlanId = %d", flowData->newVlanId);
  }
  if (flowData->popVlanAction)
  {
    printf(" popVlanAction");
  }
}

void printMplsQosFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaMplsQosFlowEntry_t *flowData;
  ofdpaMplsQosFlowMatch_t *match;
  char colorName[20];

  flowData = &flow->flowData.mplsQosFlowEntry;
  match = &flowData->match_criteria;

  /* match criteria */
  printf(" qosIndex = %d", match->qosIndex);
  printf(" mpls_tc  = %d", match->mpls_tc);

  /* instructions */
  printf(" |");
  printf(" Traffic Class = %d", flowData->trafficClass);
  qosColorNameGet(flowData->color, colorName);
  printf(" Color = %d (%s)", flowData->color, colorName);
}

void printFlowEntry(ofdpaFlowEntry_t *flow)
{
  flowPrintFcn_t *printFcn;

  if ((printFcn = flowEntryPrintFcnGet(tableId)) != NULL)
  {
    printFcn(flow);
  }
  else
  {
    printf("[No print function for this flow table]");
  }
  printf(" |");
  printf(" priority = %d", flow->priority);
  printf(" hard_time = %d", flow->hard_time);
  printf(" idle_time = %d", flow->idle_time);
  printf(" cookie = %llu", (unsigned long long int)flow->cookie);

  printf("\r\n");
}

void dumpFlowTable(OFDPA_FLOW_TABLE_ID_t tableId, int entryPrintLimit, int *entriesPrinted)
{
  int i;
  OFDPA_ERROR_t rc;
  char buffer[30];
  ofdpaFlowTableInfo_t info;
  ofdpaFlowEntry_t flow;
  ofdpaFlowEntryStats_t flowStats;

  memset(&info, 0, sizeof(info));
  rc = ofdpaFlowTableInfoGet(tableId, &info);

  if (!showEmptyTables &&
      (info.numEntries == 0))
  {
    return;
  }

  printf("Table ID %d (%s): ", tableId, flowTableNameGet(tableId));

  if (entryPrintLimit == 0) sprintf(buffer, "all entries");
  else if (entryPrintLimit == 1) sprintf(buffer, "up to 1 entry");
  else sprintf(buffer, "up to %d entries", entryPrintLimit);

  printf("  Retrieving %s. ", buffer);

  if (rc != OFDPA_E_NONE)
  {
    printf("Could not retrieve OF-DPA table info with ID %d. (rc = %d)\r\n", tableId, rc);
  }
  else
  {
    printf("Max entries = %d, Current entries = %d.\r\n", info.maxEntries, info.numEntries);
  }

  ofdpaFlowEntryInit(tableId, &flow);

  rc = ofdpaFlowStatsGet(&flow, &flowStats);
  if (rc != OFDPA_E_NONE)
  {
    rc = ofdpaFlowNextGet(&flow, &flow);
  }

  i = 0;

  while ((rc == OFDPA_E_NONE) &&
         ((entryPrintLimit == 0) || (i < entryPrintLimit)))
  {
    printf("--");
    printFlowEntry(&flow);
    i++;

    rc = ofdpaFlowNextGet(&flow, &flow);
  }

  /* blank line between tables */
  printf("\r\n");
  *entriesPrinted = i;
}

int main(int argc, char *argv[])
{
  int i, j, entriesPrinted, totalPrinted, remainingCount;
  int rc;
  char client_name[] = "ofdpa flowtable_dump client";
  char docBuffer[1000];
  char argsDocBuffer[300];

  /* Our argp parser. */
  struct argp argp =
  {
    .args_doc = argsDocBuffer,
    .doc      = docBuffer,
    .options  = options,
    .parser   = parse_opt,
  };

  count = DEFAULT_COUNT;

  strcpy(argsDocBuffer, "[table_ID]");

  strcpy(docBuffer, "Prints entries in the OF-DPA flow tables. Specify table ID to print content of a single table. "
         "If no argument given, content of all tables are printed.\vDefault values:\n");
  i = strlen(docBuffer);
  i += sprintf(&docBuffer[i], "COUNT     = %d\n", DEFAULT_COUNT);
  i += sprintf(&docBuffer[i], "\n");

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }

  /* Parse our arguments; every option seen by `parse_opt' will be reflected in
     `arguments'. */
  argp_parse(&argp, argc, argv, 0, 0, 0);

  if (showValidTableIds)
  {
    printf("Valid flow table IDs:\r\n");
    for (j = 0; j < TABLE_NAME_LIST_SIZE; j++)
    {
      if (ofdpaFlowTableSupported(tableList[j].type) == OFDPA_E_NONE)
      {
        printf("  %d - %s\r\n", tableList[j].type, tableList[j].name);
      }
    }
    printf("\r\n");
    return 0;
  }

  totalPrinted = 0;

  if (tableIdSpecified)
  {
    dumpFlowTable(tableId, count, &totalPrinted);
  }
  else
  {
    remainingCount = count;

    for (tableId = 0; tableId <= 255; tableId++)
    {
      if (ofdpaFlowTableSupported(tableId) == OFDPA_E_NONE)
      {
        entriesPrinted = 0;

        dumpFlowTable(tableId, remainingCount, &entriesPrinted);

        totalPrinted += entriesPrinted;

        if (count != 0)
        {
          if (remainingCount > entriesPrinted)
          {
            remainingCount -= entriesPrinted;
          }
          else
          {
            /* printed the requested number of total entries */
            break;
          }
        }
      }
    }
  }

  /* 
   * if not printing empty table stats and no flow entries found, we haven't printed anything at all
   * so print a message letting the user know we are responsive
   */
  if ((showEmptyTables == 0) && (totalPrinted == 0))
  {
    printf("No flow entries found.\r\n");
  }
  return 0;
}
