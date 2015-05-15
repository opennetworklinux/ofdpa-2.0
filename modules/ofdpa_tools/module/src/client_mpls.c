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
 * @filename     client_mpls.c
 *
 * @purpose      Example code for MPLS Flow Table. Uses RPC calls.
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
#include <libgen.h>
#include <assert.h>
#include <arpa/inet.h>

#define VERSION              1.0
static const char flow_table_name[] = "MPLS";
static char client_name[] = "ofdpa MPLS client";

#define NO_ACTION             0
#define ACTION                1

const struct in6_addr in6addr_null = { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } };

/* Default values */
typedef enum
{
  DEFAULT_COUNT           = 1,
  DEFAULT_PRIORITY        = 0,

  DEFAULT_MPLS_TABLE      = 1,

  DEFAULT_ETHERTYPE       = 0x8847,
  DEFAULT_MPLS_BOS        = 0,
  DEFAULT_MPLS_LABEL      = 0x1111,
  DEFAULT_INPORT          = 1,
  DEFAULT_INPORT_MASK     = 0,
  DEFAULT_MPLS_TTL        = 0,
  DEFAULT_MPLS_TTL_MASK   = 0,
  DEFAULT_MPLS_DATA_FIRST_NIBBLE = 0,
  DEFAULT_MPLS_DATA_FIRST_NIBBLE_MASK = 0,
  DEFAULT_MPLS_ACH_CHANNEL       = 0,
  DEFAULT_MPLS_ACH_CHANNEL_MASK  = 0,
  DEFAULT_NEXT_LABEL_IS_GAL      = 0,
  DEFAULT_NEXT_LABEL_IS_GAL_MASK = 0,
  DEFAULT_DESTIP4         = 0x01010101u,
  DEFAULT_DESTIP4_MASK    = OFDPA_IPV4_ADDR_FIELD_MASK,
  DEFAULT_IP_PROTO        = 0,
  DEFAULT_IP_PROTO_MASK   = 0,

  DEFAULT_UDP_SRC_PORT       = 0,
  DEFAULT_UDP_SRC_PORT_MASK  = 0,
  DEFAULT_UDP_DEST_PORT      = 0,
  DEFAULT_UDP_DEST_PORT_MASK = 0,

  DEFAULT_GOTO_TABLE_ID   = OFDPA_FLOW_TABLE_ID_ACL_POLICY,

  DEFAULT_VRF_ACT         = NO_ACTION,
  DEFAULT_VRF             = 0,
  DEFAULT_MPLS_L2_PORT_ACT = NO_ACTION,
  DEFAULT_MPLS_L2_PORT    = 0,
  DEFAULT_TUNNELID_ACT    = NO_ACTION,
  DEFAULT_TUNNELID        = 0,
  DEFAULT_QOS_ACT         = NO_ACTION,
  DEFAULT_QOS             = 0,
  DEFAULT_TC_ACT          = NO_ACTION,
  DEFAULT_TC              = 0,
  DEFAULT_VLAN_ID_ACT     = NO_ACTION,
  DEFAULT_VLAN_ID         = 10,
  DEFAULT_LMEP_ID_ACT     = NO_ACTION,
  DEFAULT_LMEP_ID         = 0,
  DEFAULT_OAM_LM_RX_COUNT = 0,
  DEFAULT_GROUP_ID        = 0,

  DEFAULT_POP_MPLS_LABEL  = ACTION,
  DEFAULT_DEC_TTL_ACT     = ACTION,
  DEFAULT_CP_TTL_ACT      = NO_ACTION,
  DEFAULT_CP_TC_ACT       = NO_ACTION,

  DEFAULT_POP_CW          = NO_ACTION,
  DEFAULT_POP_VLAN        = NO_ACTION,
  DEFAULT_POP_L2_HEADER   = NO_ACTION,

  DEFAULT_DISCARD         = NO_ACTION,
  DEFAULT_COPY            = NO_ACTION,
  DEFAULT_DELETE          = NO_ACTION,
  DEFAULT_LIST            = NO_ACTION,
} CLIENT_MPLS_DEFAULT_VALUES_ENUM;

#define ARG_DELETE        "delete"
#define ARG_LIST          "list"


typedef enum
{
  KEY_COUNT       = 'c',
  KEY_DISCARD     = 'd',
  KEY_COPY        = 'p',
  KEY_ETHERTYPE   = 1001,
  KEY_MPLS_BOS,
  KEY_MPLS_LABEL,
  KEY_INPORT,
  KEY_INPORT_MASK,
  KEY_MPLS_TTL,
  KEY_MPLS_DATA_FIRST_NIBBLE,
  KEY_MPLS_ACH_CHANNEL,
  KEY_NEXT_LABEL_IS_GAL,
  KEY_DEST_IPV4,
  KEY_DEST_IPV4MASK,
  KEY_DEST_IPV6,
  KEY_DEST_IPV6_PREFIX,
  KEY_IP_PROTO,
  KEY_UDP_SRC_PORT,
  KEY_UDP_SRC_PORT_MASK,
  KEY_UDP_DST_PORT,
  KEY_UDP_DST_PORT_MASK,

  KEY_GOTO,
  KEY_POP_MPLS_LABEL,
  KEY_POP_CW,
  KEY_POP_VLAN,
  KEY_POP_L2,
  KEY_DEC_TTL,
  KEY_CP_TTL_IN,
  KEY_CP_TC_IN,
  KEY_SET_VRF,
  KEY_MPLS_L2,
  KEY_TUN_ID,
  KEY_QOS,
  KEY_TC,
  KEY_VLAN_ID,
  KEY_LMEP_ID,
  KEY_OAM_LM_RX_COUNT,
  KEY_GROUP,
  KEY_MPLS_TABLE,
} CLIENT_MPLS_KEYS_ENUM;


typedef struct
{
  int count;
  int mpls_table;
  int discard;
  int copy;
  int delete;
  int list;
  int priority;
  ofdpaFlowEntry_t flow;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] = {
  /* long-short-arg-flag-doc-group */
  { "count",                  KEY_COUNT,                  "COUNT",                  0, "Number of rules to add, delete or list.", 0},
  { "table",                  KEY_MPLS_TABLE,             "TABLE",                  0, "Number of MPLS flow table (0-1)", 0},
  { 0,                        0,                          0,                        0, "Matches:",},
  { "ether",                  KEY_ETHERTYPE,              "ETHERTYPE",              0, "Ethernet type.",},
  { "bos",                    KEY_MPLS_BOS,               0,                        0, "MPLS Bottom Of Stack.",},
  { "label",                  KEY_MPLS_LABEL,             "LABEL",                  0, "MPLS label.",},
  { "inport",                 KEY_INPORT,                 "INPORT",                 0, "Input Interface.",},
  { "inport_mask",            KEY_INPORT_MASK,            "INPORT_MASK",            0, "Input Interface Mask.",},
  { "mpls_ttl",               KEY_MPLS_TTL,               "MPLS_TTL",               0, "MPLS TTL", },
  { "mpls_data_first_nibble", KEY_MPLS_DATA_FIRST_NIBBLE, "MPLS_DATA_FIRST_NIBBLE", 0, "MPLS Data First NIbble",},
  { "mpls_ach_channel",       KEY_MPLS_ACH_CHANNEL,       "MPLS_ACH_CHANNEL",       0, "MPLS ACH Channel",},
  { "next_label_is_gal",      KEY_NEXT_LABEL_IS_GAL,      "NEXT_LABEL_IS_GAL",      0, "Next Label GAL indicator", },
  { "dest_ipv4",              KEY_DEST_IPV4,              "DEST_IPV4",              0, "Destinatin IPv4 Address",},
  { "dest_ipv4mask",          KEY_DEST_IPV4MASK,          "DEST_IPV4MASK",          0, "Destinatin IPv4 Mask",},
  { "dest_ipv6",              KEY_DEST_IPV6,              "DEST_IPV6",              0, "Destinatin IPv6 Address",},
  { "dst_ip6pfx",             KEY_DEST_IPV6_PREFIX,       "DEST_IPV6_PREFIX",       0, "Destinatin IPv6 Prefix length",},
  { "ip_proto",               KEY_IP_PROTO,               "IP_PROTO",               0, "IP Protocol",},
  { "udp_src_port",           KEY_UDP_SRC_PORT,           "UDP_SRC_PORT",           0, "UDP Source Port",},
  { "udp_src_port_mask",      KEY_UDP_SRC_PORT_MASK,      "UDP_SRC_PORT_MASK",      0, "UDP Source Port Mask",},
  { "udp_dst_port",           KEY_UDP_DST_PORT,           "UDP_DST_PORT",           0, "UDP Destination Port",},
  { "udp_dst_port_mask",      KEY_UDP_DST_PORT_MASK,      "UDP_DST_PORT_MASK",      0, "UDP Destination Port Mask",},

  { 0,            0,                  0,            0, "Instructions:",},
  { "goto",       KEY_GOTO,           "GOTO_TABLE", 0, "Goto table.",},
  { 0,            0,                  0,            0, "Write actions:",},
  { "pop_label",  KEY_POP_MPLS_LABEL, "POP_LABEL",  0, "Pop MPLS label. Argument (ethertype)required but not used",},
  { "pop_cw",     KEY_POP_CW,         0,            0, "Pop control word.",},
  { "pop_vlan",   KEY_POP_VLAN,       0,            0, "Pop VLAN tag.",},
  { "pop_l2",     KEY_POP_L2,         0,            0, "Pop L2 header.",},
  { "dec_ttl",    KEY_DEC_TTL,        0,            0, "Decrement TTL.",},
  { "cp_ttl_in",  KEY_CP_TTL_IN,      0,            0, "Copy TTL in.",},
  { "cp_tc_in",   KEY_CP_TC_IN,       0,            0, "Copy MPLS TC in.",},
  { "set_vrf",    KEY_SET_VRF,        "VRF",        0, "VRF",},
  { "set_l2",     KEY_MPLS_L2,        "MPLS_L2",    0, "Set MPLS L2 port.",},
  { "set_tun_id", KEY_TUN_ID,         "TUN_ID",     0, "Set tunnel id.",},
  { "set_qos",    KEY_QOS,            "QOS",        0, "Set QoS index.",},
  { "set_tc",     KEY_TC,             "TC",         0, "Set MPLS Traffic Class.",},
  { "set_vlan",   KEY_VLAN_ID,        "VLAN",       0, "Set Vlan Id.",},
  { "set_lmepid", KEY_LMEP_ID,        "LMEP_ID",    0, "Set LMEP ID.",},
  { 0,            0,                  0,            0, "Apply actions:",},
  { "group",      KEY_GROUP,          "GROUP",      0, "Destination group",},
  { 0,            0,                  0,            0, "Other Actions:",},
  { "discard",    KEY_DISCARD,        0,            0, "Discard matching flows.",},
  { "copy",       KEY_COPY,           0,            0, "Copy matching flows to the CPU.",},
  { 0}
};

typedef void (*displayFlow_t)(ofdpaFlowEntry_t*);

static void printDefaults(char * const docBuffer, const int length)
{
  int i = 0;
  snprintf(docBuffer, length,
           "Adds, deletes or lists %s flows.\vDefault values:\n",
           flow_table_name);

  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], length - i,    "\tCOUNT                = %d\n", DEFAULT_COUNT);
  i += snprintf(&docBuffer[i], length - i,    "\tMPLS TABLE           = %d\n\n", DEFAULT_MPLS_TABLE);
  i += snprintf(&docBuffer[i], length - i,    "MATCHES:\n");
  i += snprintf(&docBuffer[i], length - i,    "\tLABEL              = 0x%05x\r\n", DEFAULT_MPLS_LABEL);
  if (0 != DEFAULT_INPORT_MASK)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tINPORT               = %d\n", DEFAULT_INPORT);
  }
  i += snprintf(&docBuffer[i], length - i,    "\tETHERTYPE          = 0x%04x\n", DEFAULT_ETHERTYPE);
  i += snprintf(&docBuffer[i], length - i,    "\tMPLS_BOS           = %s\n", DEFAULT_MPLS_BOS ? "TRUE" : "FALSE");
  if (0 != DEFAULT_MPLS_TTL)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tMPLS TTL             = %d\n", DEFAULT_MPLS_TTL);
  }
  if (0 != DEFAULT_MPLS_DATA_FIRST_NIBBLE)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tMPLS DATA FIRST NIBBLE = %d\n", DEFAULT_MPLS_DATA_FIRST_NIBBLE);
  }
  if (0 != DEFAULT_MPLS_ACH_CHANNEL)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tMPLS ACH CHANNEL      = %d\n", DEFAULT_MPLS_ACH_CHANNEL);
  }
  if (0 != DEFAULT_NEXT_LABEL_IS_GAL)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tNEXT LABEL IS GAL     = %d\n", DEFAULT_NEXT_LABEL_IS_GAL);
  }
  if (0 != DEFAULT_DESTIP4_MASK)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tIPV4 ADDRESS         = %d\n", DEFAULT_DESTIP4);
    i += snprintf(&docBuffer[i], length - i,  "\tIPV4 ADDRESS MASK    = %d\n", DEFAULT_DESTIP4_MASK);
  }
  if (0 != DEFAULT_IP_PROTO)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tIP PROTO             = %d\n", DEFAULT_IP_PROTO);
  }
  if (0 != DEFAULT_UDP_DEST_PORT_MASK)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tUDP DESTINATION PORT      = %d\n", DEFAULT_UDP_DEST_PORT);
    i += snprintf(&docBuffer[i], length - i,  "\tUDP DESTINATION PORT MASK = %d\n", DEFAULT_UDP_DEST_PORT_MASK);
  }
  if (0 != DEFAULT_UDP_SRC_PORT_MASK)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tUDP SOURCE PORT      = %d\n", DEFAULT_UDP_SRC_PORT);
    i += snprintf(&docBuffer[i], length - i,  "\tUDP SOURCE PORT MASK = %d\n", DEFAULT_UDP_SRC_PORT_MASK);
  }

  i += snprintf(&docBuffer[i], length - i,    "ACTIONS:\n");
  i += snprintf(&docBuffer[i], length - i,    "\tGOTO table         = %d\n", DEFAULT_GOTO_TABLE_ID);
  i += snprintf(&docBuffer[i], length - i,    "\tPOP MPLS LABEL     = %s\n", DEFAULT_POP_MPLS_LABEL ? "TRUE" : "FALSE");
  i += snprintf(&docBuffer[i], length - i,    "\tPOP CW             = %s\n", DEFAULT_POP_CW ? "TRUE" : "FALSE");
  i += snprintf(&docBuffer[i], length - i,    "\tPOP VLAN           = %s\n", DEFAULT_POP_VLAN ? "TRUE" : "FALSE");
  i += snprintf(&docBuffer[i], length - i,    "\tPOP L2 HEADER      = %s\n", DEFAULT_POP_L2_HEADER ? "TRUE" : "FALSE");
  i += snprintf(&docBuffer[i], length - i,    "\tDECREMENT TTL      = %s\n", DEFAULT_DEC_TTL_ACT ? "TRUE" : "FALSE");
  i += snprintf(&docBuffer[i], length - i,    "\tCOPY TTL IN        = %s\n", DEFAULT_CP_TTL_ACT ? "TRUE" : "FALSE");
  i += snprintf(&docBuffer[i], length - i,    "\tCOPY TC IN         = %s\n", DEFAULT_CP_TC_ACT ? "TRUE" : "FALSE");

  if (ACTION == DEFAULT_VRF_ACT)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tVRF                  = %d\n", DEFAULT_VRF);
  }

  if (ACTION == DEFAULT_MPLS_L2_PORT_ACT)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tMPLS L2 Port         = %d\n", DEFAULT_MPLS_L2_PORT);
  }

  if (ACTION == DEFAULT_TUNNELID_ACT)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tTunnel ID            = %d\n", DEFAULT_TUNNELID);
  }

  if (ACTION == DEFAULT_QOS_ACT)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tQoS                  = %d\n", DEFAULT_QOS);
  }
  if (ACTION == DEFAULT_TC_ACT)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tMPLS TC              = %d\n", DEFAULT_TC);
  }

  if (ACTION == DEFAULT_VLAN_ID_ACT)
  {
    i += snprintf(&docBuffer[i], length - i,  "\tVLAN                 = %d\n", DEFAULT_VLAN_ID);
  }

  i += snprintf(&docBuffer[i], length - i,    "\tGROUP              = %d\n", DEFAULT_GROUP_ID);

  if (i > length)
  {
    printf("\n[ERROR]\n%s, %d\nMessage longer than buffer on %d symbols, please increase docBuffer size.\n",
            __FILE__, __LINE__, i - length);
    exit(1);
  }
}

static void displayMPLS(ofdpaFlowEntry_t *flow)
{
  char buf[INET6_ADDRSTRLEN + 1];
  struct in_addr ipv4Addr;

  ofdpaMplsFlowEntry_t * const flow_entry = &flow->flowData.mplsFlowEntry;
  printf("MATCHES:\n");
  printf("\tLABEL             = 0x%05x\r\n", flow_entry->match_criteria.mplsLabel);
  if (0 != flow_entry->match_criteria.inPortMask)
  {
    printf("\tINPORT            = %d\n", flow_entry->match_criteria.inPort);
    printf("\tINPORTMASK        = %d", flow_entry->match_criteria.inPortMask);
  }

  printf("\tETHERTYPE         = 0x%04x\n", flow_entry->match_criteria.etherType);
  printf("\tMPLS_BOS          = %s\n", flow_entry->match_criteria.mplsBos ? "TRUE" : "FALSE");

  if (0 != flow_entry->match_criteria.mplsTtlMask)
  {
    printf("\tMPLS_TTL = %d\n", flow_entry->match_criteria.mplsTtl);
  }

  if (0 != flow_entry->match_criteria.mplsDataFirstNibbleMask)
  {
    printf("\tMPLS_DATA_FIRST_NIBBLE = 0x%x\n", flow_entry->match_criteria.mplsDataFirstNibble);
  }

  if (0 != flow_entry->match_criteria.mplsAchChannelMask)
  {
    printf("\tMPLS_ACH_CHANNEL = 0x%x\n", flow_entry->match_criteria.mplsAchChannel);
  }

  if (0 != flow_entry->match_criteria.nextLabelIsGalMask)
  {
    printf("\tNEXT_LABEL_IS_GAL = %d\n", flow_entry->match_criteria.nextLabelIsGal);
  }

  ipv4Addr.s_addr = htonl(flow_entry->match_criteria.destIp4);
  if ((0 != flow_entry->match_criteria.destIp4Mask) &&
      (NULL != inet_ntop(AF_INET, &ipv4Addr, buf, sizeof(buf))))
  {
    printf("\tDESTINATION IPV4 = %s\r\n", buf);

    ipv4Addr.s_addr = htonl(flow_entry->match_criteria.destIp4Mask);
    if (NULL != inet_ntop(AF_INET, &ipv4Addr, buf, sizeof(buf)))
    {
      printf("\tDESTINATION IPV4 MASK    = %s\r\n", buf);
    }
  }

  if ((0 != memcmp(&flow_entry->match_criteria.destIp6Mask, &in6addr_null, sizeof(flow_entry->match_criteria.destIp6Mask))) &&
      (NULL != inet_ntop(AF_INET6, &flow_entry->match_criteria.destIp6, buf, sizeof(buf))))
  {
    printf("\tDESTINATION IPV6 = %s\r\n", buf);

    if (NULL != inet_ntop(AF_INET6, &flow_entry->match_criteria.destIp6Mask, buf, sizeof(buf)))
    {
      printf("\tDESTINATION IPV6 MASK    = %s\r\n", buf);
    }
  }

  if (0 != flow_entry->match_criteria.ipProtoMask)
  {
    printf("\tIPPROTO = %d\n", flow_entry->match_criteria.ipProto);
  }

  if (0 != flow_entry->match_criteria.udpSrcPortMask)
  {
    printf("\tUDP SRC PORT = %d\n", flow_entry->match_criteria.udpSrcPort);
    printf("\tUDP SRC PORT MASK = 0x%x\n", flow_entry->match_criteria.udpSrcPortMask);
  }

  if (0 != flow_entry->match_criteria.udpDstPortMask)
  {
    printf("\tUDP DST PORT = %d\n", flow_entry->match_criteria.udpDstPort);
    printf("\tUDP DST PORT MASK = 0x%x\n", flow_entry->match_criteria.udpDstPortMask);
  }

  printf("ACTIONS:\n");
  printf("\tGOTO table        = %d\n", flow_entry->gotoTableId);
  printf("\tPOP MPLS LABEL    = %s\n", flow_entry->popLabelAction ? "TRUE" : "FALSE");
  printf("\tDECREMENT TTL     = %s\n", flow_entry->decrementTtlAction ? "TRUE" : "FALSE");
  printf("\tCOPY TTL IN       = %s\n", flow_entry->copyTtlInAction ? "TRUE" : "FALSE");
  printf("\tCOPY TC IN        = %s\n", flow_entry->copyTcInAction ? "TRUE" : "FALSE");

  if (flow_entry->vrfAction)
  {
    printf("\tVRF             = %d\n", flow_entry->vrf);
  }

  if (flow_entry->mplsL2PortAction)
  {
    printf("\tMPLS L2 PORT      = 0x%08x\n", flow_entry->mplsL2Port);
  }

  if (flow_entry->tunnelIdAction)
  {
    printf("\tTUNNEL ID         = 0x%08x\n", flow_entry->tunnelId);
  }

  if (flow_entry->qosIndexAction)
  {
    printf("\tQOS               = %d\n", flow_entry->qosIndex);
  }

  if (flow_entry->trafficClassAction)
  {
    printf("\tMPLS TC           = %d\n", flow_entry->trafficClass);
  }

  if (flow_entry->vlanIdAction)
  {
    printf("\tVLAN              = %d\n", flow_entry->vlanId);
  }

  printf("\tPOP CW            = %s\n", flow_entry->popCwAction ? "TRUE" : "FALSE");
  printf("\tPOP VLAN          = %s\n", flow_entry->popVlanAction ? "TRUE" : "FALSE");
  printf("\tPOP L2 HEADER     = %s\n", flow_entry->popL2HeaderAction ? "TRUE" : "FALSE");

  if (flow_entry->lmepIdAction)
  {
    printf("\tLMEP ID           = %d\n", flow_entry->lmepId);
  }

  if (0 != flow_entry->groupID)
  {
    printf("\tGROUP             = 0x%08x\n", flow_entry->groupID);
  }
}

static const displayFlow_t displayFlow = displayMPLS;

static void updateFlow(ofdpaFlowEntry_t *flow, arguments_t *arguments)
{
  memcpy(&flow->flowData.mplsFlowEntry,
         &arguments->flow.flowData.mplsFlowEntry,
         sizeof (flow->flowData.mplsFlowEntry));
}

static void copyFlow(ofdpaFlowEntry_t *flow)
{
  flow->flowData.terminationMacFlowEntry.outputPort = OFDPA_PORT_CONTROLLER;
}

static void listOrDeleteFlows(ofdpaFlowEntry_t *flow, arguments_t *arguments)
{
  int i = 0;
  OFDPA_ERROR_t rc;
  ofdpaFlowEntryStats_t flowStats;

  rc = ofdpaFlowStatsGet(flow, &flowStats);
  if (OFDPA_E_NONE != rc)
  {
    rc = ofdpaFlowNextGet(flow, flow);
  }
  while (OFDPA_E_NONE == rc)
  {
    i++;
    printf("%slow number %d.\r\n", arguments->delete ? "Deleting f" : "F", i);
    printf("\tCURRENT TABLE:  %d\n", arguments->mpls_table);
    displayFlow(flow);

    if (arguments->delete)
    {
      rc = ofdpaFlowDelete(flow);
      if (0 != rc)
      {
        printf("\r\nError deleting %s flow entry rc = %d.\r\n",
               flow_table_name, rc);
      }
    }
    if ((0 == arguments->count) || (i < arguments->count))
    {
      rc = ofdpaFlowNextGet(flow, flow);
    }
    else
    {
      rc = OFDPA_E_NOT_FOUND;
    }
  }
  if ((0 != arguments->list) && (OFDPA_E_NOT_FOUND == rc) && (i < arguments->count))
  {

    printf("\r\nNo more entries found.\r\n");
  }
}

static OFDPA_ERROR_t addFlows(ofdpaFlowEntry_t *flow, arguments_t *arguments)
{
  int i = 0;
  OFDPA_ERROR_t rc;

  for (i = 0; i < arguments->count; i++)
  {
    rc = ofdpaFlowAdd(flow);

    if (0 != rc)
    {
      printf("\r\nFailed to add %s flow entry. rc = %d.\r\n",
             flow_table_name, rc);
      displayFlow(flow);
      break;
    }
  }
  return rc;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  arguments_t *arguments = state->input;
  struct in_addr addr;
  struct in6_addr addr6;
  uint32_t prefixLen;
  uint32_t i;
  ofdpaMplsFlowEntry_t *const flow_entry = &arguments->flow.flowData.mplsFlowEntry;

  switch (key)
  {
  case KEY_COUNT:
    errno = 0;
    arguments->count = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid count \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_MPLS_TABLE:
    errno = 0;
    arguments->mpls_table = strtoul(arg, NULL, 0);
    if ((0 != errno) || (arguments->mpls_table > 1))
    {
      argp_error(state, "Invalid MPLS flow table number \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_ETHERTYPE:
    errno = 0;
    flow_entry->match_criteria.etherType = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid ethertype \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_MPLS_BOS:
    flow_entry->match_criteria.mplsBos = 1;
    break;

  case KEY_MPLS_LABEL:
    errno = 0;
    flow_entry->match_criteria.mplsLabel = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid MPLS label \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_INPORT:
    errno = 0;
    flow_entry->match_criteria.inPort = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid inport \"%s\"", arg);
      return errno;
    }
    flow_entry->match_criteria.inPortMask = OFDPA_INPORT_EXACT_MASK;
    break;

  case KEY_INPORT_MASK:
    errno = 0;
    if (0 == strcasecmp("exact", arg))
    {
      flow_entry->match_criteria.inPortMask = OFDPA_INPORT_EXACT_MASK;
    }
    else if (0 == strcasecmp("type", arg))
    {
      flow_entry->match_criteria.inPortMask = OFDPA_INPORT_TYPE_MASK;
    }
    else
    {
        argp_error(state, "Invalid interface mask value \"%s\" (can be \"exact\" or \"type\"))", arg);
        return errno;
    }
    break;

  case KEY_MPLS_TTL:
    errno = 0;
    flow_entry->match_criteria.mplsTtl = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid MPLS TTL \"%s\"", arg);
      return errno;
    }
    flow_entry->match_criteria.mplsTtlMask = 0xff;
    break;

  case KEY_MPLS_DATA_FIRST_NIBBLE:
    errno = 0;
    flow_entry->match_criteria.mplsDataFirstNibble = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid MPLS Data First Nibble \"%s\"", arg);
      return errno;
    }
    flow_entry->match_criteria.mplsDataFirstNibbleMask = 0xff;
    break;

  case KEY_MPLS_ACH_CHANNEL:
    errno = 0;
    flow_entry->match_criteria.mplsAchChannel = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid MPLS ACH Channel \"%s\"", arg);
      return errno;
    }
    flow_entry->match_criteria.mplsAchChannelMask = 0xffff;
    break;

  case KEY_NEXT_LABEL_IS_GAL:
    errno = 0;
    flow_entry->match_criteria.nextLabelIsGal = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid Next Label GAL \"%s\"", arg);
      return errno;
    }
    flow_entry->match_criteria.nextLabelIsGalMask = 0xff;
    break;

  case KEY_DEST_IPV4:
    if (1 == inet_pton(AF_INET, arg, &addr))
    {
      flow_entry->match_criteria.destIp4 = ntohl(addr.s_addr);
    }
    else
    {
      errno = 0;
      flow_entry->match_criteria.destIp4 = strtoul(arg, NULL, 0);
      if (0 != errno)
      {
        argp_error(state, "Invalid Destination IPv4 address \"%s\"", arg);
        return errno;
      }
    }
    break;

  case KEY_DEST_IPV4MASK:
    errno = 0;
    prefixLen = strtoul(arg, NULL, 0);
    if (errno != 0 || prefixLen > 32)
    {
     argp_error(state, "Invalid destination IPv4 prefix length \"%s\"", arg);
     return errno;
    }

    flow_entry->match_criteria.destIp4Mask = (~0 << (32 - prefixLen));
    break;

  case KEY_DEST_IPV6:
    errno = 0;
    if (0 == inet_pton(AF_INET6, arg, &addr6))
    {
      argp_error(state, "Invalid Destination IPv6 address \"%s\"", arg);
      return errno;
    }
    else
    {
      memcpy(flow_entry->match_criteria.destIp6.s6_addr, addr6.s6_addr, sizeof(flow_entry->match_criteria.destIp6.s6_addr));
    }
    break;

  case KEY_DEST_IPV6_PREFIX:
    errno = 0;
    prefixLen = strtoul(arg, NULL, 0);
    if (errno != 0 || prefixLen > 128)
    {
     argp_error(state, "Invalid Destination IPv6 prefix length \"%s\"", arg);
     return errno;
    }
    for (i = 0; i < prefixLen / 32; i++)
    {
     flow_entry->match_criteria.destIp6Mask.s6_addr32[i] = ~0;
    }
    if (0 != (prefixLen % 32))
    {
      flow_entry->match_criteria.destIp6Mask.s6_addr32[i] = (~0 << (prefixLen % 32));
    }
    break;

  case KEY_IP_PROTO:
    errno = 0;
    flow_entry->match_criteria.ipProto = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid IP Protocol \"%s\"", arg);
      return errno;
    }
    flow_entry->match_criteria.ipProtoMask = 0xff;
    break;

  case KEY_UDP_SRC_PORT:
    errno = 0;
    flow_entry->match_criteria.udpSrcPort = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid UDP Source Port \"%s\"", arg);
      return errno;
    }
    flow_entry->match_criteria.udpSrcPortMask = 0xffff;
    break;

  case KEY_UDP_SRC_PORT_MASK:
    errno = 0;
    flow_entry->match_criteria.udpSrcPortMask = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid UDP Source Port Mask \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_UDP_DST_PORT:
    errno = 0;
    flow_entry->match_criteria.udpDstPort = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid UDP Destination Port \"%s\"", arg);
      return errno;
    }
    flow_entry->match_criteria.udpDstPortMask = 0xffff;
    break;

  case KEY_UDP_DST_PORT_MASK:
    errno = 0;
    flow_entry->match_criteria.udpDstPortMask = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid UDP Destination Port Mask\"%s\"", arg);
      return errno;
    }
    break;

  case KEY_GOTO:
    errno = 0;
    flow_entry->gotoTableId = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid goto table id \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_POP_MPLS_LABEL:
    errno = 0;
    flow_entry->popLabelAction = 1;
    flow_entry->newEtherType = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid ethertype \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_POP_CW:
    flow_entry->popCwAction = 1;
    break;

  case KEY_POP_VLAN:
    flow_entry->popVlanAction = 1;
    break;

  case KEY_POP_L2:
    flow_entry->popL2HeaderAction = 1;
    break;

  case KEY_DEC_TTL:
    flow_entry->decrementTtlAction = 1;
    break;

  case KEY_CP_TTL_IN:
    flow_entry->copyTtlInAction = 1;
    break;

  case KEY_CP_TC_IN:
    flow_entry->copyTcInAction = 1;
    break;

  case KEY_SET_VRF:
    errno = 0;
    flow_entry->vrfAction = 1;
    flow_entry->vrf = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid VRF \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_MPLS_L2:
    errno = 0;
    flow_entry->mplsL2PortAction = 1;
    flow_entry->mplsL2Port = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid MPLS L2 port\"%s\"", arg);
      return errno;
    }
    break;

  case KEY_TUN_ID:
    errno = 0;
    flow_entry->tunnelIdAction = 1;
    flow_entry->tunnelId = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid tunnel ID \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_QOS:
    errno = 0;
    flow_entry->qosIndexAction = 1;
    flow_entry->qosIndex = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid QoS \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_TC:
    errno = 0;
    flow_entry->trafficClass = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid traffic class\"%s\"", arg);
      return errno;
    }
    flow_entry->trafficClassAction = 1;
    break;

  case KEY_VLAN_ID:
    errno = 0;
    flow_entry->vlanId = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid vlan id\"%s\"", arg);
      return errno;
    }
    flow_entry->vlanIdAction = 1;
    break;

  case KEY_LMEP_ID:
    errno = 0;
    flow_entry->lmepIdAction = 1;
    flow_entry->lmepId = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid LMEP ID\"%s\"", arg);
      return errno;
    }
    break;

  case KEY_GROUP:
    errno = 0;
    flow_entry->groupID = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid group ID \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_DISCARD: /* discard */
    arguments->discard = 1;
    break;

  case KEY_COPY: /* copy */
    arguments->copy = 1;
    break;

  case ARGP_KEY_ARG:
    if (0 == strcasecmp(ARG_DELETE, arg))
    {
      arguments->delete = 1;
    }
    else if (0 == strcasecmp(ARG_LIST, arg))
    {
      arguments->list = 1;
    }
    else
    {
      argp_error(state, "Unknown option \"%s\"", arg);
    }
    break;

  case ARGP_KEY_NO_ARGS:
  case ARGP_KEY_END:

    if ((0 == arguments->list) && (0 == arguments->delete))
    {
      if (arguments->count == 0)
      {
        argp_error(state, "Add operation requires non-zero value for count parameter.");
      }
    }
    break;

  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

int
main(int argc, char *argv[])
{
  int rc;
  char docBuffer[500];
  ofdpaFlowEntry_t flow;

  arguments_t arguments = {
    .count = DEFAULT_COUNT,
    .mpls_table = DEFAULT_MPLS_TABLE,
    .discard = 0,
    .priority = DEFAULT_PRIORITY,
    .copy = 0,
    .delete = 0,
    .list = 0,
    /* Matches */
    .flow.flowData.mplsFlowEntry.match_criteria.etherType = DEFAULT_ETHERTYPE,
    .flow.flowData.mplsFlowEntry.match_criteria.mplsBos = DEFAULT_MPLS_BOS,
    .flow.flowData.mplsFlowEntry.match_criteria.mplsLabel = DEFAULT_MPLS_LABEL,
    .flow.flowData.mplsFlowEntry.match_criteria.inPort = DEFAULT_INPORT,
    .flow.flowData.mplsFlowEntry.match_criteria.inPortMask = DEFAULT_INPORT_MASK,
    .flow.flowData.mplsFlowEntry.match_criteria.mplsTtl = DEFAULT_MPLS_TTL,
    .flow.flowData.mplsFlowEntry.match_criteria.mplsTtlMask = DEFAULT_MPLS_TTL_MASK,
    .flow.flowData.mplsFlowEntry.match_criteria.mplsDataFirstNibble = DEFAULT_MPLS_DATA_FIRST_NIBBLE,
    .flow.flowData.mplsFlowEntry.match_criteria.mplsDataFirstNibbleMask = DEFAULT_MPLS_DATA_FIRST_NIBBLE_MASK,
    .flow.flowData.mplsFlowEntry.match_criteria.mplsAchChannel = DEFAULT_MPLS_ACH_CHANNEL,
    .flow.flowData.mplsFlowEntry.match_criteria.mplsAchChannelMask = DEFAULT_MPLS_ACH_CHANNEL_MASK,
    .flow.flowData.mplsFlowEntry.match_criteria.nextLabelIsGal = DEFAULT_NEXT_LABEL_IS_GAL,
    .flow.flowData.mplsFlowEntry.match_criteria.nextLabelIsGalMask = DEFAULT_NEXT_LABEL_IS_GAL_MASK,
    .flow.flowData.mplsFlowEntry.match_criteria.destIp4 = DEFAULT_DESTIP4,
    .flow.flowData.mplsFlowEntry.match_criteria.destIp4Mask = DEFAULT_DESTIP4_MASK,
    .flow.flowData.mplsFlowEntry.match_criteria.ipProto = DEFAULT_IP_PROTO,
    .flow.flowData.mplsFlowEntry.match_criteria.ipProtoMask = DEFAULT_IP_PROTO_MASK,
    .flow.flowData.mplsFlowEntry.match_criteria.udpSrcPort = DEFAULT_UDP_SRC_PORT,
    .flow.flowData.mplsFlowEntry.match_criteria.udpSrcPortMask = DEFAULT_UDP_SRC_PORT_MASK,
    .flow.flowData.mplsFlowEntry.match_criteria.udpDstPort= DEFAULT_UDP_DEST_PORT,
    .flow.flowData.mplsFlowEntry.match_criteria.udpDstPortMask = DEFAULT_UDP_DEST_PORT_MASK,

    /* Apply actions */
    .flow.flowData.mplsFlowEntry.gotoTableId = DEFAULT_GOTO_TABLE_ID,
    .flow.flowData.mplsFlowEntry.popLabelAction = DEFAULT_POP_MPLS_LABEL,
    .flow.flowData.mplsFlowEntry.newEtherType = DEFAULT_ETHERTYPE,
    .flow.flowData.mplsFlowEntry.decrementTtlAction = DEFAULT_DEC_TTL_ACT,
    .flow.flowData.mplsFlowEntry.copyTtlInAction = DEFAULT_CP_TTL_ACT,
    .flow.flowData.mplsFlowEntry.copyTcInAction = DEFAULT_CP_TC_ACT,
    .flow.flowData.mplsFlowEntry.vrfAction = DEFAULT_VRF_ACT,
    .flow.flowData.mplsFlowEntry.vrf = DEFAULT_VRF,
    .flow.flowData.mplsFlowEntry.mplsL2PortAction = DEFAULT_MPLS_L2_PORT_ACT,
    .flow.flowData.mplsFlowEntry.mplsL2Port = DEFAULT_MPLS_L2_PORT,
    .flow.flowData.mplsFlowEntry.tunnelIdAction = DEFAULT_TUNNELID_ACT,
    .flow.flowData.mplsFlowEntry.tunnelId = DEFAULT_TUNNELID,
    .flow.flowData.mplsFlowEntry.qosIndexAction = DEFAULT_QOS_ACT,
    .flow.flowData.mplsFlowEntry.qosIndex = DEFAULT_QOS,
    .flow.flowData.mplsFlowEntry.trafficClassAction = DEFAULT_TC_ACT,
    .flow.flowData.mplsFlowEntry.trafficClass = DEFAULT_TC,
    .flow.flowData.mplsFlowEntry.vlanIdAction = DEFAULT_VLAN_ID_ACT,
    .flow.flowData.mplsFlowEntry.vlanId = DEFAULT_VLAN_ID,
    .flow.flowData.mplsFlowEntry.popCwAction = DEFAULT_POP_CW,
    .flow.flowData.mplsFlowEntry.popVlanAction = DEFAULT_POP_VLAN,
    .flow.flowData.mplsFlowEntry.popL2HeaderAction = DEFAULT_POP_L2_HEADER,
    .flow.flowData.mplsFlowEntry.lmepIdAction = DEFAULT_LMEP_ID_ACT,
    .flow.flowData.mplsFlowEntry.lmepId = DEFAULT_LMEP_ID,
    /* Write actions */
    .flow.flowData.mplsFlowEntry.groupID = DEFAULT_GROUP_ID,
  };

  /* Our argp parser. */
  struct argp argp = {
    .doc = docBuffer,
    .options = options,
    .parser = parse_opt,
    .args_doc = "[" ARG_DELETE "] [" ARG_LIST "]",
  };

  printDefaults(docBuffer, sizeof(docBuffer));

  /*
  Parse our arguments:
  every option seen by 'parse_opt' will be reflected in 'arguments'.
   */
  rc = argp_parse(&argp, argc, argv, 0, 0, &arguments);
  {
    if (0 != rc)
      return rc;
  }

  rc = ofdpaClientInitialize(client_name);
  if (OFDPA_E_NONE != rc)
  {
    return rc;
  }

  if (0 == arguments.mpls_table)
  {
    rc = ofdpaFlowEntryInit(OFDPA_FLOW_TABLE_ID_MPLS_0, &flow);
  }
  if (1 == arguments.mpls_table)
  {
    rc = ofdpaFlowEntryInit(OFDPA_FLOW_TABLE_ID_MPLS_1, &flow);
  }
  if (rc != OFDPA_E_NONE)
  {
    printf("\r\nFailed to initialize %s_%dFlow Table.(rc = %d)\n",
           flow_table_name, arguments.mpls_table, rc);
    return rc;
  }

  if (0 == arguments.list)
  {
    if (0 == arguments.discard)
    {
      updateFlow(&flow, &arguments);
    }
    if (0 != arguments.copy)
    {
      copyFlow(&flow);
    }
    flow.priority = arguments.priority;
  }

  if (arguments.list || arguments.delete)
  {
    printf("%s up to %u %s flows.\r\n",
           arguments.list ? "Listing" : "Deleting",
           arguments.count,
           flow_table_name);
    listOrDeleteFlows(&flow, &arguments);
  }
  else
  {
    printf("Adding %u %s flows with the following parameters:\r\n",
           arguments.count,
           flow_table_name);
    printf("\tCURRENT TABLE:  %d\n", arguments.mpls_table);
    displayFlow(&flow);
    addFlows(&flow, &arguments);
  }
  return rc;
}
