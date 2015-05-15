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
* @filename     client_vlan.c
*
* @purpose      Example code for VLAN Flow Table
*
* @component    Unit Test
*
* @comments
*
* @create       26 Apr 2013
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

#define VERSION              2.0
#define ARG_DELETE "delete"
#define ARG_LIST  "list"

static char flow_table_name[] = "VLAN";
static char client_name[] = "ofdpa client";

#define NO_ACTION 0
#define ACTION    1
#define DEFAULT_ZERO_MAC         {{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}

uint8_t multicastMac [] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x30 };
uint8_t multicastMask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0 };
uint8_t unicastMask  [] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

typedef enum
{
  DEFAULT_COUNT                 = 1,
  DEFAULT_VLANID                = 0x1001,
  DEFAULT_VLANIDMASK            = 0x1fff,
  DEFAULT_INPORT                = 1,
  DEFAULT_ETHERTYPE             = 0,
  DEFAULT_ETHERTYPE_MASK        = 0,

  DEFAULT_NEWVLANID             = 1,
  DEFAULT_VRF_ACT               = NO_ACTION,
  DEFAULT_VRF                   = 0,
  DEFAULT_VLAN2_ACT             = NO_ACTION,
  DEFAULT_VLAN2                 = 1,
  DEFAULT_PUSH_VLAN             = NO_ACTION,
  DEFAULT_TPID                  = 0,
  DEFAULT_POP_VLAN              = NO_ACTION,
  DEFAULT_OVID_ACT              = NO_ACTION,
  DEFAULT_OVID                  = 0,
  DEFAULT_MPLSL2PORT_ACT        = NO_ACTION,
  DEFAULT_MPLSL2PORT            = 0,
  DEFAULT_TUNNELID_ACT          = NO_ACTION,
  DEFAULT_TUNNELID              = 0,
  DEFAULT_LMEP_ID_ACT           = 0,
  DEFAULT_LMEP_ID               = 0,
  DEFAULT_OAM_LM_COUNT_ACTION   = 0,
  DEFAULT_GOTO                  = OFDPA_FLOW_TABLE_ID_TERMINATION_MAC,

  DEFAULT_DISCARD               = NO_ACTION,
  DEFAULT_DELETE                = NO_ACTION,
  DEFAULT_LIST                  = NO_ACTION,
} CLIENT_VLAN_DEFAULT_VALUES_ENUM;

typedef enum
{
  KEY_FLOW_COUNT    = 'c',
  KEY_VLAN_MATCH    = 'v', 
  KEY_VLAN_MASK     = 'm',
  KEY_IN_PORT       = 'i',
  KEY_ETHERTYPE     = 'e',
  KEY_DESTMAC       = 'a',
  KEY_DISCARD       = 'd',
  KEY_NEW_VLAN      = 'n',
  KEY_SET_TUNNEL_ID = 't',
  KEY_SET_MPLS_PORT = 'p',
  KEY_SET_LMEP_ID   = 'l',
  KEY_OAM_LM_COUNT  = 'o',
  KEY_GOTO_TABLE    = 'g',

  KEY_SET_VRF       = 1000,
  KEY_SET_OVID,
  KEY_PUSH_VLAN,
  KEY_POP_VLAN,
} CLIENT_VLAN_ARGP_ENUM;

typedef struct
{
  int               count;
  int               delete;
  int               list;
  int               discard;
  ofdpaFlowEntry_t  flow;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  /* long-short-arg-flag-doc-group */
  { "count",    KEY_FLOW_COUNT,     "COUNT",        0,  "Number of flows to add.",  0 },
  { 0,          0,                  0,              0,  "Matches:",                 0 },
  { "vlan",     KEY_VLAN_MATCH,     "VLANID",       0,  "VLAN.",                    0 },
  { "mask",     KEY_VLAN_MASK,      "VLANIDMASK",   0,  "VLAN mask.",               0 },
  { "intf",     KEY_IN_PORT,        "INTF",         0,  "Ingress port.",            0 },
  { "ether",    KEY_ETHERTYPE,      "ETHERTYPE",    0,  "Ethertype.",               0 },
  { "dstmac",   KEY_DESTMAC,        "DESTMAC",      0,  "Destination MAC",          0 },
  { 0,          0,                  0,              0,  "Actions:",                 0 },
  { "newvlan",  KEY_NEW_VLAN,       "VLANID",       0,  "Set VLAN.",                0 },
  { "vrf",      KEY_SET_VRF,        "VRF",          0,  "Set VRF.",                 0 },
  { "ovid",     KEY_SET_OVID,       "VLANID",       0,  "Set outer VLAN.",          0 },
  { "mplsPort", KEY_SET_MPLS_PORT,  "MPLSPORT",     0,  "Set MPLS L2 Port.",        0 },
  { "tunnel",   KEY_SET_TUNNEL_ID,  "TUNNELID",     0,  "Set tunnel ID.",           0 },
  { "lmepid ",  KEY_SET_LMEP_ID,    "LMEPID",       0,  "Set LMEP ID.",             0 },
  { "oamlmcount", KEY_OAM_LM_COUNT, 0,              0,  "Increment LM counters.",   0 },
  { "pushvlan", KEY_PUSH_VLAN,      "TPID",         0,  "Push VLAN.",               0 },
  { "popvlan",  KEY_POP_VLAN,       0,              0,  "Pop VLAN.",                0 },
  { "goto",     KEY_GOTO_TABLE,     "TABLEID",      0,  "Goto table (13=MPLS Port, 20=Term Mac).",0 },
  { "discard",  KEY_DISCARD,        0,              0,  "Discard matching flows.",  0 },
  { 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state);
static void listOrDeleteFlows(ofdpaFlowEntry_t *flow, const arguments_t * const arguments);
static OFDPA_ERROR_t addFlows(ofdpaFlowEntry_t *flow, const arguments_t * const arguments);
static void updateFlow(ofdpaFlowEntry_t *flow, const arguments_t * const arguments);
static void discardFlow(ofdpaFlowEntry_t *flow, const arguments_t * const arguments);
static void incrementVlan(ofdpaFlowEntry_t *flow, const arguments_t * const arguments);
static void printDefaults(char * const docBuffer, const int length);
static void displayVlan(const ofdpaFlowEntry_t * const flow);

typedef void (*displayFlow_t)(const ofdpaFlowEntry_t* const);
static const displayFlow_t displayFlow = displayVlan;


error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  arguments_t *arguments = state->input;
  union
  {
    unsigned char  bytes[6];
    unsigned short shorts[3];
  } mac;

  ofdpaVlanFlowEntry_t *const flow_entry = &arguments->flow.flowData.vlanFlowEntry;
  
  switch (key)
  {
  case KEY_FLOW_COUNT:
    errno = 0;
    arguments->count = strtoul(arg, NULL, 0);
    if ( 0 != errno )
    {
      argp_error(state, "Invalid count \"%s\"", arg);
      return errno;
    }
    break;

    /* Matches */
  case KEY_IN_PORT:
    errno = 0;
    flow_entry->match_criteria.inPort = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid ingress port\"%s\"", arg);
      return errno;
    }
    break;

  case KEY_VLAN_MATCH:
    errno = 0;
    flow_entry->match_criteria.vlanId = strtoul(arg, NULL, 0);
    if (0 != errno )
    {
      argp_error(state, "Invalid VLAN ID \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_VLAN_MASK:
    errno = 0;
    flow_entry->match_criteria.vlanIdMask = strtoul(arg, NULL, 0);
    if (0 !=  errno)
    {
      argp_error(state, "Invalid VLAN mask \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_ETHERTYPE:
    errno = 0;
    flow_entry->match_criteria.etherType = strtoul(arg, NULL, 0);
    if (0 !=  errno)
    {
      argp_error(state, "Invalid Ethertype value \"%s\"", arg);
      return errno;
    }
    flow_entry->match_criteria.etherTypeMask = OFDPA_ETHERTYPE_EXACT_MASK;
    break;

  case KEY_DESTMAC:
    if (6 != sscanf(arg, " %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx ",
                    &mac.bytes[0], &mac.bytes[1], &mac.bytes[2], &mac.bytes[3], &mac.bytes[4], &mac.bytes[5]))
    {
      if (6 != sscanf(arg, " %2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx ",
                      &mac.bytes[0], &mac.bytes[1], &mac.bytes[2], &mac.bytes[3], &mac.bytes[4], &mac.bytes[5]))
      {
        if (3 != sscanf(arg, " %4hx.%4hx.%4hx ", &mac.shorts[0], &mac.shorts[1], &mac.shorts[2]))
        {
          argp_error(state, "Invalid destination MAC address \"%s\"", arg);
          return errno;
        }
        else
        {
          /* successfully converted address string to short int values, need to handle endian issues here */
          mac.shorts[0] = htons(mac.shorts[0]);
          mac.shorts[1] = htons(mac.shorts[1]);
          mac.shorts[2] = htons(mac.shorts[2]);
        }
      }
    }
    memcpy(flow_entry->match_criteria.destMac.addr, mac.bytes, sizeof(flow_entry->match_criteria.destMac.addr));

    mac.bytes[5] = 0;
    /* MAC could be 01-80-C2-00-00-3X multicast */
    if (memcmp(&mac, &multicastMac, sizeof(ofdpaMacAddr_t)) == 0)
    {
      memcpy(flow_entry->match_criteria.destMacMask.addr, multicastMac, sizeof(flow_entry->match_criteria.destMacMask.addr));
    }
    else if (0 != (mac.bytes[0] & 0x01))
    {
      argp_error(state, "Invalid multicast MAC address \"%s\", should be 01-80-C2-00-00-3X", arg);
    }
    else
    {
      memcpy(flow_entry->match_criteria.destMacMask.addr, unicastMask, sizeof(flow_entry->match_criteria.destMacMask.addr));
    }
    break;

/* Actions */
  case KEY_NEW_VLAN:
    errno = 0;
    flow_entry->newVlanId = strtoul(arg, NULL, 0);
    if ( 0 != errno )
    {
      argp_error(state, "Invalid VLAN ID \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_SET_VRF:
    errno = 0;
    flow_entry->vrfAction  = ACTION;
    flow_entry->vrf = strtoul(arg, NULL, 0);
    if (0 !=  errno)
    {
      argp_error(state, "Invalid VRF \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_SET_OVID:
    errno = 0;
    flow_entry->brcmOvidAction = ACTION;
    flow_entry->brcmOvid = strtoul(arg, NULL, 0);
    if (0 !=  errno)
    {
      argp_error(state, "Invalid OVID \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_SET_MPLS_PORT:
    errno = 0;
    flow_entry->mplsL2PortAction = ACTION;
    flow_entry->mplsL2Port = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid MPLS L2 Port \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_SET_TUNNEL_ID:
    errno = 0;
    flow_entry->tunnelIdAction = ACTION;
    flow_entry->tunnelId = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid Tunnel ID \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_POP_VLAN:
    flow_entry->popVlanAction = ACTION;
    break;

  case KEY_PUSH_VLAN:
    errno = 0;
    flow_entry->pushVlan2Action = ACTION;
    flow_entry->newTpid2 = strtoul(arg, NULL, 0);
    if (0 !=  errno)
    {
      argp_error(state, "Invalid TPID \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_GOTO_TABLE:
    errno = 0;
    flow_entry->gotoTableId = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid goto table ID \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_SET_LMEP_ID:
    errno = 0;
    flow_entry->lmepId = strtoul(arg, NULL, 0);
    if (0 != errno)
    {
      argp_error(state, "Invalid LMEP ID \"%s\"", arg);
      return errno;
    }
    flow_entry->lmepIdAction = 1;
    break;

  case KEY_OAM_LM_COUNT:
    errno = 0;
    flow_entry->oamLmTxCountAction = ACTION;
    break;

  case KEY_DISCARD:
    arguments->discard = ACTION;
    break;

  case ARGP_KEY_ARG:
    if (0 == strcasecmp(ARG_DELETE, arg))
    {
      arguments->delete = ACTION;
    }
    else if (0 == strcasecmp(ARG_LIST, arg))
    {
      arguments->list = ACTION;
    }
    else
    {
      argp_error(state, "Unknown option \"%s\"", arg);
    }
    break;

  case ARGP_KEY_NO_ARGS:
  case ARGP_KEY_END:
    break;

  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static void displayVlan(const ofdpaFlowEntry_t * const flow)
{
  printf("MATCHES:\n");
  printf("\tVLANID       = 0x%4.4x\n", flow->flowData.vlanFlowEntry.match_criteria.vlanId);
  printf("\tVLANIDMASK   = 0x%4.4x\n", flow->flowData.vlanFlowEntry.match_criteria.vlanIdMask);
  printf("\tINTERFACE    = %d\n",      flow->flowData.vlanFlowEntry.match_criteria.inPort);
  if (flow->flowData.vlanFlowEntry.match_criteria.etherTypeMask != OFDPA_ETHERTYPE_ALL_MASK)
  {
    printf("\tETHERTYPE    = 0x%x\n",      flow->flowData.vlanFlowEntry.match_criteria.etherType);
  }
  if (!(OFDPA_MAC_ADDR_IS_NULL(flow->flowData.vlanFlowEntry.match_criteria.destMacMask.addr)))
  {
    printf("\tDestination MAC address  = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x\r\n",
           flow->flowData.vlanFlowEntry.match_criteria.destMac.addr[0],
           flow->flowData.vlanFlowEntry.match_criteria.destMac.addr[1],
           flow->flowData.vlanFlowEntry.match_criteria.destMac.addr[2],
           flow->flowData.vlanFlowEntry.match_criteria.destMac.addr[3],
           flow->flowData.vlanFlowEntry.match_criteria.destMac.addr[4],
           flow->flowData.vlanFlowEntry.match_criteria.destMac.addr[5]);
    printf("\tDestination MAC mask     = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x\r\n",
           flow->flowData.vlanFlowEntry.match_criteria.destMacMask.addr[0],
           flow->flowData.vlanFlowEntry.match_criteria.destMacMask.addr[1],
           flow->flowData.vlanFlowEntry.match_criteria.destMacMask.addr[2],
           flow->flowData.vlanFlowEntry.match_criteria.destMacMask.addr[3],
           flow->flowData.vlanFlowEntry.match_criteria.destMacMask.addr[4],
           flow->flowData.vlanFlowEntry.match_criteria.destMacMask.addr[5]);
  }

  printf("ACTIONS:\n");
  printf("\tGOTO TABLE   = %d\n",      flow->flowData.vlanFlowEntry.gotoTableId);
  printf("\tNEW VLAN     = %d\n",      flow->flowData.vlanFlowEntry.newVlanId);
  const ofdpaVlanFlowEntry_t * const flow_entry = &flow->flowData.vlanFlowEntry;
  
  if (NO_ACTION != flow_entry->setVlanId2Action)
  {
    printf("\tNEW VLAN2       = %d\n", flow_entry->newVlanId2);
  }

  if (NO_ACTION != flow_entry->vrfAction)
  {
    printf("\tVRF             = %d\n", flow_entry->vrf);
  }

  if (NO_ACTION != flow_entry->brcmOvidAction)
  {
    printf("\tOVID            = %d\n", flow_entry->brcmOvid);
  }

  if (NO_ACTION != flow_entry->pushVlan2Action)
  {
    printf("\tPUSH VLAN       = %d\n", flow_entry->newTpid2);
  }

  printf("\tPOP VLAN        = %s\n", flow_entry->popVlanAction ? "TRUE" : "FALSE");

  if (NO_ACTION != flow_entry->mplsL2PortAction)
  {
    printf("\tMPLS L2 PORT    = 0x%8x\n", flow_entry->mplsL2Port);
  }

  if (NO_ACTION != flow_entry->tunnelIdAction)
  {
    printf("\tTUNNEL ID       = 0x%8x\n", flow_entry->tunnelId);
  }

  if (NO_ACTION != flow_entry->lmepIdAction)
  {
    printf("\tLMEP ID         = %d\n", flow_entry->lmepId);
  }

  if (NO_ACTION != flow_entry->oamLmTxCountAction)
  {
    printf("\tOAM LM TX COUNT = %d\n", flow_entry->oamLmTxCountAction);
    printf("\tLMEP ID         = %d\n", flow_entry->lmepId);
  }

}

int main(int argc, char *argv[])
{
  OFDPA_ERROR_t         rc;
  char                  docBuffer[300];
  char                  versionBuf[100];
  ofdpaFlowEntry_t      flow;

  arguments_t arguments =
  {
    .count      = DEFAULT_COUNT,
    .list       = NO_ACTION,
    .discard    = NO_ACTION,
    .delete     = NO_ACTION,
    /* VLAN */
    /* Matches */
    .flow.flowData.vlanFlowEntry.match_criteria.vlanId = DEFAULT_VLANID,
    .flow.flowData.vlanFlowEntry.match_criteria.vlanIdMask = DEFAULT_VLANIDMASK,
    .flow.flowData.vlanFlowEntry.match_criteria.inPort = DEFAULT_INPORT,
    .flow.flowData.vlanFlowEntry.match_criteria.etherTypeMask = DEFAULT_ETHERTYPE_MASK,
    .flow.flowData.vlanFlowEntry.match_criteria.destMac = DEFAULT_ZERO_MAC,
    .flow.flowData.vlanFlowEntry.match_criteria.destMacMask = DEFAULT_ZERO_MAC,
    /* Actions */
    .flow.flowData.vlanFlowEntry.newVlanId = DEFAULT_NEWVLANID,

    .flow.flowData.vlanFlowEntry.brcmOvidAction = DEFAULT_OVID_ACT,
    .flow.flowData.vlanFlowEntry.brcmOvid = DEFAULT_OVID,

    .flow.flowData.vlanFlowEntry.pushVlan2Action = DEFAULT_PUSH_VLAN,
    .flow.flowData.vlanFlowEntry.newTpid2 = DEFAULT_TPID,

    .flow.flowData.vlanFlowEntry.setVlanId2Action =  DEFAULT_VLAN2_ACT,
    .flow.flowData.vlanFlowEntry.newVlanId2 = DEFAULT_VLAN2,

    .flow.flowData.vlanFlowEntry.popVlanAction = DEFAULT_POP_VLAN,

    .flow.flowData.vlanFlowEntry.mplsL2PortAction = DEFAULT_MPLSL2PORT_ACT,
    .flow.flowData.vlanFlowEntry.mplsL2Port = DEFAULT_MPLSL2PORT,

    .flow.flowData.vlanFlowEntry.tunnelIdAction = DEFAULT_TUNNELID_ACT,
    .flow.flowData.vlanFlowEntry.tunnelId = DEFAULT_TUNNELID,

    .flow.flowData.vlanFlowEntry.lmepIdAction = DEFAULT_LMEP_ID_ACT,
    .flow.flowData.vlanFlowEntry.lmepIdAction = DEFAULT_LMEP_ID,

    .flow.flowData.vlanFlowEntry.oamLmTxCountAction = DEFAULT_OAM_LM_COUNT_ACTION,

    .flow.flowData.vlanFlowEntry.gotoTableId = DEFAULT_GOTO,
  };

  /* Our argp parser. */
  struct argp argp =
  {
    .doc      = docBuffer,
    .options  = options,
    .parser   = parse_opt,
    .args_doc = "[" ARG_DELETE "] [" ARG_LIST "]",
  };

  sprintf(versionBuf, "%s v%.1f", basename(strdup(__FILE__)), VERSION);
  argp_program_version = versionBuf;

  printDefaults(docBuffer, sizeof(docBuffer));

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

  rc = ofdpaFlowEntryInit(OFDPA_FLOW_TABLE_ID_VLAN, &flow);
  if (OFDPA_E_NONE != rc)
  {
    printf("\r\nFailed to initialize %s Flow Table.(rc = %d)\n",
           flow_table_name, rc);
    return rc;
  }

  if (NO_ACTION == arguments.list)
  {
    updateFlow(&flow, &arguments);
    if (ACTION == arguments.discard)
    {
      discardFlow(&flow, &arguments);
    }
  }

  if ((ACTION == arguments.list) || (ACTION == arguments.delete))
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
    displayFlow(&flow);
    addFlows(&flow, &arguments);
  }
  return rc;
}

void listOrDeleteFlows(ofdpaFlowEntry_t *flow, const arguments_t * const arguments)
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
  if ((NO_ACTION == arguments->list) && (OFDPA_E_NOT_FOUND == rc) && (i < arguments->count))
  {
    printf("\r\nNo more entries found.\r\n");
  }
}

OFDPA_ERROR_t addFlows(ofdpaFlowEntry_t *flow, const arguments_t * const arguments)
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
    incrementVlan(flow, arguments);
  }
  return rc;
}

void updateFlow(ofdpaFlowEntry_t *flow, const arguments_t * const arguments)
{
  memcpy(&flow->flowData.vlanFlowEntry,
         &arguments->flow.flowData.vlanFlowEntry,
         sizeof (flow->flowData.vlanFlowEntry));
}

void discardFlow(ofdpaFlowEntry_t *flow, const arguments_t * const arguments)
{
  /* Set illegal table number */
  flow->flowData.vlanFlowEntry.gotoTableId = OFDPA_FLOW_TABLE_ID_INGRESS_PORT;
}

void incrementVlan(ofdpaFlowEntry_t *flow, const arguments_t * const arguments)
{
  flow->flowData.vlanFlowEntry.match_criteria.vlanId++;
}

void printDefaults(char * const docBuffer, const int length)
{
  int i = 0;

  i += snprintf(&docBuffer[i], length,    "VLAN flow.\vDefault values:\n");
  i += snprintf(&docBuffer[i], length - i,    "COUNT        = %d\n", DEFAULT_COUNT);

  i += snprintf(&docBuffer[i], length - i,    "VLANID       = 0x%x\n", DEFAULT_VLANID);
  i += snprintf(&docBuffer[i], length - i,    "VLANIDMASK   = 0x%x\n", DEFAULT_VLANIDMASK);
  i += snprintf(&docBuffer[i], length - i,    "IN PORT      = %d\n", DEFAULT_INPORT);

  i += snprintf(&docBuffer[i], length - i,    "NEW VLAN     = %d\n", DEFAULT_NEWVLANID);

  if (ACTION == DEFAULT_VRF_ACT)
  {
    i += snprintf(&docBuffer[i], length - i,  "VRF          = %d\n", DEFAULT_VRF);
  }

  if (ACTION == DEFAULT_OVID_ACT)
  {
    i += snprintf(&docBuffer[i], length - i,  "OVID         = %d\n", DEFAULT_OVID);
  }

  if (ACTION == DEFAULT_PUSH_VLAN)
  {
    i += snprintf(&docBuffer[i], length - i,  "TPID2        = %d\n", DEFAULT_TPID);
  }

  if (ACTION == DEFAULT_VLAN2_ACT)
  {
    i += snprintf(&docBuffer[i], length - i,  "VLAN ID 2    = %d\n", DEFAULT_VLANID);
  }

  i += snprintf(&docBuffer[i], length - i,    "POP VLAN     = %s\n", DEFAULT_POP_VLAN ? "TRUE" : "FALSE");

  if (ACTION == DEFAULT_MPLSL2PORT_ACT)
  {
    i += snprintf(&docBuffer[i], length - i,  "MPLS L2 PORT = %d\n", DEFAULT_MPLSL2PORT);
  }

  if (ACTION == DEFAULT_TUNNELID_ACT)
  {
    i += snprintf(&docBuffer[i], length - i,  "TUNNEL ID    = %d\n", DEFAULT_TUNNELID);
  }

  i += snprintf(&docBuffer[i], length - i,    "GOTO TABLE   = %d\n", DEFAULT_GOTO);
  i += snprintf(&docBuffer[i], length - i, "\n");
}
