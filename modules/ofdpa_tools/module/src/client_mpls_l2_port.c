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
* @filename     client_mpls_l2_port.c
*
* @purpose      Example code for MPLS L2 Port Flow Table. Uses RPC calls.
*
* @component    client example
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

#define VERSION              2.0

#define ARG_DELETE        "delete"
#define ARG_LIST          "list"

#define KEY_COUNT             1001
#define KEY_MPLSL2PORT        1002
#define KEY_MPLSL2PORTMASK    1003
#define KEY_TUNNELID          1004
#define KEY_SETGROUP          1005
#define KEY_GOTOTABLE         1006
#define KEY_QUEUEID           1007
#define KEY_QOSINDEX          1008
#define KEY_ETHERTYPE         1009

#define DEFAULT_COUNT         1
#define DEFAULT_MPLSL2PORT    1
#define DEFAULT_MPLSL2PORTMASK    OFDPA_MPLS_L2_PORT_EXACT_MASK
#define DEFAULT_TUNNELID      0x10001  /* MPLS_TP Tunnel */
#define DEFAULT_ETHERTYPE     0
#define DEFAULT_ETHERTYPEMASK OFDPA_ETHERTYPE_ALL_MASK
#define DEFAULT_DELETE        0
#define DEFAULT_LIST          0


typedef struct
{
  int      count;
  uint32_t mplsL2Port;
  uint32_t mplsL2PortMask;
  uint32_t tunnelId;
  uint16_t etherType;
  uint16_t etherTypeMask;
  uint32_t groupId;
  uint32_t qosIndex;
  uint32_t qosIndexAction;
  uint32_t gotoTableId;
  int      delete;
  int      list;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "count",           KEY_COUNT,          "COUNT",            0, "Number of MPLS L2 ports to add."                                              , },
  { "mplsl2port",      KEY_MPLSL2PORT,     "MPLSL2PORT",       0, "MPLS L2 port (VPWS/VPLS local port)."                       , },
  { "mplsl2portmask",  KEY_MPLSL2PORTMASK, "MPLSL2PORTMASK",   0, "MPLS L2 port mask."                                                           , },
  { "tunnel",          KEY_TUNNELID,       "TUNNELID",         0, "Tunnel ID (must match VLAN and MPLS flows)."                                  , },
  { "ethertype",       KEY_ETHERTYPE,      "ETHERTYPE",        0, "Ethertype (only for going to DSCP Trust table)."                              , },
  { 0,                 0,                  0,                  0, "Actions:"                                                                     , },
  { "goto",            KEY_GOTOTABLE,      "GOTO_TABLE",       0, "Next table ID."                                                               , },
  { "setgroup",        KEY_SETGROUP,       "GROUP",            0, "Set the output group for packets in this flow. Applicable for only VPWS type.", },
  { "qosIndex",        KEY_QOSINDEX,       "INDEX",            0, "Set the QoS Index to use in the QoS Trust table."                             , },
  { 0 }
};

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  /* Get the INPUT argument from `argp_parse', which we
     know is a pointer to our arguments structure. */
  arguments_t *arguments = state->input;

  switch(key)
  {
    case KEY_COUNT:                     /* count */
      errno = 0;
      arguments->count = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid count \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_MPLSL2PORT:                /* MPLS L2 port id */
      errno = 0;
      arguments->mplsL2Port = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid port number \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_MPLSL2PORTMASK:            /* MPLS L2 port id mask */
      errno = 0;
      if (0 == strcasecmp("exact", arg))
      {
        arguments->mplsL2PortMask = OFDPA_MPLS_L2_PORT_EXACT_MASK;
      }
      else if (0 == strcasecmp("type", arg))
      {
        arguments->mplsL2PortMask = OFDPA_MPLS_L2_PORT_TYPE_MASK;
      }
      else
      {
        argp_error(state, "Invalid MPLS L2 port mask value \"%s\" (can be \"exact\" or \"type\"))", arg);
        return errno;
      }

      break;

    case KEY_TUNNELID:                  /* Tunnel ID */
      errno = 0;
      arguments->tunnelId = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid tunnel ID \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_ETHERTYPE:                 /* Ethertype */
      errno = 0;
      arguments->etherType = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid Ethertype \"%s\"", arg);
        return errno;
      }
      if (0 == arguments->etherType)
      {
        arguments->etherTypeMask = OFDPA_ETHERTYPE_ALL_MASK;
      }
      else
      {
        arguments->etherTypeMask = OFDPA_ETHERTYPE_EXACT_MASK;
      }
      break;

    case KEY_SETGROUP:                  /* Group ID */
      arguments->groupId = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid group ID \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_GOTOTABLE:
      arguments->gotoTableId = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid goto table ID \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_QOSINDEX:
      arguments->qosIndex = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid QoS Index \"%s\"", arg);
        return errno;
      }
      arguments->qosIndexAction = 1;
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
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static void displayMplsL2Port(ofdpaFlowEntry_t *flow, int decodeGroup)
{
  char buf[200];

  printf("\tMPLS L2 PORT      = 0x%08x\n", flow->flowData.mplsL2PortFlowEntry.match_criteria.mplsL2Port);
  printf("\tMPLS L2 PORT Mask = 0x%08x\n", flow->flowData.mplsL2PortFlowEntry.match_criteria.mplsL2PortMask);
  printf("\tTUNNEL ID         = 0x%08x\n", flow->flowData.mplsL2PortFlowEntry.match_criteria.tunnelId);

  if (OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST == flow->flowData.mplsL2PortFlowEntry.gotoTableId)
  {   
    printf("\tETHERTYPE         = 0x%04x\n", flow->flowData.mplsL2PortFlowEntry.match_criteria.etherType);
  }

  printf("\tGO TABLE          = %d\n",     flow->flowData.mplsL2PortFlowEntry.gotoTableId);

  if (0 != flow->flowData.mplsL2PortFlowEntry.qosIndexAction)
  {
    printf("\tQOS INDEX         = %d\n", flow->flowData.mplsL2PortFlowEntry.qosIndex);
  }

  if (flow->flowData.mplsL2PortFlowEntry.groupId != 0)
  {
    printf("\tGROUP             = 0x%08x\n", flow->flowData.mplsL2PortFlowEntry.groupId);
    if (decodeGroup)
    {
      ofdpaGroupDecode(flow->flowData.mplsL2PortFlowEntry.groupId, buf, sizeof(buf));
      printf("\t\t%s\r\n", buf);
    }
  }

  if (flow->flowData.mplsL2PortFlowEntry.qosIndexAction == 1)
  {
    printf("\tQOS INDEX         = %d\n", flow->flowData.mplsL2PortFlowEntry.qosIndex);
  }
}

int main(int argc, char *argv[])
{
   int                   i;
  OFDPA_ERROR_t         rc;
  char                  client_name[20] = "ofdpa client";
  char                  docBuffer[300];
  char                  versionBuf[100];
  ofdpaFlowEntry_t      flow;
  ofdpaFlowEntryStats_t flowStats;

  arguments_t arguments =
    {
      .count          = DEFAULT_COUNT,
      .delete         = DEFAULT_DELETE,
      .list           = DEFAULT_LIST,
      .mplsL2Port     = DEFAULT_MPLSL2PORT,
      .mplsL2PortMask = DEFAULT_MPLSL2PORTMASK,
      .tunnelId       = DEFAULT_TUNNELID,
      .etherType      = DEFAULT_ETHERTYPE,
      .etherTypeMask  = DEFAULT_ETHERTYPEMASK,
      .groupId        = 0,
      .qosIndex       = 0,
      .qosIndexAction = 0,
      .gotoTableId    = 0
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

  strcpy(docBuffer, "Adds an MPLS L2 Port flow.\vDefault values:\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "COUNT              = %d\n",     DEFAULT_COUNT);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "MPLS L2 PORT       = 0x%08x\n", DEFAULT_MPLSL2PORT);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "MPLS L2 PORT MASK  = 0x%08x\n", DEFAULT_MPLSL2PORTMASK);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "TUNNEL ID          = 0x%08x\n", DEFAULT_TUNNELID);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "\n");

  /* Parse our arguments; every option seen by `parse_opt' will be reflected in
     `arguments'. */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }

  rc = ofdpaFlowEntryInit(OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT, &flow);
  if (rc != OFDPA_E_NONE)
  {
    printf("\r\nFailed to initialize MPLS L2 Port Flow Table.(rc = %d)\n", rc);
    return rc;
  }

  flow.flowData.mplsL2PortFlowEntry.match_criteria.mplsL2Port     = arguments.mplsL2Port;
  flow.flowData.mplsL2PortFlowEntry.match_criteria.mplsL2PortMask = arguments.mplsL2PortMask;
  flow.flowData.mplsL2PortFlowEntry.match_criteria.tunnelId       = arguments.tunnelId;
  if (OFDPA_ETHERTYPE_ALL_MASK != arguments.etherTypeMask)
  {
    flow.flowData.mplsL2PortFlowEntry.match_criteria.etherType     = arguments.etherType;
    flow.flowData.mplsL2PortFlowEntry.match_criteria.etherTypeMask = arguments.etherTypeMask;
  }

  if (0 != arguments.qosIndexAction)
  {
    flow.flowData.mplsL2PortFlowEntry.qosIndex       = arguments.qosIndex;
    flow.flowData.mplsL2PortFlowEntry.qosIndexAction = arguments.qosIndexAction;
  }

  if (0 == arguments.list)
  {
    flow.flowData.mplsL2PortFlowEntry.gotoTableId = arguments.gotoTableId;
    if (arguments.groupId != 0)
    {
      flow.flowData.mplsL2PortFlowEntry.groupId = arguments.groupId;
    }
  }

  if (arguments.list || arguments.delete)
  {
    printf("%s up to %u MPLS L2 Port flows.\r\n", arguments.list ? "Listing" : "Deleting", arguments.count);
  }
  else
  {
      printf("Adding %u MPLS L2 Port flows with the following parameters:\r\n", arguments.count);
      displayMplsL2Port(&flow, (0 == arguments.list));
  }

  if (arguments.list || arguments.delete)
  {
    i = 0;

    rc = ofdpaFlowStatsGet(&flow, &flowStats);
    if (rc != OFDPA_E_NONE)
    {
      rc = ofdpaFlowNextGet(&flow, &flow);
    }
    while (rc == OFDPA_E_NONE)
    {
      i++;
      printf("%slow number %d.\r\n", arguments.delete ? "Deleting f": "F", i);
      displayMplsL2Port(&flow, 1);

      if (arguments.delete)
      {
        rc = ofdpaFlowDelete(&flow);
        if (rc != 0)
        {
          printf("\r\nError deleting MPLS L2 Port flow entry rc = %d.\r\n", rc);
        }
      }
      if ((arguments.count == 0) || (i < arguments.count))
      {
        rc = ofdpaFlowNextGet(&flow, &flow);
      }
      else
      {
        rc = OFDPA_E_NOT_FOUND;
      }
    }
    if ((1 == arguments.list) && (OFDPA_E_NOT_FOUND == rc) && (i < arguments.count))
    {
      printf("\r\nNo more entries found.\r\n");
    }
  }
  else
  {
    printf("\r\nMPLS L2 Port and tunnel id are incremented in each additional flow.\r\n\r\n");

    for (i = 0; i < arguments.count; i++)
    {
      rc = ofdpaFlowAdd(&flow);

      if (rc != 0)
      {
        printf("\r\nFailed to add MPLS L2 Port flow entry. rc = %d.\r\n", rc);
        displayMplsL2Port(&flow, 1);
        break;
      }
      flow.flowData.mplsL2PortFlowEntry.match_criteria.mplsL2Port++;
      flow.flowData.mplsL2PortFlowEntry.match_criteria.tunnelId++; 
    }
  }

  return 0;
}
