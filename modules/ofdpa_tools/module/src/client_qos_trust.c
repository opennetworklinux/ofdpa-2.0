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
* @filename     client_qos_trust.c
*
* @purpose      Example code for QoS Trust flow tables
*
* @component    Unit Test
*
* @comments
*
* @create       11 Jul 2014
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

#define VERSION                  1.0

#define DEFAULT_COUNT            1
#define DEFAULT_DELETE           0
#define DEFAULT_LIST             0
#define DEFAULT_INDEX            1
#define DEFAULT_TABLEID          0
#define DEFAULT_MPLSL2PORT       0
#define DEFAULT_TRAFFICCLASS     1
#define DEFAULT_COLOR            OFDPA_QOS_GREEN
#define DEFAULT_GOTOTABLE        0

#define ARG_DELETE               "delete"
#define ARG_LIST                 "list"

#define KEY_COUNT                1001
#define KEY_INDEX                'i'
#define KEY_TABLEID              'b'
#define KEY_DSCP                 'd'
#define KEY_PCP                  'p'
#define KEY_DEI                  'e'
#define KEY_MPLSL2PORT           'm'
#define KEY_TRAFFICCLASS         't'
#define KEY_COLOR                'c'
#define KEY_GOTOTABLE            'g'

typedef struct
{
  int                   count;
  int                   delete;
  int                   list;
  OFDPA_FLOW_TABLE_ID_t tableId;
  uint8_t               qosIndex;
  uint8_t               dscpValue;
  int                   dscpSet;
  uint8_t               pcpValue;
  int                   pcpSet;
  uint8_t               dei;
  int                   deiSet;
  uint32_t              mplsL2Port;
  OFDPA_FLOW_TABLE_ID_t gotoTableId;
  uint8_t               trafficClass;
  OFDPA_QOS_COLORS_t    color;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "count",        KEY_COUNT,           "COUNT",        0, "The number of flows to list or delete.",                    0 },
  { "tableId",      KEY_TABLEID,         "TABLEID",      0, "QOS trust flow table id (DSCP/PCP - Port/Tunnel/MPLS)",     0 },
  { "qosIndex",     KEY_INDEX,           "INDEX",        0, "The Index of the trust table entry.",                       0 },
  { "dscp",         KEY_DSCP,            "DSCP",         0, "The DSCP value to match.",                                  0 },
  { "pcp",          KEY_PCP,             "PCP",          0, "The dot1p value to match.",                                 0 },
  { "dei",          KEY_DEI,             "DEI",          0, "The DEI value to match.",                                   0 },
  { "mplsl2port",   KEY_MPLSL2PORT,      "PORT",         0, "The MPLS L2 port type to match.",                           0 },
  { "trafficclass", KEY_TRAFFICCLASS,    "TC",           0, "The traffic class to set for packets that match.",          0 },
  { "color",        KEY_COLOR,           "COLOR",        0, "The color to set for packets that match.",                  0 },
  { "goto",         KEY_GOTOTABLE,       "GOTO_TABLE",   0, "The next table ID.",                                        0 },
  { 0 }
};

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  /* Get the INPUT argument from `argp_parse', which we
     know is a pointer to our arguments structure. */
  arguments_t *arguments = state->input;

  switch (key)
  {
    case KEY_COUNT:                      /* count */
      errno = 0;
      arguments->count = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid count \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_INDEX:                     /* QoS Index */
      errno = 0;
      arguments->qosIndex = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid QoS index \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_TABLEID:
      errno = 0;
      arguments->tableId = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid Table ID \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_DSCP:                      /* DSCP match */
      errno = 0;
      arguments->dscpValue = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid DSCP \"%s\"", arg);
        return errno;
      }
      arguments->dscpSet = 1;
      break;

    case KEY_PCP:                       /* PCP match */
      errno = 0;
      arguments->pcpValue = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid dot1p value \"%s\"", arg);
        return errno;
      }
      arguments->pcpSet = 1;
      break;

    case KEY_DEI:                       /* DEI match */
      errno = 0;
      arguments->dei = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid DEI \"%s\"", arg);
        return errno;
      }
      arguments->deiSet = 1;
      break;

    case KEY_MPLSL2PORT:                /* MPLS L2 Port match */
      errno = 0;
      arguments->mplsL2Port = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid MPLS L2 Port number \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_TRAFFICCLASS:
      errno = 0;
      arguments->trafficClass = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid Traffic Class \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_COLOR:
      errno = 0;
      arguments->color = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid Color \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_GOTOTABLE:                    /* GoTo table instruction */
      arguments->gotoTableId = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid goto table ID \"%s\"", arg);
        return errno;
      }
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
      break;

    case ARGP_KEY_END:
      if (0 == arguments->tableId)
      {
        argp_error(state, "QOS Trust flow table id must be required.");
        return EINVAL;
      }

      if ((0 != arguments->dscpSet) &&
          ((0 != arguments->pcpSet) ||
           (0 != arguments->deiSet)))
      {
        argp_error(state, "Cannot match on both DSCP and dot1p values.");
        return EINVAL;
      }
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static void displayTrustFlow(ofdpaFlowEntry_t *flow)
{
  ofdpaDscpTrustFlowEntry_t *dscpFlow;
  ofdpaPcpTrustFlowEntry_t  *pcpFlow;

  printf("\tTable ID      = %d\r\n",      flow->tableId);

  switch (flow->tableId)
  {
    case OFDPA_FLOW_TABLE_ID_PORT_DSCP_TRUST:
    case OFDPA_FLOW_TABLE_ID_TUNNEL_DSCP_TRUST:
    case OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST:
      dscpFlow = &flow->flowData.dscpTrustFlowEntry;

      printf("\tQoS Index     = %u\r\n",      dscpFlow->match_criteria.qosIndex);
      printf("\tDSCP          = %u\r\n",      dscpFlow->match_criteria.dscpValue);

      if (OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST == flow->tableId)
      {
        printf("\tMPLS L2 Port       = 0x%8.8x\r\n", dscpFlow->match_criteria.mplsL2Port);
        printf("\tMPLS L2 Port Mask  = 0x%8.8x\r\n", dscpFlow->match_criteria.mplsL2PortMask);
      }

      printf("\tTraffic Class = %u\r\n",      dscpFlow->trafficClass);
      printf("\tColor         = %u\r\n",      dscpFlow->color);
      printf("\tGoto Table    = %u\r\n",      dscpFlow->gotoTableId);
      break;

    case OFDPA_FLOW_TABLE_ID_PORT_PCP_TRUST:
    case OFDPA_FLOW_TABLE_ID_TUNNEL_PCP_TRUST:
    case OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST:
      pcpFlow = &flow->flowData.pcpTrustFlowEntry;

      printf("\tQoS Index     = %u\r\n",      pcpFlow->match_criteria.qosIndex);
      printf("\tdot1p value   = %u\r\n",      pcpFlow->match_criteria.pcpValue);
      printf("\tDEI           = %u\r\n",      pcpFlow->match_criteria.dei);

      if (OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST == flow->tableId)
      {
        printf("\tMPLS L2 Port       = 0x%8.8x\r\n", pcpFlow->match_criteria.mplsL2Port);
        printf("\tMPLS L2 Port Mask  = 0x%8.8x\r\n", pcpFlow->match_criteria.mplsL2PortMask);
      }

      printf("\tTraffic Class = %u\r\n",      pcpFlow->trafficClass);
      printf("\tColor         = %u\r\n",      pcpFlow->color);
      printf("\tGoto Table    = %u\r\n",      pcpFlow->gotoTableId);
      break;

    default:
      printf("Invalid Flow Table ID (%d)\r\n", flow->tableId);
      break;
  }
}

int main(int argc, char *argv[])
{
  int                        i;
  OFDPA_ERROR_t              rc;
  char                       client_name[20] = "ofdpa QoS client";
  char                       docBuffer[300];
  char                       versionBuf[100];
  ofdpaFlowEntry_t           flow;
  ofdpaDscpTrustFlowEntry_t *dscpFlow;
  ofdpaPcpTrustFlowEntry_t  *pcpFlow;
  ofdpaFlowEntryStats_t flowStats;

  arguments_t arguments =
    {
      .count        = DEFAULT_COUNT,
      .delete       = DEFAULT_DELETE,
      .list         = DEFAULT_LIST,
      .tableId      = DEFAULT_TABLEID,
      .qosIndex     = DEFAULT_INDEX,
      .mplsL2Port   = DEFAULT_MPLSL2PORT,
      .trafficClass = DEFAULT_TRAFFICCLASS,
      .color        = DEFAULT_COLOR,
      .gotoTableId  = DEFAULT_GOTOTABLE,
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

  strcpy(docBuffer, "Adds a QoS trust table flow.\vDefault values:\r\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "Count            = %u\r\n", arguments.count);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "QoSIndex         = %u\r\n", arguments.qosIndex);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "Traffic Class    = %u\r\n", arguments.trafficClass);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "Color            = %u\r\n", arguments.color);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "\r\n");
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "Must specify a QOS Trust Flow Table id and Goto Table.\r\n");

  if (i >= sizeof(docBuffer))
  {
    printf("\r\n!!!!!Doc buffer overflow -- increase docBuffer size!!!!!\r\n");
    exit(1);
  }

  /* Parse our arguments; every option seen by `parse_opt' will be reflected in
     `arguments'. */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  rc = ofdpaFlowEntryInit(arguments.tableId, &flow);
  if (rc != OFDPA_E_NONE)
  {
    printf("\r\nFailed to initialize Ingress Port flow entry.(rc = %d)\r\n", rc);
    return rc;
  }

  switch (arguments.tableId)
  {
    case OFDPA_FLOW_TABLE_ID_PORT_DSCP_TRUST:
    case OFDPA_FLOW_TABLE_ID_TUNNEL_DSCP_TRUST:
    case OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST:
      dscpFlow                           = &flow.flowData.dscpTrustFlowEntry;
      dscpFlow->match_criteria.qosIndex  = arguments.qosIndex;
      dscpFlow->match_criteria.dscpValue = arguments.dscpValue;
      dscpFlow->gotoTableId              = arguments.gotoTableId;
      dscpFlow->trafficClass             = arguments.trafficClass;
      dscpFlow->color                    = arguments.color;

      if (OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST == arguments.tableId)
      {
        dscpFlow->match_criteria.mplsL2Port     = arguments.mplsL2Port;
        dscpFlow->match_criteria.mplsL2PortMask = OFDPA_MPLS_L2_PORT_TYPE_MASK;
      }
      break;

    case OFDPA_FLOW_TABLE_ID_PORT_PCP_TRUST:
    case OFDPA_FLOW_TABLE_ID_TUNNEL_PCP_TRUST:
    case OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST:
      pcpFlow                          = &flow.flowData.pcpTrustFlowEntry;
      pcpFlow->match_criteria.qosIndex = arguments.qosIndex;
      pcpFlow->match_criteria.pcpValue = arguments.pcpValue;
      pcpFlow->match_criteria.dei      = arguments.dei;
      pcpFlow->gotoTableId             = arguments.gotoTableId;
      pcpFlow->trafficClass            = arguments.trafficClass;
      pcpFlow->color                   = arguments.color;

      if (OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST == arguments.tableId)
      {
        pcpFlow->match_criteria.mplsL2Port     = arguments.mplsL2Port;
        pcpFlow->match_criteria.mplsL2PortMask = OFDPA_MPLS_L2_PORT_TYPE_MASK;
      }
      break;

    default:
      printf("Invalid QOS Trust Flow Table ID %d", arguments.tableId);
      exit(2);
  }

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }

  if (arguments.list || arguments.delete)
  {
    printf("%s up to %u QoS trust flows.\r\n", arguments.list ? "Listing" : "Deleting", arguments.count);
  }
  else
  {
    printf("Adding QoS Trust flow with the following parameters:\r\n");
    displayTrustFlow(&flow);
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
      displayTrustFlow(&flow);

      if (arguments.delete)
      {
        rc = ofdpaFlowDelete(&flow);
        if (rc != 0)
        {
          printf("\r\nError deleting Qos Trust flow entry rc = %d.\r\n", rc);
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
    rc = ofdpaFlowAdd(&flow);
    if (rc != 0)
    {
      printf("\r\nFailed to add Qos Trust flow entry. rc = %d.\r\n", rc);
      displayTrustFlow(&flow);
    }
  }

  return rc;
}

