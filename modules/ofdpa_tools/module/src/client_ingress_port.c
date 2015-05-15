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
* @filename     client_ingress_port.c
*
* @purpose      Example code for Ingress Port Flow Table
*
* @component    Unit Test
*
* @comments
*
* @create       17 Jul 2013
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
#define DEFAULT_PRIORITY         0
#define DEFAULT_DELETE           0
#define DEFAULT_LIST             0
#define DEFAULT_INTF             1
#define DEFAULT_INTF_MASK        (OFDPA_INPORT_EXACT_MASK)
#define DEFAULT_TUNNEL           0
#define DEFAULT_TUNNEL_MASK      (OFDPA_TUNNEL_ID_EXACT_MASK)
#define DEFAULT_ETHTYPE          0x0u
#define DEFAULT_ETHTYPE_MASK     (OFDPA_ETHERTYPE_ALL_MASK)
#define DEFAULT_SETQOSINDEX      0
#define DEFAULT_SETVRF           0
#define DEFAULT_GOTOTABLE        (OFDPA_FLOW_TABLE_ID_VLAN)

#define ARG_DELETE        "delete"
#define ARG_LIST          "list"

#define KEY_COUNT                1000
#define KEY_PRIORITY             1001
#define KEY_INTF                 1002
#define KEY_INTF_MASK            1003
#define KEY_TUNNEL               1004
#define KEY_TUNNEL_MASK          1005
#define KEY_ETHTYPE              1006
#define KEY_SETQOSINDEX          1007
#define KEY_SETVRF               1008
#define KEY_GOTOTABLE            1009

typedef struct
{
  int              count;
  int              delete;
  int              list;
  ofdpaFlowEntry_t flow;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "count",        KEY_COUNT,           "COUNT",        0, "Number of flows to add.",                                   0 },
  { "priority",     KEY_PRIORITY,        "PRIORITY",     0, "The priority of the rule.",                                 0 },
  { "intf",         KEY_INTF,            "IFNUM",        0, "The ingress interface number.",                             0 },
  { "intfmask",     KEY_INTF_MASK,       "MASK",         0, "The ingress interface mask value (\"exact\" or \"all\").",  0 },
  { "tunnel",       KEY_TUNNEL,          "TUNNEL",       0, "The Data Center Overlay Tunnel ID.",                        0 },
  { "tunnelmask",   KEY_TUNNEL_MASK,     "MASK",         0, "The tunnel ID mask value (\"exact\" or \"type\").",         0 },
  { "ether",        KEY_ETHTYPE,         "ETHERTYPE",    0, "The ethertype.",                                            0 },
  { "qos",          KEY_SETQOSINDEX,     "QOS",          0, "The QoS index.",                                            0 },
  { "vrf",          KEY_SETVRF,          "VRF",          0, "Virtual Routing and Forwarding value.",                     0 },
  { "goto",         KEY_GOTOTABLE,       "GOTO_TABLE",   0, "Next table ID.",                                            0 },
  { 0 }
};

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  /* Get the INPUT argument from `argp_parse', which we
     know is a pointer to our arguments structure. */
  arguments_t *arguments = state->input;
  ofdpaIngressPortFlowEntry_t *flowEntry = &arguments->flow.flowData.ingressPortFlowEntry;

  switch (key)
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

    case KEY_PRIORITY:                  /* priority */
      errno = 0;
      arguments->flow.priority = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid priority \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_INTF:                      /* interface number */
      errno = 0;
      flowEntry->match_criteria.inPort = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid interface number \"%s\"", arg);
        return errno;
      }
      flowEntry->match_criteria.inPortMask = OFDPA_INPORT_EXACT_MASK;
      break;

    case KEY_INTF_MASK:                 /* interface mask value */
      if (0 == strcasecmp("exact", arg))
      {
        flowEntry->match_criteria.inPortMask = OFDPA_INPORT_EXACT_MASK;
      }
      else if (0 == strcasecmp("all", arg))
      {
        flowEntry->match_criteria.inPortMask = OFDPA_INPORT_FIELD_MASK;
      }
      else
      {
        argp_error(state, "Invalid interface mask value \"%s\" (can be \"exact\" or \"all\"))", arg);
        return errno;
      }
      break;

    case KEY_TUNNEL:                    /* tunnel ID */
      errno = 0;
      flowEntry->match_criteria.tunnelId = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid tunnel ID \"%s\"", arg);
        return errno;
      }
      flowEntry->match_criteria.tunnelIdMask = OFDPA_TUNNEL_ID_EXACT_MASK;
      break;

    case KEY_TUNNEL_MASK:               /* tunnel ID mask value */
      if (0 == strcasecmp("exact", arg))
      {
        flowEntry->match_criteria.tunnelIdMask = OFDPA_TUNNEL_ID_EXACT_MASK;
      }
      else if (0 == strcasecmp("type", arg))
      {
        flowEntry->match_criteria.tunnelIdMask = OFDPA_TUNNEL_ID_TYPE_MASK;
      }
      else
      {
        argp_error(state, "Invalid tunnel ID mask value \"%s\" (can be \"exact\" or \"type\"))", arg);
        return errno;
      }
      break;

    case KEY_ETHTYPE:                   /* ethertype value */
      errno = 0;
      flowEntry->match_criteria.etherType = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid ethertype value \"%s\"", arg);
        return errno;
      }
      if (0 == flowEntry->match_criteria.etherType)
      {
        flowEntry->match_criteria.etherTypeMask = OFDPA_ETHERTYPE_ALL_MASK;
      }
      else
      {
        flowEntry->match_criteria.etherTypeMask = OFDPA_ETHERTYPE_EXACT_MASK;
      }
      break;

    case KEY_SETQOSINDEX:               /* QoS index */
      errno = 0;
      flowEntry->qosIndex = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid QoS index \"%s\"", arg);
        return errno;
      }
      flowEntry->qosIndexAction = 1;
      break;

    case KEY_SETVRF:                    /* VRF value */
      errno = 0;
      flowEntry->vrf = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid VRF value \"%s\"", arg);
        return errno;
      }
      flowEntry->vrfAction = 1;
      break;

    case KEY_GOTOTABLE:                 /* GoTo table instruction */
      flowEntry->gotoTableId = strtoul(arg, NULL, 0);
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
    case ARGP_KEY_END:
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static void displayIngressPort(ofdpaFlowEntry_t *flow)
{
  printf("\tPriority      = %u\r\n", flow->priority);
  printf("\tInPort        = 0x%08x\n", flow->flowData.ingressPortFlowEntry.match_criteria.inPort);
  printf("\tInPortMask    = 0x%08x\n", flow->flowData.ingressPortFlowEntry.match_criteria.inPortMask);

  if (OFDPA_TUNNEL_ID_FIELD_MASK != flow->flowData.ingressPortFlowEntry.match_criteria.tunnelIdMask)
  {
    printf("\tTunnelId      = 0x%08x\n", flow->flowData.ingressPortFlowEntry.match_criteria.tunnelId);
    printf("\tTunnelIdMask  = 0x%08x\n", flow->flowData.ingressPortFlowEntry.match_criteria.tunnelIdMask);
  }

  printf("\tEthertype     = 0x%04x\n", flow->flowData.ingressPortFlowEntry.match_criteria.etherType);

  if (flow->flowData.ingressPortFlowEntry.qosIndexAction)
  {
    printf("\tQoSIndex      = %u\n", flow->flowData.ingressPortFlowEntry.qosIndex);
  }
  if (flow->flowData.ingressPortFlowEntry.vrfAction)
  {
    printf("\tVRF           = %u\n", flow->flowData.ingressPortFlowEntry.vrf);
  }

  printf("\tGoto table    = %u\n", flow->flowData.ingressPortFlowEntry.gotoTableId);
}

static void incrementPort(uint32_t *inPort)
{
  ++(*inPort);
}

int main(int argc, char *argv[])
{
  int               i;
  OFDPA_ERROR_t     rc;
  char              client_name[20] = "ofdpa client";
  char              docBuffer[300];
  char              versionBuf[100];
  ofdpaFlowEntry_t  flow;
  ofdpaFlowEntryStats_t  flowStats;
  arguments_t arguments =
    {
      .count                                                             = DEFAULT_COUNT,
      .delete                                                            = DEFAULT_DELETE,
      .list                                                              = DEFAULT_LIST,
      .flow.priority                                                     = DEFAULT_PRIORITY,
      .flow.flowData.ingressPortFlowEntry.match_criteria.inPort          = DEFAULT_INTF,
      .flow.flowData.ingressPortFlowEntry.match_criteria.inPortMask      = DEFAULT_INTF_MASK,
      .flow.flowData.ingressPortFlowEntry.match_criteria.tunnelId        = DEFAULT_TUNNEL,
      .flow.flowData.ingressPortFlowEntry.match_criteria.tunnelIdMask    = DEFAULT_TUNNEL_MASK,
      .flow.flowData.ingressPortFlowEntry.match_criteria.etherType       = DEFAULT_ETHTYPE,
      .flow.flowData.ingressPortFlowEntry.match_criteria.etherTypeMask   = DEFAULT_ETHTYPE_MASK,
      .flow.flowData.ingressPortFlowEntry.qosIndexAction                 = 0,
      .flow.flowData.ingressPortFlowEntry.qosIndex                       = DEFAULT_SETQOSINDEX,
      .flow.flowData.ingressPortFlowEntry.vrfAction                      = 0,
      .flow.flowData.ingressPortFlowEntry.vrf                            = DEFAULT_SETVRF,
      .flow.flowData.ingressPortFlowEntry.gotoTableId                    = DEFAULT_GOTOTABLE,
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

  strcpy(docBuffer, "Adds an Ingress Port flow.\vDefault values:\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "Count            = %u\n", DEFAULT_COUNT);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "Priority         = %u\n", DEFAULT_PRIORITY);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "InPort           = 0x%8.8x\n", arguments.flow.flowData.ingressPortFlowEntry.match_criteria.inPort);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "InPortMask       = 0x%8.8x\n", arguments.flow.flowData.ingressPortFlowEntry.match_criteria.inPortMask);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "TunnelId         = 0x%8.8x\n", arguments.flow.flowData.ingressPortFlowEntry.match_criteria.tunnelId);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "TunnelIdMask     = 0x%8.8x\n", arguments.flow.flowData.ingressPortFlowEntry.match_criteria.tunnelIdMask);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "Ethertype        = 0x%4.4x\n", arguments.flow.flowData.ingressPortFlowEntry.match_criteria.etherType);

  if (arguments.flow.flowData.ingressPortFlowEntry.qosIndexAction)
  {
    i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "QoSIndex         = %u\n", arguments.flow.flowData.ingressPortFlowEntry.qosIndex);
  }
  if (arguments.flow.flowData.ingressPortFlowEntry.vrfAction)
  {
    i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "VRF              = %u\n", arguments.flow.flowData.ingressPortFlowEntry.vrf);
  }

  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "Goto table       = %u\n", arguments.flow.flowData.ingressPortFlowEntry.gotoTableId);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "\n");

  if (i >= sizeof(docBuffer))
  {
    printf("\r\n!!!!!Doc buffer overflow -- increase docBuffer size!!!!!\r\n");
  }

  /* Parse our arguments; every option seen by `parse_opt' will be reflected in
     `arguments'. */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }

  rc = ofdpaFlowEntryInit(OFDPA_FLOW_TABLE_ID_INGRESS_PORT, &flow);
  if (rc != OFDPA_E_NONE)
  {
    printf("\r\nFailed to initialize Ingress Port flow entry.(rc = %d)\n", rc);
    return rc;
  }

  if (0 == arguments.list)
  {
    memcpy(&flow.flowData.ingressPortFlowEntry, &arguments.flow.flowData.ingressPortFlowEntry, sizeof(flow.flowData.ingressPortFlowEntry));
    flow.priority = arguments.flow.priority;
  }

  if (arguments.list || arguments.delete)
  {
    printf("%s up to %u ingress port flows.\r\n", arguments.list ? "Listing" : "Deleting", arguments.count);
  }
  else
  {
    printf("Adding %u ingress port flows with the following parameters:\r\n", arguments.count);
    displayIngressPort(&flow);
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
      displayIngressPort(&flow);

      if (arguments.delete)
      {
        rc = ofdpaFlowDelete(&flow);
        if (rc != 0)
        {
          printf("\r\nError deleting ingress port flow entry rc = %d.\r\n", rc);
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
    printf("\r\nInterface number is incremented in each additional flow.\r\n\r\n");

    for (i = 0; i < arguments.count; i++)
    {
      rc = ofdpaFlowAdd(&flow);

      if (rc != 0)
      {
        printf("\r\nFailed to add ingress port flow entry. rc = %d.\r\n", rc);
        displayIngressPort(&flow);
        break;
      }
      incrementPort(&flow.flowData.ingressPortFlowEntry.match_criteria.inPort);
    }
  }

  return rc;
}
