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
* @filename     client_briding.c
*
* @purpose      Example code for Bridging Flow Table. Uses RPC calls.
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

#define VERSION              1.0

#define DEFAULT_COUNT        1
#define DEFAULT_GROUP        1
#define DEFAULT_VLANID       1
#define DEFAULT_TUNNELID     0
#define DEFAULT_DESTMAC      { 0x00, 0x01, 0x03, 0x05, 0x07, 0x09 }
#define DEFAULT_DISCARD      0
#define DEFAULT_COPY         0
#define DEFAULT_DLF          0
#define DEFAULT_DELETE       0
#define DEFAULT_LIST         0

#define VLANID_MAX        4096

#define ARG_DELETE        "delete"
#define ARG_LIST          "list"

ofdpaMacAddr_t exactMacMask  = {{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }};

typedef struct
{
  int      count;
  uint32_t groupId;
  uint32_t portnum;
  int      vlanId;
  int      tunnelId;
  int      discard;
  int      copy;
  int      dlf;
  int      delete;
  int      list;
  char     mac[6];
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "count",   'c', "COUNT",   0, "Number of flows to add/list/delete. (Use 0 to list/delete all flows.)", 0 },
  { "group",   'g', "GROUP",   0, "The destination group ID.  May be just an ifnum for L2 Intf Group.",    1 },
  { "portnum", 'n', "PORT",    0, "The logical port number for Unicast Tenant Bridging flows.",            1 },
  { "vlan",    'v', "VLANID",  0, "The VLAN for VLAN Bridging flows.",                                     1 },
  { "tunnel",  't', "TUNNELID", 0, "The tenant for Tenant Bridging flows.",                                1 },
  { "dstmac",  'm', "DESTMAC", 0, "The destination MAC address match criteria.",                           1 },
  { "lookup",  'l', 0,         0, "Match destination lookup failures.",                                    2 },
  { 0,          0,  0,         0, "Actions:",                                                                },
  { "copy",    'p', 0,         0, "Copy matching flows to the CPU.",                                         },
  { "discard", 'd', 0,         0, "Discard matching flows.",                                                 },
  { 0 }
};

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  /* Get the INPUT argument from `argp_parse', which we
     know is a pointer to our arguments structure. */
  arguments_t *arguments = state->input;
  union
  {
    unsigned char  bytes[6];
    unsigned short shorts[3];
  } mac;

  switch (key)
  {
    case 'c':                           /* count */
      errno = 0;
      arguments->count = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid count \"%s\"", arg);
        return errno;
      }
      break;

    case 'g':                           /* group number */
      errno = 0;
      arguments->groupId = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid group number \"%s\"", arg);
        return errno;
      }
      break;

    case 'n':                           /* logical port */
      errno = 0;
      arguments->portnum = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid logical port number \"%s\"", arg);
        return errno;
      }
      break;

    case 'v':                           /* VLAN */
      errno = 0;
      arguments->vlanId = strtoul(arg, NULL, 0);
      if ((errno != 0) ||
          (arguments->vlanId >= VLANID_MAX))
      {
        argp_error(state, "Invalid VLAN ID \"%s\"", arg);
        return errno;
      }
      break;

    case 't':                           /* TUNNEL ID */
      errno = 0;
      arguments->tunnelId = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid tunnel ID \"%s\"", arg);
        return errno;
      }
      break;

    case 'm':                           /* destination MAC address */
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
      memcpy(arguments->mac, mac.bytes, sizeof(arguments->mac));
      break;

    case 'd':                           /* discard */
      arguments->discard = 1;
      break;

    case 'p':                           /* copy */
      arguments->copy = 1;
      break;

    case 'l':                           /* destination lookup failure */
      arguments->dlf = 1;
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

      if ((arguments->list == 0) && (arguments->delete == 0))
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

static void displayBridging(ofdpaFlowEntry_t *flow, int decodeGroup)
{
  char              buf[200];

  if (decodeGroup)
  {
    ofdpaGroupDecode(flow->flowData.bridgingFlowEntry.groupID, buf, sizeof(buf));
  }

  printf("\tVLANID    = %d\n", flow->flowData.bridgingFlowEntry.match_criteria.vlanId);
  printf("\tTUNNELID  = 0x%x\n", flow->flowData.bridgingFlowEntry.match_criteria.tunnelId);
  printf("\tDESTMAC   = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x\r\n",
         flow->flowData.bridgingFlowEntry.match_criteria.destMac.addr[0],
         flow->flowData.bridgingFlowEntry.match_criteria.destMac.addr[1],
         flow->flowData.bridgingFlowEntry.match_criteria.destMac.addr[2],
         flow->flowData.bridgingFlowEntry.match_criteria.destMac.addr[3],
         flow->flowData.bridgingFlowEntry.match_criteria.destMac.addr[4],
         flow->flowData.bridgingFlowEntry.match_criteria.destMac.addr[5]);
  printf("\tDESTMASK  = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x\r\n",
         flow->flowData.bridgingFlowEntry.match_criteria.destMacMask.addr[0],
         flow->flowData.bridgingFlowEntry.match_criteria.destMacMask.addr[1],
         flow->flowData.bridgingFlowEntry.match_criteria.destMacMask.addr[2],
         flow->flowData.bridgingFlowEntry.match_criteria.destMacMask.addr[3],
         flow->flowData.bridgingFlowEntry.match_criteria.destMacMask.addr[4],
         flow->flowData.bridgingFlowEntry.match_criteria.destMacMask.addr[5]);

  printf("\tCOPY      = %s\n", (OFDPA_PORT_CONTROLLER == flow->flowData.bridgingFlowEntry.outputPort) ? "TRUE" : "FALSE");
  printf("\tDISCARD   = %s\n", (OFDPA_FLOW_TABLE_ID_ACL_POLICY != flow->flowData.bridgingFlowEntry.gotoTableId) ? "TRUE" : "FALSE");

  printf("\tGROUP     = 0x%08x\n", flow->flowData.bridgingFlowEntry.groupID);
  if (decodeGroup)
  {
    printf("\t\t%s\r\n", buf);
  }
  printf("\tTUNNEL_LOGICAL_PORT = 0x%08x\n", flow->flowData.bridgingFlowEntry.tunnelLogicalPort);

  printf("\tHARD_TIME = %d\n", flow->hard_time);
  printf("\tIDLE_TIME = %d\n", flow->idle_time);
}

static void incrementMac(ofdpaMacAddr_t *mac)
{
  int i;

  mac->addr[5]++;
  for (i = 5; i > 0; i--)
  {
    if (0 == mac->addr[i])
    {
      mac->addr[i - 1]++;
    }
    else
    {
      break;
    }
  }
}

int main(int argc, char *argv[])
{
  int               i;
  OFDPA_ERROR_t     rc;
  uint32_t          groupType;
  int               groupVlan;
  char              docBuffer[300];
  char              versionBuf[100];
  char              client_name[] = "ofdpa bridging client";
  ofdpaFlowEntry_t  flow;
  ofdpaFlowEntryStats_t  flowStats;
  arguments_t arguments =
    {
      .count    = DEFAULT_COUNT,
      .groupId  = DEFAULT_GROUP,
      .vlanId   = DEFAULT_VLANID,
      .tunnelId = DEFAULT_TUNNELID,
      .discard  = DEFAULT_DISCARD,
      .copy     = DEFAULT_COPY,
      .dlf      = DEFAULT_DLF,
      .delete   = DEFAULT_DELETE,
      .list     = DEFAULT_LIST,
      .mac      = DEFAULT_DESTMAC,
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

  strcpy(docBuffer, "Adds, deletes or lists bridging flows.\vDefault values:\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "COUNT     = %d\n", DEFAULT_COUNT);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "GROUP     = %d\n", DEFAULT_GROUP);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "VLANID    = %d\n", DEFAULT_VLANID);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "TUNNELID  = %d\n", DEFAULT_TUNNELID);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "DISCARD   = %s\n", (DEFAULT_DISCARD) ? "TRUE" : "FALSE");
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "COPY      = %s\n", (DEFAULT_COPY) ? "TRUE" : "FALSE");
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "DLF       = %s\n", (DEFAULT_DLF) ? "TRUE" : "FALSE");
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "DESTMAC   = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x\r\n",
                arguments.mac[0], arguments.mac[1], arguments.mac[2], arguments.mac[3], arguments.mac[4], arguments.mac[5]);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "\n");

  /* Parse our arguments; every option seen by `parse_opt' will be reflected in
     `arguments'. */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }


  rc = ofdpaFlowEntryInit(OFDPA_FLOW_TABLE_ID_BRIDGING, &flow);
  if (rc != OFDPA_E_NONE)
  {
    printf("\r\nFailed to initialize Bridging Flow Table.(rc = %d)\n", rc);
    return rc;
  }

  if (0 != arguments.copy)
  {
    flow.flowData.bridgingFlowEntry.outputPort = OFDPA_PORT_CONTROLLER;
  }
  if (0 == arguments.discard)
  {
    flow.flowData.bridgingFlowEntry.gotoTableId = OFDPA_FLOW_TABLE_ID_ACL_POLICY;
  }
  flow.flowData.bridgingFlowEntry.groupID = arguments.groupId;
  ofdpaGroupTypeGet(flow.flowData.bridgingFlowEntry.groupID, &groupType);
  ofdpaGroupVlanGet(flow.flowData.bridgingFlowEntry.groupID, (uint32_t*) &groupVlan);
  if ((OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE == groupType) &&
      (0 == groupVlan))
  {
    ofdpaGroupVlanSet(&flow.flowData.bridgingFlowEntry.groupID, arguments.vlanId);
  }
  flow.flowData.bridgingFlowEntry.match_criteria.vlanId = arguments.vlanId;

  flow.flowData.bridgingFlowEntry.match_criteria.tunnelId = arguments.tunnelId;
  flow.flowData.bridgingFlowEntry.tunnelLogicalPort = arguments.portnum;

  if (0 == arguments.dlf)
  {
    memcpy(flow.flowData.bridgingFlowEntry.match_criteria.destMac.addr, arguments.mac, sizeof(flow.flowData.bridgingFlowEntry.match_criteria.destMac.addr));
    memcpy(flow.flowData.bridgingFlowEntry.match_criteria.destMacMask.addr, exactMacMask.addr, sizeof(flow.flowData.bridgingFlowEntry.match_criteria.destMacMask.addr));
  }

  flow.idle_time = 30;

  if (arguments.list || arguments.delete)
  {
    printf("%s up to %u bridging flows.\r\n", arguments.list ? "Listing" : "Deleting", arguments.count);
  }
  else
  {
      printf("Adding %u bridging flows with the following parameters:\r\n", arguments.count);
      displayBridging(&flow, (0 == arguments.list));
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
      displayBridging(&flow, 1);

      if (arguments.delete)
      {
        rc = ofdpaFlowDelete(&flow);
        if (rc != 0)
        {
          printf("\r\nError deleting bridging flow entry rc = %d.\r\n", rc);
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
    printf("\r\nDestination MAC address is incremented in each additional flow.\r\n\r\n");
    for (i = 0; i < arguments.count; i++)
    {
      rc = ofdpaFlowAdd(&flow);

      if (rc != 0)
      {
        printf("\r\nFailed to add bridging flow entry. rc = %d.\r\n", rc);
        displayBridging(&flow, 1);
        break;
      }

      incrementMac(&flow.flowData.bridgingFlowEntry.match_criteria.destMac);
    }
  }

  return rc;
}
