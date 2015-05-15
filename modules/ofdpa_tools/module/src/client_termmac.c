/*********************************************************************
 *
 * (C) Copyright Broadcom Corporation 2001-2014
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
 * @filename  client_termmac.c
 *
 * @purpose   Example code for the Termination MAC Flow Table
 *
 * @component Unit Test
 *
 * @comments
 *
 * @create    1 May 2013
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
#include <net/ethernet.h>

#define DEFAULT_COUNT         1
#define DEFAULT_IFNUM         1
#define DEFAULT_IFNUMMASK     0xFFFFFFFFu
#define DEFAULT_PRIORITY      0
#define DEFAULT_SRCMAC        {{ 0x00, 0x09, 0x07, 0x05, 0x03, 0x01 }}
#define DEFAULT_SRCMACMASK    {{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }}
#define DEFAULT_DESTMAC       {{ 0x00, 0x01, 0x03, 0x05, 0x07, 0x09 }}
#define DEFAULT_DESTMACMASK   {{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }}
#define DEFAULT_VLANID        1
#define DEFAULT_VLANIDMASK    OFDPA_VID_EXACT_MASK
#define DEFAULT_ETHERTYPE     0x0800u
#define DEFAULT_ETHERTYPEMASK 0xFFFFu

uint8_t ipv4MulticastMac [] = { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x00 };
uint8_t ipv6MulticastMac [] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x00 };
uint8_t ipv4MulticastMask[] = { 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00 };
uint8_t ipv6MulticastMask[] = { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };
uint8_t unicastMask      [] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

#define INVALID_ETHERTYPE    0xFFFFu

#define VLANID_MAX        4096

#define ARG_DELETE        "delete"
#define ARG_LIST          "list"

ofdpaMacAddr_t noMacMask  = {{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};

const char *argp_program_version = "client_termMac_add v1.0";

/* The options we understand. */
static struct argp_option options[] =
{
  { "count",   'c', "COUNT",     0, "Number of STATIONs to add.",                               0 },
  { "intf",    'i', "IFNUM",     0, "The ingress port number.",                                 0 },
  { "vlan",    'v', "VLANID",    0, "The VLAN to which the STATION should be applied.",         0 },
  { "ether",   'e', "ETHERTYPE", 0, "The ethertype match criteria.",                            1 },
  { "dstmac",  'm', "DESTMAC",   0, "The destination MAC address match criteria.",              1 },
  { "prio",    'r', "PRIO",      0, "The flow priority.",                                       1 },
  { 0,          0,  0,           0, "Actions:",                                                   },
  { "copy",    'p', 0,           0, "Copy matching flows to the CPU.",                            },
  { "discard", 'd', 0,           0, "Discard matching flows.",                                    },
  { 0 }
};

typedef struct
{
  int                            count;
  int                            discard;
  int                            copy;
  int                            delete;
  int                            list;
  int                            priority;
  ofdpaTerminationMacFlowMatch_t termMacMatch;
} arguments_t;

static void macMaskApply(uint8_t *mac, uint8_t *mask)
{
  int i;

  for (i = 0; i < ETHER_ADDR_LEN; i++)
  {
    mac[i] &= mask[i];
  }
}

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

    case 'e':                           /* Ethertype */
      errno = 0;
      arguments->termMacMatch.etherType = strtoul(arg, NULL, 0);
      if ((errno != 0) ||
          (arguments->termMacMatch.etherType >= INVALID_ETHERTYPE))
      {
        argp_error(state, "Invalid Ethertype \"%s\"", arg);
        return errno;
      }
      break;

    case 'i':                           /* interface number */
      errno = 0;
      arguments->termMacMatch.inPort = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid interface number \"%s\"", arg);
        return errno;
      }
      if (0 == arguments->termMacMatch.inPort)
      {
        arguments->termMacMatch.inPortMask = 0;
      }
      else
      {
        arguments->termMacMatch.inPortMask = DEFAULT_IFNUMMASK;
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
      memcpy(arguments->termMacMatch.destMac.addr, mac.bytes, sizeof(arguments->termMacMatch.destMac.addr));
      macMaskApply(mac.bytes, ipv4MulticastMask);
      if (0 == memcmp(mac.bytes, ipv4MulticastMac, sizeof(mac.bytes)))
      {
        memcpy(arguments->termMacMatch.destMacMask.addr, ipv4MulticastMask, sizeof(arguments->termMacMatch.destMacMask.addr));
      }
      else
      {
        macMaskApply(mac.bytes, ipv6MulticastMask);
        if (0 == memcmp(mac.bytes, ipv6MulticastMac, sizeof(mac.bytes)))
        {
          memcpy(arguments->termMacMatch.destMacMask.addr, ipv6MulticastMask, sizeof(arguments->termMacMatch.destMacMask.addr));
        }
        else if (0 != (mac.bytes[0] & 0x01))
        {
          argp_error(state, "Invalid multicast MAC address \"%s\"", arg);
        }
        else
        {
          memcpy(arguments->termMacMatch.destMacMask.addr, unicastMask, sizeof(arguments->termMacMatch.destMacMask.addr));
        }
      }
      break;

    case 'v':                           /* VLAN */
      errno = 0;
      arguments->termMacMatch.vlanId = strtoul(arg, NULL, 0);
      if ((errno != 0) ||
          (arguments->termMacMatch.vlanId > VLANID_MAX))
      {
        argp_error(state, "Invalid VLAN ID \"%s\"", arg);
        return errno;
      }
      break;

    case 'd':                           /* discard */
      arguments->discard = 1;
      break;

    case 'p':                           /* copy */
      arguments->copy = 1;
      break;

    case 'r':                           /* Priority */
      errno = 0;
      arguments->priority = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid Priority \"%s\"", arg);
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

static void displayTermMac(ofdpaFlowEntry_t *flow)
{
  if (0 != flow->flowData.terminationMacFlowEntry.match_criteria.inPortMask)
  {
    printf("\tInterface                = %u\r\n", flow->flowData.terminationMacFlowEntry.match_criteria.inPort);
  }
  if (0 != flow->flowData.terminationMacFlowEntry.match_criteria.vlanIdMask)
  {
    printf("\tVLAN Id                  = %u\r\n", flow->flowData.terminationMacFlowEntry.match_criteria.vlanId);
  }
  if (0 != memcmp(flow->flowData.terminationMacFlowEntry.match_criteria.destMacMask.addr, noMacMask.addr,
                  sizeof(flow->flowData.terminationMacFlowEntry.match_criteria.destMac.addr)))
  {
    printf("\tDestination MAC address  = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x\r\n",
           flow->flowData.terminationMacFlowEntry.match_criteria.destMac.addr[0],
           flow->flowData.terminationMacFlowEntry.match_criteria.destMac.addr[1],
           flow->flowData.terminationMacFlowEntry.match_criteria.destMac.addr[2],
           flow->flowData.terminationMacFlowEntry.match_criteria.destMac.addr[3],
           flow->flowData.terminationMacFlowEntry.match_criteria.destMac.addr[4],
           flow->flowData.terminationMacFlowEntry.match_criteria.destMac.addr[5]);
    printf("\tDestination MAC mask     = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x\r\n",
           flow->flowData.terminationMacFlowEntry.match_criteria.destMacMask.addr[0],
           flow->flowData.terminationMacFlowEntry.match_criteria.destMacMask.addr[1],
           flow->flowData.terminationMacFlowEntry.match_criteria.destMacMask.addr[2],
           flow->flowData.terminationMacFlowEntry.match_criteria.destMacMask.addr[3],
           flow->flowData.terminationMacFlowEntry.match_criteria.destMacMask.addr[4],
           flow->flowData.terminationMacFlowEntry.match_criteria.destMacMask.addr[5]);
  }

  printf("\tEthertype                = 0x%4.4x\r\n", flow->flowData.terminationMacFlowEntry.match_criteria.etherType);
  printf("\tPriority                 = %u\r\n", flow->priority);
  switch (flow->flowData.terminationMacFlowEntry.gotoTableId)
  {
    case 0:
      printf("\tdiscard                  = TRUE\n");
      break;

    case OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING:
      printf("\tGo to Table              = Unicast Routing\n");
      break;

    case OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING:
      printf("\tGo to Table              = Multicast Routing\n");
      break;

    case OFDPA_FLOW_TABLE_ID_MPLS_0:
      printf("\tGo to Table              = MPLS\n");
      break;

    default:
      printf("\tGo to Table              = Invalid\n");
      break;
  }
  printf("\tcopy                     = %s\n", (OFDPA_PORT_CONTROLLER == flow->flowData.terminationMacFlowEntry.outputPort) ? "TRUE" : "FALSE");
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
  int i;
  int rc;
  char client_name[] = "ofdpa termination MAC client";
  char docBuffer[300];
  ofdpaFlowEntry_t flow;
  ofdpaFlowEntryStats_t  flowStats;
  arguments_t arguments =
    {
      .count                    = DEFAULT_COUNT,
      .discard                  = 0,
      .priority                 = DEFAULT_PRIORITY,
      .copy                     = 0,
      .delete                   = 0,
      .list                     = 0,
      .termMacMatch.inPort      = DEFAULT_IFNUM,
      .termMacMatch.inPortMask  = DEFAULT_IFNUMMASK,
      .termMacMatch.etherType   = DEFAULT_ETHERTYPE,
      .termMacMatch.destMac     = DEFAULT_DESTMAC,
      .termMacMatch.destMacMask = DEFAULT_DESTMACMASK,
      .termMacMatch.vlanId      = DEFAULT_VLANID,
      .termMacMatch.vlanIdMask  = DEFAULT_VLANIDMASK,
    };

  /* Our argp parser. */
  struct argp argp =
    {
      .doc     = docBuffer,
      .options = options,
      .parser  = parse_opt,
      .args_doc = "[" ARG_DELETE "] [" ARG_LIST "]",
    };

  strcpy(docBuffer, "Adds, deletes or lists termination MAC flows.\vDefault values:\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "COUNT     = %d\n", DEFAULT_COUNT);
  if (0 != arguments.termMacMatch.inPortMask)
  {
    i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "IFNUM     = %d\n", DEFAULT_IFNUM);
  }
  if (0 != memcmp(arguments.termMacMatch.destMacMask.addr, noMacMask.addr, sizeof(arguments.termMacMatch.destMac.addr)))
  {
    i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "DESTMAC   = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x\r\n", arguments.termMacMatch.destMac.addr[0], arguments.termMacMatch.destMac.addr[1],
                 arguments.termMacMatch.destMac.addr[2], arguments.termMacMatch.destMac.addr[3], arguments.termMacMatch.destMac.addr[4], arguments.termMacMatch.destMac.addr[5]);
  }
  if (0 != arguments.termMacMatch.vlanIdMask)
  {
    i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "VLANID    = %d\n", DEFAULT_VLANID);
  }

  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "ETHERTYPE = 0x%4.4x\n", DEFAULT_ETHERTYPE);

  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "PRIORITY = %u\n", DEFAULT_PRIORITY);

  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "\n");

  /* Parse our arguments; every option seen by `parse_opt' will be reflected in
     `arguments'. */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }

  rc = ofdpaFlowEntryInit(OFDPA_FLOW_TABLE_ID_TERMINATION_MAC, &flow);
  if (rc != OFDPA_E_NONE)
  {
    printf("\r\nFailed to initialize Termination MAC Flow Table.(rc = %d)\n", rc);
    return rc;
  }

  if (0 == arguments.list)
  {
    if (0 == arguments.discard)
    {
      if (0x8847 == arguments.termMacMatch.etherType)
      {
        flow.flowData.terminationMacFlowEntry.gotoTableId = OFDPA_FLOW_TABLE_ID_MPLS_0;
      }
      else if (0 == (arguments.termMacMatch.destMac.addr[0] & 0x1))
      {
        flow.flowData.terminationMacFlowEntry.gotoTableId = OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING;
      }
      else
      {
        flow.flowData.terminationMacFlowEntry.gotoTableId = OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING;
      }
    }
    if (0 != arguments.copy)
    {
      flow.flowData.terminationMacFlowEntry.outputPort = OFDPA_PORT_CONTROLLER;
    }

    flow.priority = arguments.priority;

    memcpy(&flow.flowData.terminationMacFlowEntry.match_criteria, &arguments.termMacMatch, sizeof(flow.flowData.terminationMacFlowEntry.match_criteria));
  }

  if (arguments.list || arguments.delete)
  {
    printf("%s up to %u termination MAC flows.\r\n", arguments.list ? "Listing" : "Deleting", arguments.count);
  }
  else
  {
      printf("Adding %u termination MAC flows with the following parameters:\r\n", arguments.count);
      displayTermMac(&flow);
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
      displayTermMac(&flow);

      if (arguments.delete)
      {
        rc = ofdpaFlowDelete(&flow);
        if (rc != 0)
        {
          printf("\r\nError deleting termination MAC flow entry rc = %d.\r\n", rc);
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
        printf("\r\nFailed to add termination MAC flow entry. rc = %d.\r\n", rc);
        displayTermMac(&flow);
        break;
      }
      incrementMac(&flow.flowData.terminationMacFlowEntry.match_criteria.destMac);
    }
  }

  return rc;
}
