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
* @filename     client_tunnel_nexthop.c
*
* @purpose      Example code for Tunnel Next Hop table. Uses RPC calls.
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

#define DEFAULT_COUNT        1   /* zero signifies 'all' entries */
#define DEFAULT_NEXTHOP_ID   1
#define DEFAULT_PROTOCOL     OFDPA_TUNNEL_PROTO_VXLAN
#define DEFAULT_SRCMAC       { 0x00, 0x01, 0x03, 0x05, 0x07, 0x09 }
#define DEFAULT_DSTMAC       { 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a }
#define DEFAULT_VLANID       1
#define DEFAULT_TAGGED       1
#define DEFAULT_PHYS_PORT    1
#define DEFAULT_MODIFY       0
#define DEFAULT_DELETE       0
#define DEFAULT_LIST         0

#define VLANID_MAX        4095

#define ARG_MODIFY        "modify"
#define ARG_DELETE        "delete"
#define ARG_LIST          "list"

typedef struct
{
  int      count;
  OFDPA_TUNNEL_PROTO_t protocol;
  uint32_t nextHopId;
  char     macSa[6];
  char     macDa[6];
  int      vlanId;
  int      physPort;
  int      modify;
  int      delete;
  int      list;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "count",     'c', "COUNT",     0, "Number of tunnel next hop entries to delete or list. (Use 0 for all.)",   0 },
  { "nexthopid", 'n', "NEXTHOPID", 0, "Identifier for tunnel next hop entry/entries affected.",             0},
  { "macsa",     's', "SRCMAC",    0, "The source MAC address for the tunnel next hop.",                    1},
  { "macda",     'd', "DSTMAC",    0, "The destination MAC address for the tunnel next hop.",               1},
  { "vlan",      'v', "VLANID",    0, "The VLAN for the tunnel next hop.",                                  1},
  { "physport",  'p', "PHYSPORT",  0, "Physical port to send packets through.",                             1},
  { 0}
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
  uint32_t portType;

  switch (key)
  {
  case 'c':
    errno = 0;
    arguments->count = strtoul(arg, NULL, 0);
    if (errno != 0)
    {
      argp_error(state, "Invalid count \"%s\"", arg);
      return errno;
    }
    break;

  case 'n':                           /* next hop entry ID */
    errno = 0;
    arguments->nextHopId = strtoul(arg, NULL, 0);
    if ((errno != 0) ||
        (arguments->nextHopId < 1))
    {
      argp_error(state, "Invalid tunnel next hop entry ID \"%s\"", arg);
      return errno;
    }
    break;

  case 's':                           /* source MAC address */
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
    memcpy(arguments->macSa, mac.bytes, sizeof(arguments->macSa));
    break;

  case 'd':                           /* destination MAC address */
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
    memcpy(arguments->macDa, mac.bytes, sizeof(arguments->macDa));
    break;

  case 'v':                           /* VLAN */
    errno = 0;
    arguments->vlanId = strtoul(arg, NULL, 0);
    if ((errno != 0) ||
        (arguments->vlanId > VLANID_MAX))
    {
      argp_error(state, "Invalid VLAN ID \"%s\"", arg);
      return errno;
    }
    break;

  case 'p':                           /* VLAN */
    errno = 0;
    arguments->physPort = strtoul(arg, NULL, 0);
    if (errno != 0)
    {
      argp_error(state, "Invalid physical port \"%s\"", arg);
      return errno;
    }

    ofdpaPortTypeGet(arguments->physPort, &portType);
    if (portType != OFDPA_PORT_TYPE_PHYSICAL)
    {
      argp_error(state, "Invalid physical port \"%s\"", arg);
      return errno;
    }
    break;

  case ARGP_KEY_ARG:
    if (state->arg_num == 0)
    {
      /* first arg must be one of the keywords */
      if (0 == strcasecmp(ARG_DELETE, arg))
      {
        arguments->delete = 1;
      }
      else if (0 == strcasecmp(ARG_MODIFY, arg))
      {
        arguments->modify = 1;
      }
      else if (0 == strcasecmp(ARG_LIST, arg))
      {
        arguments->list = 1;
      }
      else
      {
        argp_error(state, "Unknown option \"%s\"", arg);
      }
    }
    else
    {
      argp_error(state, "Invalid syntax.");
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

void displayNextHop(uint32_t nextHopId,
                    ofdpaTunnelNextHopConfig_t *nhConfig,
                    ofdpaTunnelNextHopStatus_t *nhStatus)
{
  printf("next hop ID = %d\n", nextHopId);
  printf("\tProtocol  = %s\n", (nhConfig->protocol == OFDPA_TUNNEL_PROTO_VXLAN) ? "vxlan" : "nvgre");
  printf("\tMAC SA    = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x\r\n",
         nhConfig->srcAddr.addr[0],
         nhConfig->srcAddr.addr[1],
         nhConfig->srcAddr.addr[2],
         nhConfig->srcAddr.addr[3],
         nhConfig->srcAddr.addr[4],
         nhConfig->srcAddr.addr[5]);
  printf("\tMAC DA    = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x\r\n",
         nhConfig->dstAddr.addr[0],
         nhConfig->dstAddr.addr[1],
         nhConfig->dstAddr.addr[2],
         nhConfig->dstAddr.addr[3],
         nhConfig->dstAddr.addr[4],
         nhConfig->dstAddr.addr[5]);
  printf("\tPhys port = %d\n", nhConfig->physicalPortNum);
  printf("\tVLANID    = %d\n", nhConfig->vlanId);

  if (nhStatus)
  {
    printf("\tStatus:\n");
    printf("\t\tReference count = %d\n", nhStatus->refCount);
  }
}

int main(int argc, char *argv[])
{
  int               i;
  int               rc;
  char              docBuffer[300];
  char              versionBuf[100];
  char              client_name[] = "ofdpa tunnel next hop client";
  char              howmany[20];
  ofdpaTunnelNextHopConfig_t nhConfig;
  ofdpaTunnelNextHopStatus_t nhStatus;
  arguments_t arguments =
  {
    .count     = DEFAULT_COUNT,
    .protocol  = DEFAULT_PROTOCOL,
    .nextHopId = DEFAULT_NEXTHOP_ID,
    .macSa     = DEFAULT_SRCMAC,
    .macDa     = DEFAULT_DSTMAC,
    .vlanId    = DEFAULT_VLANID,
    .physPort  = DEFAULT_PHYS_PORT,
    .modify    = DEFAULT_MODIFY,
    .delete    = DEFAULT_DELETE,
    .list      = DEFAULT_LIST,
  };

  /* Our argp parser. */
  struct argp argp =
  {
    .doc      = docBuffer,
    .options  = options,
    .parser   = parse_opt,
    .args_doc = "[" ARG_MODIFY "] [" ARG_DELETE "] [" ARG_LIST "]",
  };

  sprintf(versionBuf, "%s v%.1f", basename(strdup(__FILE__)), VERSION);
  argp_program_version = versionBuf;

  strcpy(docBuffer, "Adds, modifies, deletes or lists tunnel next hop entries.\vDefault values:\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "COUNT     = %d\n", DEFAULT_COUNT);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "NEXTHOPID = %d\n", DEFAULT_NEXTHOP_ID);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "SRCMAC    = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x\r\n",
                arguments.macSa[0],
                arguments.macSa[1],
                arguments.macSa[2],
                arguments.macSa[3],
                arguments.macSa[4],
                arguments.macSa[5]);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "DSTMAC    = %2.2x%2.2x.%2.2x%2.2x.%2.2x%2.2x\r\n",
                arguments.macDa[0],
                arguments.macDa[1],
                arguments.macDa[2],
                arguments.macDa[3],
                arguments.macDa[4],
                arguments.macDa[5]);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "VLANID    = %d\n", DEFAULT_VLANID);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "PHYSPORT  = %d\n", DEFAULT_PHYS_PORT);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "\n");

  /* Parse our arguments; every option seen by `parse_opt' will be reflected in
     `arguments'. */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    printf("\nFailure calling ofdpaClientInitialize(). rc = %d", rc);
    return rc;
  }

  if ((1 == arguments.list) || (1 == arguments.delete))
  {
    if (arguments.count == 0)
      sprintf(howmany, "all");
    else
      sprintf(howmany, "up to %d", arguments.count);

    printf("%s %s entr%s starting at index %d.\n",
           arguments.list ? "Listing" : "Deleting",
           howmany,
           arguments.count == 1 ? "y":"ies",
           arguments.nextHopId);

    i = 0;
    /* see if entry matches given next hop ID */
    if (ofdpaTunnelNextHopGet(arguments.nextHopId, NULL, NULL) != OFDPA_E_NONE)
    {
      /* if no exact match, get the next one if any */
      if (ofdpaTunnelNextHopNextGet(arguments.nextHopId, &arguments.nextHopId) != OFDPA_E_NONE)
      {
        /* no next hop entries found to list */
        printf("No matching next hop entries found.\n");
        return(0);
      }
    }

    /* got an entry, display or delete it and continue for count */
    do
    {
      i++;
      if (arguments.list)
      {
        if ((rc = ofdpaTunnelNextHopGet(arguments.nextHopId, &nhConfig, &nhStatus)) == OFDPA_E_NONE)
        {
          displayNextHop(arguments.nextHopId, &nhConfig, &nhStatus);
        }
        else
        {
          printf("Error retrieving data for next hop entry. (id = %u, rc = %d)\n",
                 arguments.nextHopId, rc);
        }
      }
      else
      {
        if ((rc = ofdpaTunnelNextHopDelete(arguments.nextHopId)) != OFDPA_E_NONE)
        {
          printf("Error deleting next hop entry. (id = %u, rc = %d)\n",
                 arguments.nextHopId, rc);
        }
      }

      /* if loop is controlled by count argument, check if done */
      if (arguments.count != 0)
      {
        if (i >= arguments.count)
        {
          break;
        }
      }
    } while (ofdpaTunnelNextHopNextGet(arguments.nextHopId, &arguments.nextHopId) == OFDPA_E_NONE);
  }
  else
  {
    /* add or modify */
    memset(&nhConfig, 0, sizeof(nhConfig));
    nhConfig.protocol = arguments.protocol;
    memcpy(nhConfig.srcAddr.addr, arguments.macSa, sizeof(nhConfig.srcAddr.addr));
    memcpy(nhConfig.dstAddr.addr, arguments.macDa, sizeof(nhConfig.dstAddr.addr));
    nhConfig.physicalPortNum = arguments.physPort;
    nhConfig.vlanId = arguments.vlanId;

    printf("%s next hop entry with following parameters.\r\n",
           arguments.modify ? "Modifying" :  "Adding");
    displayNextHop(arguments.nextHopId, &nhConfig, NULL);

    if (1 == arguments.modify)
    {
      rc = ofdpaTunnelNextHopModify(arguments.nextHopId, &nhConfig);
    }
    else
    {
      rc = ofdpaTunnelNextHopCreate(arguments.nextHopId, &nhConfig);
    }
    if (rc != OFDPA_E_NONE)
    {
      printf("Error %s next hop entry. (rc = %d)\r\n",
             arguments.modify ? "modifying" :  "adding", rc);
    }
  }

  return rc;
}
