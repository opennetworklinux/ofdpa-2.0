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
* @filename     client_routing.c
*
* @purpose      Example code for Routing Flows Table. Uses RPC calls.
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
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libgen.h>
#include <net/ethernet.h>

#define VERSION              1.0

#define INVALID_ETHERTYPE    0xFFFFu
#define VLANID_MAX           4096

#define ARG_DELETE        "delete"
#define ARG_LIST          "list"

#define KEY_COUNT          1
#define KEY_VLANID         3
#define KEY_ETHERTYPE      5
#define KEY_VRF            6
#define KEY_DESTIP4        8
#define KEY_PREFIXLEN      9
#define KEY_SOURCEIP4     10
#define KEY_SOURCEIP6     11
#define KEY_DESTIP6       12
#define KEY_SETGROUP      17
#define KEY_DISCARD       21

typedef struct
{
  int                   count;
  int                   delete;
  int                   list;
  uint16_t              etherType;      /* must be 0x0800 or 0x86dd */
  uint16_t              vlanId;
  uint16_t              vrf;
  uint16_t              vrfMask;
  in_addr_t             srcIp4;         /* optional, can contain IPv4 address, must be completely masked if not used */
  in_addr_t             srcIp4Mask;
  in_addr_t             dstIp4;         /* must be multicast address */
  struct in6_addr       srcIp6;         /* optional, can contain IPv6 address, must be completely masked if not used */
  struct in6_addr       srcIp6Mask;
  struct in6_addr       dstIp6;         /* must be multicast address */
  uint32_t              groupID;
  int                   prefixLen;
  int                   ipv4Found;
  int                   ipv6Found;
  OFDPA_FLOW_TABLE_ID_t tableId;
  OFDPA_FLOW_TABLE_ID_t gotoTableId;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "count",    KEY_COUNT,     "COUNT",     0, "Number of flows to add, delete or list.",        },
  { 0,          0,             0,           0, "Match Criteria:",                                },
  { "vlan",     KEY_VLANID,    "VLANID",    0, "The VLAN of a multicast flow.",                  },
  { "ether",    KEY_ETHERTYPE, "ETHERTYPE", 0, "The ethertype.",                                 },
  { "vrf",      KEY_VRF,       "VRF",       0, "The virtual routing table id.",                  },
  { "dstip4",   KEY_DESTIP4,   "DESTIP4",   0, "The destination IPv4 address.",                  },
  { "srcip4",   KEY_SOURCEIP4, "SOURCEIP4", 0, "The source IPv4 address (multicast only).",      },
  { "srcip6",   KEY_SOURCEIP6, "SOURCEIP6", 0, "The source IPv6 address (multicast only).",      },
  { "dstip6",   KEY_DESTIP6,   "DESTIP6",   0, "The destination IPv6 address.",                  },
  { "prefix",   KEY_PREFIXLEN, "PREFIXLEN", 0, "The destination prefix length (unicast only).",  },
  { 0,          0,             0,           0, "Actions:",                                       },
  { "setgroup", KEY_SETGROUP,  "GROUP",     0, "Set the output group for packets in this flow.", },
  { "discard",  KEY_DISCARD,   0,           0, "Discard matching flows.",                        },
  { 0 }
};

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  /* Get the INPUT argument from `argp_parse', which we
     know is a pointer to our arguments structure. */
  arguments_t *arguments = state->input;
  struct in_addr addr;
  struct in6_addr addr6;
  int etherType = 0;

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

    case KEY_VLANID:                    /* VLAN */
      errno = 0;
      arguments->vlanId = strtoul(arg, NULL, 0);
      if ((errno != 0) ||
          (arguments->vlanId > VLANID_MAX))
      {
        argp_error(state, "Invalid VLAN ID \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_ETHERTYPE:                 /* Ethertype */
      errno = 0;
      etherType = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid Ethertype \"%s\"", arg);
        return errno;
      }
      if ((etherType != ETHERTYPE_IP) &&
          (etherType != ETHERTYPE_IPV6))
      {
        argp_error(state, "Not supported Ethertype \"%s\"", arg);
        return EINVAL;
      }
      arguments->etherType = etherType;
      break;

    case KEY_VRF:                       /* VRF */
      errno = 0;
      arguments->vrf = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid vrf \"%s\"", arg);
        return errno;
      }
      if (arguments->vrf)
      {
        arguments->vrfMask = OFDPA_VRF_VALUE_MASK;
      }
      else 
      {
        arguments->vrfMask = OFDPA_ZERO_MASK;
      }
      break;

    case KEY_SOURCEIP6:                 /* source IPv6 address */
      if ((ETHERTYPE_IP == arguments->etherType) ||
          (arguments->ipv4Found))
      {
        argp_error(state, "Flow must be either IPv4 or IPv6 but not both.");
        return EINVAL;
      }
      if (0 == inet_pton(AF_INET6, arg, &addr6))
      {
        argp_error(state, "Invalid Source IPv6 address \"%s\"", arg);
        return errno;
      }
      else
      {
        memcpy(arguments->srcIp6.s6_addr, addr6.s6_addr, sizeof(arguments->srcIp6.s6_addr));
        memset(arguments->srcIp6Mask.s6_addr, 0xff, sizeof(arguments->srcIp6.s6_addr));
        arguments->ipv6Found = 1;
      }
      break;

    case KEY_DESTIP6:                   /* destination IPv6 address */
      if ((ETHERTYPE_IP == arguments->etherType) ||
          (arguments->ipv4Found))
      {
        argp_error(state, "Flow must be either IPv4 or IPv6 but not both.");
        return EINVAL;
      }
      if (0 == inet_pton(AF_INET6, arg, &addr6))
      {
        argp_error(state, "Invalid Destination IPv6 address \"%s\"", arg);
        return errno;
      }
      else
      {
        memcpy(arguments->dstIp6.s6_addr, addr6.s6_addr, sizeof(arguments->dstIp6.s6_addr));
        arguments->ipv6Found = 1;
      }
      break;

    case KEY_DESTIP4:                   /* destination IPv4 address */
      if ((ETHERTYPE_IPV6 == arguments->etherType) ||
          (arguments->ipv6Found))
      {
        argp_error(state, "Flow must be either IPv4 or IPv6 but not both.");
        return EINVAL;
      }
      if (1 == inet_pton(AF_INET, arg, &addr))
      {
        arguments->dstIp4 = ntohl(addr.s_addr);
      }
      else
      {
        errno = 0;
        arguments->dstIp4 = strtoul(arg, NULL, 0);
        if (errno != 0)
        {
          argp_error(state, "Invalid Destination IPv4 address \"%s\"", arg);
          return errno;
        }
      }

      arguments->ipv4Found = 1;
      break;

    case KEY_SOURCEIP4:                 /* source IPv4 address */
      if ((ETHERTYPE_IPV6 == arguments->etherType) ||
          (arguments->ipv6Found))
      {
        argp_error(state, "Flow must be either IPv4 or IPv6 but not both.");
        return EINVAL;
      }
      if (1 == inet_pton(AF_INET, arg, &addr))
      {
        arguments->srcIp4 = ntohl(addr.s_addr);
      }
      else
      {
        errno = 0;
        arguments->srcIp4 = strtoul(arg, NULL, 0);
        if (errno != 0)
        {
          argp_error(state, "Invalid Source IPv4 address \"%s\"", arg);
          return errno;
        }
      }

      arguments->srcIp4Mask = 0xffffffff;
      arguments->ipv4Found = 1;
      break;

    case KEY_PREFIXLEN:                 /* Destination IP address prefix length */
      errno = 0;
      arguments->prefixLen = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid count \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_SETGROUP:
      errno = 0;
      arguments->groupID = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid group ID \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_DISCARD:
      arguments->gotoTableId = 0;
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

    case ARGP_KEY_END:
      switch (arguments->etherType)
      {
        case ETHERTYPE_IP:
          if (IN_MULTICAST(arguments->dstIp4))
          {
            if (arguments->prefixLen != 0)
            {
              argp_error(state, "Prefix length not valid on multicast flows, ignored.");
            }
            arguments->tableId = OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING;
          }
          else                          /* Must be unicast flow */
          {
            if (INADDR_ANY != arguments->srcIp4)
            {
              argp_error(state, "Source IP address only valid for multicast flows.");
              return EINVAL;
            }
            if (arguments->prefixLen > 32)
            {
              argp_error(state, "Prefix length (%d) out of range.", arguments->prefixLen);
              return EINVAL;
            }
            arguments->tableId = OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING;
          }
          break;

        case ETHERTYPE_IPV6:
          if (IN6_IS_ADDR_MULTICAST(&arguments->dstIp6))
          {
            if (arguments->prefixLen != 0)
            {
              argp_error(state, "Prefix length not valid on multicast flows, ignored.");
            }
            arguments->tableId = OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING;
          }
          else
          {
            if (!IN6_IS_ADDR_UNSPECIFIED(&arguments->srcIp6))
            {
              argp_error(state, "Source IP address only valid for multicast flows.");
              return EINVAL;
            }
            if (arguments->prefixLen > 128)
            {
              argp_error(state, "Prefix length (%d) out of range.", arguments->prefixLen);
              return EINVAL;
            }
            arguments->tableId = OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING;
          }
          break;

        default:
          argp_error(state, "Ethertype not specified, required");
          return ENODATA;
      }
      /* in case "list": two fields have to be inputed --ether=0x0800 (or --ether=0x86dd) and --dstip4 (or --dstip6) */
      /* checking if dstip is present */
      if (arguments->list && !arguments->ipv6Found && !arguments->ipv4Found)
      {
          argp_error(state, "Destination IP not specified, required");
          return ENODATA;
      }
      break;

    case ARGP_KEY_NO_ARGS:
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

static void displayFlow(ofdpaFlowEntry_t *flow)
{
  char buf[INET6_ADDRSTRLEN + 1];
  struct in_addr ipv4Addr;

  ofdpaUnicastRoutingFlowEntry_t *unicastFlow = &flow->flowData.unicastRoutingFlowEntry;
  ofdpaUnicastRoutingFlowMatch_t *unicastMatch = &flow->flowData.unicastRoutingFlowEntry.match_criteria;

  ofdpaMulticastRoutingFlowEntry_t *multicastFlow = &flow->flowData.multicastRoutingFlowEntry;
  ofdpaMulticastRoutingFlowMatch_t *multicastMatch = &flow->flowData.multicastRoutingFlowEntry.match_criteria;

  if (OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING == flow->tableId)
  {
    printf("\tEthertype                = 0x%4.4x\r\n", unicastMatch->etherType);

    if (ETHERTYPE_IP == unicastMatch->etherType)
    {
      ipv4Addr.s_addr = htonl(unicastMatch->dstIp4);
      if (NULL != inet_ntop(AF_INET, &ipv4Addr, buf, sizeof(buf)))
      {
        printf("\tDestination IPv4 address = %s\r\n", buf);
      }

      ipv4Addr.s_addr = htonl(unicastMatch->dstIp4Mask);
      if (NULL != inet_ntop(AF_INET, &ipv4Addr, buf, sizeof(buf)))
      {
        printf("\tDestination IPv4 netmask = %s\r\n", buf);
      }
    }
    else                                /* IPv6 */
    {
      if (NULL != inet_ntop(AF_INET6, &unicastMatch->dstIp6, buf, sizeof(buf)))
      {
        printf("\tDestination IPv6 address = %s\r\n", buf);
      }
      if (NULL != inet_ntop(AF_INET6, &unicastMatch->dstIp6Mask, buf, sizeof(buf)))
      {
        printf("\tDestination IPv6 netmask = %s\r\n", buf);
      }
    }
    if (unicastMatch->vrfMask)
    {
      printf("\tvrf                      = 0x%x\r\n", unicastMatch->vrf);
    }

    printf("  Actions:\r\n");
    if (OFDPA_FLOW_TABLE_ID_ACL_POLICY == unicastFlow->gotoTableId)
    {
      printf("\tSet output group ID = 0x%8x\r\n", unicastFlow->groupID);
    }
    else
    {
      printf("\tDrop packet\r\n");
    }
  }
  else                                  /* Multicast */
  {
    printf("\tVLAN Id                  = %u\r\n", multicastMatch->vlanId);
    printf("\tEthertype                = 0x%4.4x\r\n", multicastMatch->etherType);

    if (ETHERTYPE_IP == multicastMatch->etherType)
    {
      ipv4Addr.s_addr = htonl(multicastMatch->dstIp4);
      if (NULL != inet_ntop(AF_INET, &ipv4Addr, buf, sizeof(buf)))
      {
        printf("\tDestination IPv4 address = %s\r\n", buf);
      }

      ipv4Addr.s_addr = htonl(multicastMatch->srcIp4);
      if ((0 != multicastMatch->srcIp4) &&
          (NULL != inet_ntop(AF_INET, &ipv4Addr, buf, sizeof(buf))))
      {
        printf("\tSource IPv4 address      = %s\r\n", buf);
      }

    }
    else                                /* IPv6 */
    {
      if (NULL != inet_ntop(AF_INET6, &multicastMatch->dstIp6, buf, sizeof(buf)))
      {
        printf("\tDestination IPv6 address = %s\r\n", buf);
      }
      if ((0 != memcmp(&multicastMatch->srcIp6Mask, &in6addr_any, sizeof(multicastMatch->srcIp6Mask))) &&
          (NULL != inet_ntop(AF_INET6, &multicastMatch->srcIp6, buf, sizeof(buf))))
      {
        printf("\tSource IPv6 address      = %s\r\n", buf);
      }
    }
    if (multicastMatch->vrfMask)
    {
      printf("\tvrf                      = 0x%x\r\n", multicastMatch->vrf);
    }

    printf("  Actions:\r\n");
    if (OFDPA_FLOW_TABLE_ID_ACL_POLICY == multicastFlow->gotoTableId)
    {
      printf("\tSet output group ID = 0x%8x\r\n", multicastFlow->groupID);
    }
    else
    {
      printf("\tDrop packet\r\n");
    }
  }
  printf("\tIdle Time             = %d\r\n", flow->idle_time);
}

static void incrementDestIpv6(struct in6_addr *Ip6Addr)
{
  int i;

  Ip6Addr->s6_addr32[3]++;
  for (i = 3; i > 0; i--)
  {
    if (0 == Ip6Addr->s6_addr32[i])
    {
      Ip6Addr->s6_addr32[i - 1]++;
    }
    else
    {
      break;
    }
  }
}

int main(int argc, char *argv[])
{
  int                   i;
  int                   rc;
  char                  client_name[] = "ofdpa Routing client";
  char                  docBuffer[300];
  char                  versionBuf[100];
  ofdpaFlowEntry_t      flow;
  ofdpaFlowEntryStats_t flowStats;

  arguments_t arguments;

  /* Our argp parser. */
  struct argp argp =
    {
      .doc     = docBuffer,
      .options = options,
      .parser  = parse_opt,
      .args_doc = "[" ARG_DELETE "] [" ARG_LIST "]",
    };

  sprintf(versionBuf, "%s v%.1f", basename(strdup(__FILE__)), VERSION);
  argp_program_version = versionBuf;

  memset(&arguments, 0, sizeof(arguments));
  arguments.count = 1;
  arguments.gotoTableId = OFDPA_FLOW_TABLE_ID_ACL_POLICY;

  strcpy(docBuffer, "\nAdds, deletes or lists Routing flows.\vDefault values:\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "COUNT     = %d\n", arguments.count);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "\n");

  /* Parse our arguments; every option seen by `parse_opt' will be reflected in
     `arguments'. */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }


  rc = ofdpaFlowEntryInit(arguments.tableId, &flow);
  if (rc != OFDPA_E_NONE)
  {
    printf("\r\nFailed to initialize Routing Flow Table.(rc = %d)\n", rc);
    return rc;
  }

  flow.idle_time= 30;

  if (0 == arguments.list)
  {
    if (OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING == flow.tableId)
    {
      flow.flowData.unicastRoutingFlowEntry.groupID                  = arguments.groupID;
      flow.flowData.unicastRoutingFlowEntry.gotoTableId              = arguments.gotoTableId;
      if (arguments.vrfMask)
      {
        flow.flowData.unicastRoutingFlowEntry.match_criteria.vrf = arguments.vrf;
        flow.flowData.unicastRoutingFlowEntry.match_criteria.vrfMask = arguments.vrfMask;
      }
      flow.flowData.unicastRoutingFlowEntry.match_criteria.etherType = arguments.etherType;
      if (ETHERTYPE_IP == arguments.etherType)
      {
        flow.flowData.unicastRoutingFlowEntry.match_criteria.dstIp4     = arguments.dstIp4;
        /* Convert prefix length to netmask */
        flow.flowData.unicastRoutingFlowEntry.match_criteria.dstIp4Mask = (~0 << (32 - arguments.prefixLen));
      }
      else                              /* IPv6 */
      {
        memcpy(flow.flowData.unicastRoutingFlowEntry.match_criteria.dstIp6.s6_addr,
               arguments.dstIp6.s6_addr,
               sizeof(flow.flowData.unicastRoutingFlowEntry.match_criteria.dstIp6.s6_addr));
        /* Convert prefix length to netmask */
        for (i = 0; i < arguments.prefixLen / 32; i++)
        {
          flow.flowData.unicastRoutingFlowEntry.match_criteria.dstIp6Mask.s6_addr32[i] = ~0;
        }
        if (0 != (arguments.prefixLen % 32))
        {
          flow.flowData.unicastRoutingFlowEntry.match_criteria.dstIp6Mask.s6_addr32[i] = (~0 << (arguments.prefixLen % 32));
        }
      }
    }
    else                                /* multicast flow */
    {
      flow.flowData.multicastRoutingFlowEntry.groupID                  = arguments.groupID;
      flow.flowData.multicastRoutingFlowEntry.gotoTableId              = arguments.gotoTableId;
      if (arguments.vrfMask)
      {
        flow.flowData.multicastRoutingFlowEntry.match_criteria.vrf = arguments.vrf;
        flow.flowData.multicastRoutingFlowEntry.match_criteria.vrfMask = arguments.vrfMask;
      }
      flow.flowData.multicastRoutingFlowEntry.match_criteria.etherType = arguments.etherType;
      flow.flowData.multicastRoutingFlowEntry.match_criteria.vlanId    = arguments.vlanId;
      if (ETHERTYPE_IP == arguments.etherType)
      {
        flow.flowData.multicastRoutingFlowEntry.match_criteria.dstIp4     = arguments.dstIp4;
        flow.flowData.multicastRoutingFlowEntry.match_criteria.srcIp4     = arguments.srcIp4;
        flow.flowData.multicastRoutingFlowEntry.match_criteria.srcIp4Mask = arguments.srcIp4Mask;
      }
      else                              /* IPv6 */
      {
        memcpy(flow.flowData.multicastRoutingFlowEntry.match_criteria.dstIp6.s6_addr,
               arguments.dstIp6.s6_addr,
               sizeof(flow.flowData.multicastRoutingFlowEntry.match_criteria.dstIp6.s6_addr));
        memcpy(flow.flowData.multicastRoutingFlowEntry.match_criteria.srcIp6.s6_addr,
               arguments.srcIp6.s6_addr,
               sizeof(flow.flowData.multicastRoutingFlowEntry.match_criteria.srcIp6.s6_addr));
        memcpy(flow.flowData.multicastRoutingFlowEntry.match_criteria.srcIp6Mask.s6_addr,
               arguments.srcIp6Mask.s6_addr,
               sizeof(flow.flowData.multicastRoutingFlowEntry.match_criteria.srcIp6Mask.s6_addr));
      }
    }
  }

  if (arguments.list)
  {
      printf("Listing up to %u %s Routing flows.\r\n",
             arguments.count, (OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING == flow.tableId) ? "Unicast" : "Multicast");
  }
  else
  {
      printf("%s %u %s Routing flows with the following parameters:\r\n",
             arguments.delete ? "Deleting" : "Adding",
             arguments.count, (OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING == flow.tableId) ? "Unicast" : "Multicast");
      displayFlow(&flow);
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
      displayFlow(&flow);

      if (arguments.delete)
      {
        rc = ofdpaFlowDelete(&flow);
        if (rc != 0)
        {
          printf("\r\nError deleting %s Routing flow entry rc = %d.\r\n",
                 (OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING == flow.tableId) ? "Unicast" : "Multicast", rc);
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
    printf("\r\nDestination IP address is incremented in each additional flow.\r\n\r\n");

    for (i = 0; i < arguments.count; i++)
    {
      rc = ofdpaFlowAdd(&flow);

      if (rc != 0)
      {
        printf("\r\nFailed to add %s Routing flow entry rc = %d.\r\n",
               (OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING == flow.tableId) ? "Unicast" : "Multicast", rc);
        displayFlow(&flow);
        break;
      }
      if (flow.tableId == OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING)
      {
        if (ETHERTYPE_IP == arguments.etherType)
        {
          flow.flowData.unicastRoutingFlowEntry.match_criteria.dstIp4++;
        }
        else
        {
          incrementDestIpv6(&flow.flowData.unicastRoutingFlowEntry.match_criteria.dstIp6);
        }
      }
      else if (flow.tableId == OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING)
      {
        if (ETHERTYPE_IP == arguments.etherType)
        {
          flow.flowData.multicastRoutingFlowEntry.match_criteria.dstIp4++;
        }
        else
        {
          incrementDestIpv6(&flow.flowData.multicastRoutingFlowEntry.match_criteria.dstIp6);
        }
      }
      else
      {
        printf("\r\nInvalid table ID.");
      }
    }
  }

  return rc;
}
