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
* @filename     client_tunnel_tenant.c
*
* @purpose      Example code for Tunnel Tenant table. Uses RPC calls.
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
#include <arpa/inet.h>

#define VERSION              1.0

#define DEFAULT_COUNT            1   /* zero signifies 'all' entries */
#define DEFAULT_TUNNEL_ID        1
#define DEFAULT_PROTOCOL         OFDPA_TUNNEL_PROTO_VXLAN
#define DEFAULT_VNID             1
#define DEFAULT_MCAST_GRP_ADDR   0
#define DEFAULT_MCAST_NEXTHOP_ID 0
#define DEFAULT_DELETE           0
#define DEFAULT_LIST             0

#define VNID_MAX          0xfffffful

#define ARG_DELETE        "delete"
#define ARG_LIST          "list"

typedef struct
{
  int       count;
  OFDPA_TUNNEL_PROTO_t protocol;
  uint32_t  tunnelId;
  uint32_t  vnId;
  in_addr_t mcastAddr;
  uint32_t  mcastNextHopId;
  int       delete;
  int       list;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "count",     'c', "COUNT",            0, "Number of tunnel next hop entries to delete or list. (Use 0 for all.)",               0 },
  { "tunnelid",  't', "TUNNELID",         0, "Identifier for tunnel tenant entry/entries affected.",          0},
  { "vnid",      'v', "VNID",             0, "The virtual network identifier for the tenant.",                1},
  { "mcastaddr", 'm', "MCAST_GRP_ADDR",   0, "The multicast group address for the tenant. 0 indicates none.", 1},
  { "mcastnhop", 'n', "MCAST_NEXTHOP_ID", 0, "Identfier of next hop entry used for multicast packets.",       1},
  { 0}
};

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  /* Get the INPUT argument from `argp_parse', which we
     know is a pointer to our arguments structure. */
  arguments_t *arguments = state->input;
  struct in_addr addr;

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

  case 't':                           /* tenant/tunnel entry ID */
    errno = 0;
    arguments->tunnelId = strtoul(arg, NULL, 0);
    if ((errno != 0) ||
        (arguments->tunnelId < 1))
    {
      argp_error(state, "Invalid tunnel entry ID \"%s\"", arg);
      return errno;
    }
    break;

  case 'v':                           /* VNID */
    errno = 0;
    arguments->vnId = strtoul(arg, NULL, 0);
    if ((errno != 0) ||
        (arguments->vnId > VNID_MAX))
    {
      argp_error(state, "Invalid VNID \"%s\"", arg);
      return errno;
    }
    break;

  case 'm':                           /* mcast address */
    if (1 == inet_pton(AF_INET, arg, &addr))
    {
      arguments->mcastAddr = ntohl(addr.s_addr);
    }
    else
    {
      errno = 0;
      arguments->mcastAddr = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid IPv4 address \"%s\"", arg);
        return errno;
      }
    }
    break;

  case 'n':                           /* mcast next hop */
    errno = 0;
    arguments->mcastNextHopId = strtoul(arg, NULL, 0);
    if (errno != 0)
    {
      argp_error(state, "Invalid mcast next hop ID \"%s\"", arg);
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

void displayTenant(uint32_t tunnelId,
                   ofdpaTunnelTenantConfig_t *config,
                   ofdpaTunnelTenantStatus_t *status)
{
  in_addr_t mcastIp;
  char buffer[50];

  memset(buffer, 0, sizeof(buffer));

  printf("tunnel ID = %d\n", tunnelId);
  printf("\tProtocol  = %s\n", (config->protocol == OFDPA_TUNNEL_PROTO_VXLAN) ? "vxlan" : "nvgre");
  printf("\tVNID      = %d\n", config->virtualNetworkId);

  mcastIp = htonl(config->mcastIp);
  if (inet_ntop(AF_INET, &mcastIp, buffer, sizeof(buffer)) == buffer)
  {
    printf("\tMcast Grp = %s\n", buffer);
  }
  printf("\tMcast NHID  = %d\n", config->mcastNextHopId);

  if (status)
  {
    printf("\tStatus:\n");
    printf("\t\tReference count = %d\n", status->refCount);
  }
}

int main(int argc, char *argv[])
{
  int               i;
  int               rc;
  char              docBuffer[300];
  char              versionBuf[100];
  char              howmany[20];
  char              client_name[] = "ofdpa tunnel tenant client";
  ofdpaTunnelTenantConfig_t config;
  ofdpaTunnelTenantStatus_t status;
  arguments_t arguments =
  {
    .count          = DEFAULT_COUNT,
    .tunnelId       = DEFAULT_TUNNEL_ID,
    .protocol       = DEFAULT_PROTOCOL,
    .vnId           = DEFAULT_VNID,
    .mcastAddr      = DEFAULT_MCAST_GRP_ADDR,
    .mcastNextHopId = DEFAULT_MCAST_NEXTHOP_ID,
    .delete         = DEFAULT_DELETE,
    .list           = DEFAULT_LIST,
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

  strcpy(docBuffer, "Adds, modifies, deletes or lists tunnel tenant entries.\vDefault values:\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "COUNT            = %d\n", DEFAULT_COUNT);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "TUNNELID         = %d\n", DEFAULT_TUNNEL_ID);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "VNID             = %d\n", DEFAULT_VNID);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "MCAST_GRP_ADDR   = %d\n", DEFAULT_MCAST_GRP_ADDR);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "MCAST_NEXTHOP_ID = %d\n", DEFAULT_MCAST_NEXTHOP_ID);
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
           arguments.tunnelId);

    i = 0;
    /* see if entry matches given tunnel ID */
    if (ofdpaTunnelTenantGet(arguments.tunnelId, NULL, NULL) != OFDPA_E_NONE)
    {
      /* if no exact match, get the next one if any */
      if (ofdpaTunnelTenantNextGet(arguments.tunnelId, &arguments.tunnelId) != OFDPA_E_NONE)
      {
        /* no tenant entries found to list */
        printf("No matching tenant entries found.\n");
        return(0);
      }
    }
    /* got an entry, display or delete it and continue for count */
    do
    {
      i++;
      if (arguments.list)
      {
        if ((rc = ofdpaTunnelTenantGet(arguments.tunnelId, &config, &status)) == OFDPA_E_NONE)
        {
          displayTenant(arguments.tunnelId, &config, &status);
        }
        else
        {
          printf("Error retrieving data for tenant entry. (id = %u, rc = %d)\n",
                 arguments.tunnelId, rc);
        }
      }
      else
      {
        if ((rc = ofdpaTunnelTenantDelete(arguments.tunnelId)) != OFDPA_E_NONE)
        {
          printf("Error deleting tenant entry. (id = %u, rc = %d)\n",
                 arguments.tunnelId, rc);
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

    } while (ofdpaTunnelTenantNextGet(arguments.tunnelId, &arguments.tunnelId) == OFDPA_E_NONE);
  }
  else
  {
    /* add or modify */
    memset(&config, 0, sizeof(config));
    config.protocol         = arguments.protocol;
    config.virtualNetworkId = arguments.vnId;
    config.mcastIp          = arguments.mcastAddr;
    config.mcastNextHopId   = arguments.mcastNextHopId;

    printf("Adding tenant entry with following parameters.\r\n");
    displayTenant(arguments.tunnelId, &config, NULL);

    rc = ofdpaTunnelTenantCreate(arguments.tunnelId, &config);

    if (rc != OFDPA_E_NONE)
    {
      printf("Error adding tenant entry. (rc = %d)\r\n", rc);
    }
  }

  return rc;
}
