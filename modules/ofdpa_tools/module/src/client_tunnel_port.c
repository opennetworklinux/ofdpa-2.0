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
* @filename     client_tunnel_port.c
*
* @purpose      Example code for Tunnel Logical Ports. Uses RPC calls.
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

#define DEFAULT_COUNT             1   /* zero signifies 'all' entries */
#define DEFAULT_PORT_INDEX        1

#define DEFAULT_PROTOCOL          OFDPA_TUNNEL_PROTO_VXLAN

/* parameters applying to Access Ports */
#define DEFAULT_PHYS_PORT         1
#define DEFAULT_VLANID            1
#define DEFAULT_UNTAGGED          0
#define DEFAULT_USE_ETAG          0
#define DEFAULT_ETAG              1

/* parameters applying to Endpoints */
#define DEFAULT_REMOTE_IP                0x01010101
#define DEFAULT_LOCAL_IP                 0x02020202
#define DEFAULT_TTL                      64
#define DEFAULT_ECMP                     0
#define DEFAULT_NEXTHOP_ID               1
#define DEFAULT_VXLAN_TERM_DST_UDP       4789
#define DEFAULT_VXLAN_INIT_DST_UDP       4789
#define DEFAULT_VXLAN_USE_ENTROPY        0
#define DEFAULT_VXLAN_SRC_UDP_NO_ENTROPY 1
#define DEFAULT_NVGRE_USE_ENTROPY        1

#define ARG_DELETE        "delete"
#define ARG_LIST          "list"

#define VLANID_MAX        4095

#define KEY_COUNT                              1
#define KEY_PORT_INDEX                         2
#define KEY_ACCESS_PORT                        3
#define KEY_ENDPOINT                           4
#define KEY_PROTOCOL_VXLAN                     5
#define KEY_PROTOCOL_NVGRE                     6
#define KEY_AP_PHYS_PORT                       7
#define KEY_AP_VLAN_ID                         8
#define KEY_AP_UNTAGGED                        9
#define KEY_AP_ETAG                           10
#define KEY_EP_REMOTE_IP                      11
#define KEY_EP_LOCAL_IP                       12
#define KEY_EP_TTL                            13
#define KEY_EP_ECMP                           14
#define KEY_EP_VXLAN_TERM_UDP_DST_PORT        15
#define KEY_EP_VXLAN_INIT_UDP_DST_PORT        16
#define KEY_EP_VXLAN_UDP_SRC_PORT_NO_ENTROPY  17
#define KEY_EP_USE_ENTROPY                    18
#define KEY_EP_NEXT_HOP_ID                    20

typedef struct
{
  int          count;
  int          delete;
  int          list;

  /* flags to track which options encountered */
  int          accessPortSpecified;
  int          endpointSpecified;
  int          vxlanSpecified;
  int          nvgreSpecified;

  uint32_t     tunnelPortId;

  /* parameters for all tunnel port types */
  OFDPA_TUNNEL_PORT_TYPE_t  type;
  OFDPA_TUNNEL_PROTO_t      tunnelProtocol;

  /* parameters for tunnel access ports */
  uint32_t   physicalPortNum;
  uint16_t   vlanId;
  uint16_t   etag;
  uint16_t   untagged;
  uint16_t   useEtag;

  /* parameters for tunnel endpoints */
  in_addr_t  remoteEndpoint;
  in_addr_t  localEndpoint;
  uint32_t   ttl;
  uint32_t   ecmp;
  uint32_t   nextHopId;
  /* parameters for VXLAN endpoints */
  uint16_t   terminatorUdpDstPort;
  uint16_t   initiatorUdpDstPort;
  uint16_t   udpSrcPortIfNoEntropy;
  uint16_t   useEntropy;
  /* parameters for NVGRE endpoints */
  uint16_t   useEntropyInKey;

} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "count",       KEY_COUNT,                            "COUNT",        0, "Number of tunnel ports to delete or list. (Use 0 for all.)",        0 },
  { "port-index",  KEY_PORT_INDEX,                       "INDEX",        0, "Index part of the ifNum of the logical port.",     0 },
  { 0,             0,                                    0,              0, "Type of tunnel port (use only one):",                },
  { "access",      KEY_ACCESS_PORT,                      0,              0, "Create an access port.",                           1 },
  { "endpoint",    KEY_ENDPOINT,                         0,              0, "Create an endpoint.",                              1 },
  { 0,             0,                                    0,              0, "Tunnel protocol (use only one):",                    },
  { "vxlan",       KEY_PROTOCOL_VXLAN,                   0,              0, "Tunnel protocol is vxlan.",                        2 },
  { "nvgre",       KEY_PROTOCOL_NVGRE,                   0,              0, "Tunnel protocol is nvgre.",                        2 },
  { 0,             0,                                    0,              0, "Access port parameters:",                            },
  { "phys-port",   KEY_AP_PHYS_PORT,                     "PORT_NUM",     0, "Physical port for access port.",                   3 },
  { "vlan",        KEY_AP_VLAN_ID,                       "VLANID",       0, "VLAN.",                                            3 },
  { "untagged",    KEY_AP_UNTAGGED,                      0,              0, "Packets sent untagged.",                           3 },
  { "etag",        KEY_AP_ETAG,                          "ETAG",         0, "ETAG value.",                                      3 },
  { 0,             0,                                    0,              0, "Endpoint parameters:",                               },
  { "remoteip",    KEY_EP_REMOTE_IP,                     "REMOTEIP",     0, "Remote endpoint IP address.",                      4 },
  { "localip",     KEY_EP_LOCAL_IP,                      "LOCALIP",      0, "Local endpoint IP address.",                       4 },
  { "ttl",         KEY_EP_TTL,                           "TTL",          0, "TTL value for tunnel packets.",                    4 },
  { "ecmp",        KEY_EP_ECMP,                          0,              0, "Endpoint nexthop is an ECMP nexthop group.",       4 },
  { "term-udp",    KEY_EP_VXLAN_TERM_UDP_DST_PORT,       "PORT",         0, "Terminator UDP destination port.",                 4 },
  { "init-udp",    KEY_EP_VXLAN_INIT_UDP_DST_PORT,       "PORT",         0, "Initiator UDP destination port.",                  4 },
  { "src-udp",     KEY_EP_VXLAN_UDP_SRC_PORT_NO_ENTROPY, "PORT",         0, "UDP source port used if entropy disabled.",        4 },
  { "entropy",     KEY_EP_USE_ENTROPY,                   0,              0, "Enable entropy.",                                  4 },
  { "nexthop",     KEY_EP_NEXT_HOP_ID,                   "NEXTHOPID",    0, "Index of next hop table entry.",                   4 },
  { 0 }
};

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  /* Get the INPUT argument from `argp_parse', which we
     know is a pointer to our arguments structure. */
  arguments_t *arguments = state->input;
  uint32_t portIndex;
  uint32_t physPort;
  uint32_t portType;
  uint32_t vlanId;
  uint32_t etag;
  struct in_addr addr;
  uint32_t ttl;
  uint32_t nextHopId;
  uint32_t udpPort;

  switch (key)
  {
  case KEY_COUNT:
    errno = 0;
    arguments->count = strtoul(arg, NULL, 0);
    if (errno != 0)
    {
      argp_error(state, "Invalid count \"%s\"", arg);
      return errno;
    }
    break;

  case KEY_PORT_INDEX:
    errno = 0;
    portIndex = strtoul(arg, NULL, 0);
    if ((errno != 0) ||
        (portIndex < 1))
    {
      argp_error(state, "Invalid access port index \"%s\"", arg);
      return errno;
    }
    /* construct a valid logical port ID from given index */
    ofdpaPortTypeSet(&arguments->tunnelPortId, OFDPA_PORT_TYPE_LOGICAL_TUNNEL);
    ofdpaPortIndexSet(&arguments->tunnelPortId, portIndex);
    break;

  case KEY_ACCESS_PORT:
    arguments->type = OFDPA_TUNNEL_PORT_TYPE_ACCESS;
    arguments->accessPortSpecified = 1;
    break;

  case KEY_ENDPOINT:
    arguments->type = OFDPA_TUNNEL_PORT_TYPE_ENDPOINT;
    arguments->endpointSpecified = 1;
    break;

  case KEY_PROTOCOL_VXLAN:
    arguments->tunnelProtocol = OFDPA_TUNNEL_PROTO_VXLAN;
    arguments->vxlanSpecified = 1;
    break;

  case KEY_PROTOCOL_NVGRE:
    arguments->tunnelProtocol = OFDPA_TUNNEL_PROTO_NVGRE;
    arguments->nvgreSpecified = 1;
    break;

  case KEY_AP_PHYS_PORT:
    errno = 0;
    physPort = strtoul(arg, NULL, 0);
    if (errno != 0)
    {
      argp_error(state, "Invalid physical port \"%s\"", arg);
      return errno;
    }

    ofdpaPortTypeGet(physPort, &portType);
    if (portType != OFDPA_PORT_TYPE_PHYSICAL)
    {
      argp_error(state, "Invalid physical port \"%s\"", arg);
      return errno;
    }
    arguments->physicalPortNum = physPort;
    break;

  case KEY_AP_VLAN_ID:
    errno = 0;
    vlanId = strtoul(arg, NULL, 0);
    if ((errno != 0) ||
        (vlanId > VLANID_MAX))
    {
      argp_error(state, "Invalid VLAN ID \"%s\"", arg);
      return errno;
    }
    arguments->vlanId = vlanId;
    break;

  case KEY_AP_UNTAGGED:
    arguments->untagged = 1;
    break;

  case KEY_AP_ETAG:
    errno = 0;
    etag = strtoul(arg, NULL, 0);
    if (errno != 0)
    {
      argp_error(state, "Invalid ETAG \"%s\"", arg);
      return errno;
    }
    arguments->etag = etag;
    arguments->useEtag = 1;
    break;

  case KEY_EP_REMOTE_IP:
    if (1 == inet_pton(AF_INET, arg, &addr))
    {
      arguments->remoteEndpoint = ntohl(addr.s_addr);
    }
    else
    {
      errno = 0;
      arguments->remoteEndpoint = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid remote endpoint address \"%s\"", arg);
        return errno;
      }
    }
    break;

  case KEY_EP_LOCAL_IP:
    if (1 == inet_pton(AF_INET, arg, &addr))
    {
      arguments->localEndpoint = ntohl(addr.s_addr);
    }
    else
    {
      errno = 0;
      arguments->localEndpoint = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid local endpoint address \"%s\"", arg);
        return errno;
      }
    }
    break;

  case KEY_EP_TTL:
    errno = 0;
    ttl = strtoul(arg, NULL, 0);
    if ((errno != 0) ||
        (ttl > 255))
    {
      argp_error(state, "Invalid TTL \"%s\"", arg);
      return errno;
    }
    arguments->ttl = ttl;
    break;

  case KEY_EP_ECMP:
    arguments->ecmp = 1;
    break;

  case KEY_EP_VXLAN_TERM_UDP_DST_PORT:
    errno = 0;
    udpPort = strtoul(arg, NULL, 0);
    if ((errno != 0) ||
        (udpPort < 1) ||
        (udpPort > 65535))
    {
      argp_error(state, "Invalid terminator UDP port \"%s\"", arg);
      return errno;
    }
    arguments->terminatorUdpDstPort = udpPort;
    break;

  case KEY_EP_VXLAN_INIT_UDP_DST_PORT:
    errno = 0;
    udpPort = strtoul(arg, NULL, 0);
    if ((errno != 0) ||
        (udpPort < 1) ||
        (udpPort > 65535))
    {
      argp_error(state, "Invalid initiator UDP port \"%s\"", arg);
      return errno;
    }
    arguments->initiatorUdpDstPort = udpPort;
    break;

  case KEY_EP_VXLAN_UDP_SRC_PORT_NO_ENTROPY:
    errno = 0;
    udpPort = strtoul(arg, NULL, 0);
    if ((errno != 0) ||
        (udpPort < 1) ||
        (udpPort > 65535))
    {
      argp_error(state, "Invalid source UDP port for when no entropy \"%s\"", arg);
      return errno;
    }
    arguments->udpSrcPortIfNoEntropy = udpPort;
    break;

  case KEY_EP_USE_ENTROPY:
    arguments->useEntropy = 1;
    arguments->useEntropyInKey = 1;
    break;

  case KEY_EP_NEXT_HOP_ID:
    errno = 0;
    nextHopId = strtoul(arg, NULL, 0);
    if ((errno != 0) ||
        (nextHopId < 1))
    {
      argp_error(state, "Invalid next hop ID \"%s\"", arg);
      return errno;
    }
    arguments->nextHopId = nextHopId;
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
    break;

  case ARGP_KEY_END:
    /* do any parameter cross checking */

    /* if a create command (i.e. not a list or delete) check parameters */
    if (arguments->list == 0 && arguments->delete == 0)
    {
      if ((arguments->accessPortSpecified == 1) && (arguments->endpointSpecified == 1))
      {
        argp_error(state, " Specify either access or endpoint for logical port creation, not both.");
        return EINVAL;
      }
      if ((arguments->accessPortSpecified == 0) && (arguments->endpointSpecified == 0))
      {
        argp_error(state, " Specify access or endpoint for logical port creation, not both.");
        return EINVAL;
      }
      if ((arguments->vxlanSpecified == 1) && (arguments->nvgreSpecified == 1))
      {
        argp_error(state, " Specify only one protocol for logical port creation.");
        return EINVAL;
      }
      if ((arguments->vxlanSpecified == 0) && (arguments->nvgreSpecified == 0))
      {
        argp_error(state, " Specify protocol for logical port creation.");
        return EINVAL;
      }
    }
    else
    {
      /* things to check if a list or delete command */
    }
    break;

  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

void displayTunnelPort(uint32_t portId,
                       ofdpaTunnelPortConfig_t *config,
                       ofdpaTunnelPortStatus_t *status)
{
  char buffer[50];
  ofdpaAccessPortConfig_t      *access;
  ofdpaEndpointConfig_t        *endpoint;
  OFDPA_TUNNEL_PORT_TYPE_t portType;
  uint32_t                 portIndex;
  struct in_addr           ipv4_addr;

  memset(buffer, 0, sizeof(buffer));

  ofdpaPortTypeGet(portId, &portType);
  ofdpaPortIndexGet(portId, &portIndex);
  printf("port ID  = %x (type = %d, index = %d)\n", portId, portType, portIndex);

  switch (config->tunnelProtocol)
  {
  case OFDPA_TUNNEL_PROTO_VXLAN:
    sprintf(buffer, "vxlan");
    break;
  case OFDPA_TUNNEL_PROTO_NVGRE:
    sprintf(buffer, "nvgre");
    break;
  default:
    sprintf(buffer, "unknown");
    break;
  }

  printf("\tProtocol  = %s\n", buffer);
  if (config->type == OFDPA_TUNNEL_PORT_TYPE_ACCESS)
  {
    access = &config->configData.access;
    printf("\tType      = ACCESS PORT\n");
    printf("\tPhys port = %d\n", access->physicalPortNum);
    printf("\tVLAN ID   = %d\n", access->vlanId);
    printf("\tUntagged  = %s\n", access->untagged ? "True" : "False");
    printf("\tETAG      = %d\n", access->etag);
    printf("\tUse ETAG  = %s\n", access->useEtag ? "True" : "False");
  }
  else if (config->type == OFDPA_TUNNEL_PORT_TYPE_ENDPOINT)
  {
    endpoint = &config->configData.endpoint;
    printf("\tType      = ENDPOINT\n");

    ipv4_addr.s_addr = htonl(endpoint->remoteEndpoint);
    if (NULL != inet_ntop(AF_INET, &ipv4_addr, buffer, sizeof(buffer)))
      printf("\tRemote IP  = %s\n", buffer);
    else
      printf("\tError converting Remote IP for output.\n");


    ipv4_addr.s_addr = htonl(endpoint->localEndpoint);
    if (NULL != inet_ntop(AF_INET, &ipv4_addr, buffer, sizeof(buffer)))
      printf("\tLocal IP   = %s\n", buffer);
    else
      printf("\tError converting Local IP for output.\n");

    printf("\tTTL        = %d\n", endpoint->ttl);
    printf("\tECMP       = %s\n", endpoint->ecmp ? "True" : "False");
    printf("\tNexthop ID = %d\n", endpoint->nextHopId);

    /* protocol specific stuff */
    if (config->tunnelProtocol == OFDPA_TUNNEL_PROTO_VXLAN)
    {
      ofdpaVxlanProtoInfo_t *vxlan;

      vxlan = &endpoint->protocolInfo.vxlan;

      printf("\tTerminator dest UDP port      = %d\n", vxlan->terminatorUdpDstPort);
      printf("\tInitiator dest UDP port       = %d\n", vxlan->initiatorUdpDstPort);
      printf("\tSource UDP port if no entropy = %d\n", vxlan->udpSrcPortIfNoEntropy);
      printf("\tUse entropy                   = %s\n", vxlan->useEntropy ? "True" : "False");
    }
    else if (config->tunnelProtocol == OFDPA_TUNNEL_PROTO_NVGRE)
    {
      ofdpaNvgreProtoInfo_t *nvgre;

      nvgre = &endpoint->protocolInfo.nvgre;

      printf("\tUse entropy in key = %s\n", nvgre->useEntropyInKey ? "True" : "False");
    }
  }
  if (status)
  {
    printf("\tStatus:\n");
    printf("\t\tReference count = %d\n", status->refCount);
    printf("\t\tTenant count = %d", status->tenantCount);
    if (status->tenantCount)
    {
      uint32_t tunnelId = 0;

      printf(" (tenant IDs:");
      while(ofdpaTunnelPortTenantNextGet(portId, tunnelId, &tunnelId) == OFDPA_E_NONE)
      {
        printf(" %d", tunnelId);
      }
      printf(")");
    }
    printf("\n");
  }
}

int main(int argc, char *argv[])
{
  int i;
  OFDPA_ERROR_t rc;
  char docBuffer[300];
  char versionBuf[100];
  char client_name[] = "ofdpa tunnel port client";
  char howmany[20];
  ofdpaTunnelPortConfig_t config;
  ofdpaTunnelPortStatus_t status;
  char portNameBuffer[OFDPA_PORT_NAME_STRING_SIZE];
  ofdpa_buffdesc portName;

  arguments_t arguments =
  {
    .count                             = DEFAULT_COUNT,
    .delete                            = 0,
    .list                              = 0,

#if 0 /* require user to specify these paraeters */
    .type                              = OFDPA_TUNNEL_PORT_TYPE_ACCESS,
    .accessPortSpecified               = 1,
    .tunnelProtocol                    = OFDPA_TUNNEL_PROTO_VXLAN,
    .vxlanSpecified                    = 1,
#endif

    .physicalPortNum = DEFAULT_PHYS_PORT,
    .vlanId          = DEFAULT_VLANID,
    .untagged        = DEFAULT_UNTAGGED,
    .useEtag         = DEFAULT_USE_ETAG,
    .etag            = DEFAULT_ETAG,

    .remoteEndpoint = DEFAULT_REMOTE_IP,
    .localEndpoint  = DEFAULT_LOCAL_IP,
    .ttl            = DEFAULT_TTL,
    .ecmp           = DEFAULT_ECMP,
    .nextHopId      = DEFAULT_NEXTHOP_ID,

    .terminatorUdpDstPort  = DEFAULT_VXLAN_TERM_DST_UDP,
    .initiatorUdpDstPort   = DEFAULT_VXLAN_INIT_DST_UDP,
    .useEntropy            = DEFAULT_VXLAN_USE_ENTROPY,
    .udpSrcPortIfNoEntropy = DEFAULT_VXLAN_SRC_UDP_NO_ENTROPY,

    .useEntropyInKey = DEFAULT_NVGRE_USE_ENTROPY,
  };

  /* Our argp parser. */
  struct argp argp =
  {
    .doc      = docBuffer,
    .options  = options,
    .parser   = parse_opt,
    .args_doc = "[[" ARG_DELETE "] [" ARG_LIST "]]",
  };

  sprintf(versionBuf, "%s v%.1f", basename(strdup(__FILE__)), VERSION);
  argp_program_version = versionBuf;

  ofdpaPortTypeSet(&arguments.tunnelPortId, OFDPA_PORT_TYPE_LOGICAL_TUNNEL);
  ofdpaPortIndexSet(&arguments.tunnelPortId, DEFAULT_PORT_INDEX);

  strcpy(docBuffer, "Creates, deletes or lists tunnel logical port entries.\vDefault values:\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "COUNT     = %d\n", DEFAULT_COUNT);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "INDEX   = %d\n", DEFAULT_PORT_INDEX);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "INDEX   = %d\n", DEFAULT_PORT_INDEX);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "\n");


  /* Parse our arguments; every option seen by `parse_opt' will be reflected in `arguments'. */
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

    printf("%s %s entr%s starting at index %x.\n",
           arguments.list ? "Listing" : "Deleting",
           howmany,
           arguments.count == 1 ? "y":"ies",
           arguments.tunnelPortId);

    i = 0;
    /* see if entry matches  */
    if (ofdpaTunnelPortGet(arguments.tunnelPortId, NULL, NULL) != OFDPA_E_NONE)
    {
      /* if no exact match, get the next one if any */
      if (ofdpaTunnelPortNextGet(arguments.tunnelPortId, &arguments.tunnelPortId) != OFDPA_E_NONE)
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
        if ((rc = ofdpaTunnelPortGet(arguments.tunnelPortId, &config, &status)) == OFDPA_E_NONE)
        {
          displayTunnelPort(arguments.tunnelPortId, &config, &status);
        }
        else
        {
          printf("Error retrieving data for tunnel port entry. (id = %x, rc = %d)\n",
                 arguments.tunnelPortId, rc);
        }
      }
      else
      {
        if ((rc = ofdpaTunnelPortDelete(arguments.tunnelPortId)) != OFDPA_E_NONE)
        {
          printf("Error deleting tunnel port entry. (id = %x, rc = %d)\n",
                 arguments.tunnelPortId, rc);
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

    } while (ofdpaTunnelPortNextGet(arguments.tunnelPortId, &arguments.tunnelPortId) == OFDPA_E_NONE);
  }
  else
  {
    /* add or modify */
    memset(&config, 0, sizeof(config));
    /* load configuration structure from arguments structure */
    config.type           = arguments.type;
    config.tunnelProtocol = arguments.tunnelProtocol;
    switch (config.type)
    {
    case OFDPA_TUNNEL_PORT_TYPE_ACCESS:
      config.configData.access.physicalPortNum = arguments.physicalPortNum;
      config.configData.access.vlanId          = arguments.vlanId;
      config.configData.access.etag            = arguments.etag;
      config.configData.access.untagged        = arguments.untagged;
      config.configData.access.useEtag         = arguments.useEtag;
      break;
    case OFDPA_TUNNEL_PORT_TYPE_ENDPOINT:
      config.configData.endpoint.remoteEndpoint = arguments.remoteEndpoint;
      config.configData.endpoint.localEndpoint  = arguments.localEndpoint;
      config.configData.endpoint.ttl            = arguments.ttl;
      config.configData.endpoint.ecmp           = arguments.ecmp;
      config.configData.endpoint.nextHopId      = arguments.nextHopId;
      switch (config.tunnelProtocol)
      {
      case OFDPA_TUNNEL_PROTO_VXLAN:
        config.configData.endpoint.protocolInfo.vxlan.terminatorUdpDstPort  = arguments.terminatorUdpDstPort;
        config.configData.endpoint.protocolInfo.vxlan.initiatorUdpDstPort   = arguments.initiatorUdpDstPort;
        config.configData.endpoint.protocolInfo.vxlan.udpSrcPortIfNoEntropy = arguments.udpSrcPortIfNoEntropy;
        config.configData.endpoint.protocolInfo.vxlan.useEntropy            = arguments.useEntropy;
        break;
      case OFDPA_TUNNEL_PROTO_NVGRE:
        config.configData.endpoint.protocolInfo.nvgre.useEntropyInKey = arguments.useEntropyInKey;
        break;
      default:
        printf("Unexpected value for tunnel protocol in parameters.\r\n");
        break;
      }
      break;
    default:
      printf("Unexpected value for tunnel type in parameters.\r\n");
      break;
    }

    printf("Creating tunnel port entry with following parameters.\r\n");
    displayTunnelPort(arguments.tunnelPortId, &config, NULL);

    /* build a port name */
    memset(portNameBuffer, 0, sizeof(portNameBuffer));
    sprintf(portNameBuffer, "TP0x%08x", arguments.tunnelPortId);
    portName.pstart = portNameBuffer;
    portName.size = strlen(portNameBuffer) + 1;

    rc = ofdpaTunnelPortCreate(arguments.tunnelPortId, &portName, &config);

    if (rc != OFDPA_E_NONE)
    {
      printf("Error creating tunnel port. (rc = %d)\r\n", rc);
    }
  }

  return rc;
}
