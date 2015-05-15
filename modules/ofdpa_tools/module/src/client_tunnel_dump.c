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
* @filename     client_tunnel_dump.c
*
* @purpose      Display Overlay Tunnel configuration.
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
#include <netinet/in.h>
#include <arpa/inet.h>

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

void displayTunnelEcmpGroup(uint32_t ecmpGrpId,
                            ofdpaTunnelEcmpNextHopGroupConfig_t *config,
                            ofdpaTunnelEcmpNextHopGroupStatus_t *status)
{
  uint32_t nhId = 0;

  printf("ECMP Next Hop Group ID  = %d \n", ecmpGrpId);
  printf("\tProtocol  = %s\n", (config->protocol == OFDPA_TUNNEL_PROTO_VXLAN) ? "vxlan" : "nvgre");
  if (status)
  {
    printf("\tStatus:\n");
    printf("\t\tReference count = %d\n", status->refCount);
    printf("\t\tMember count = %d", status->memberCount);
    if (status->memberCount == 0)
    {
      printf("\n");
    }
    else
    {
      /* print out next hop IDs for member next hops */
      printf(" (Member Next Hop ID%s: ", (status->memberCount <= 1) ? "" : "s");
      if (ofdpaTunnelEcmpNextHopGroupMemberNextGet(ecmpGrpId, nhId, &nhId) == OFDPA_E_NONE)
      {
        printf("%d", nhId);
        while (ofdpaTunnelEcmpNextHopGroupMemberNextGet(ecmpGrpId, nhId, &nhId) == OFDPA_E_NONE)
        {
          printf(", %d", nhId);
        }
        printf(")\n");
      }
    }
  }
}

void displayTenantEntries(void)
{
  OFDPA_ERROR_t rc;
  uint32_t tunnelId;
  ofdpaTunnelTenantConfig_t config;
  ofdpaTunnelTenantStatus_t status;

  tunnelId = 0;

  if ((rc = ofdpaTunnelTenantGet(tunnelId, NULL, NULL)) != OFDPA_E_NONE)
  {
    if ((rc = ofdpaTunnelTenantNextGet(tunnelId, &tunnelId)) != OFDPA_E_NONE)
    {
      printf("No tunnel tenant entries found.\n");
      return;
    }
  }

  if (rc == OFDPA_E_NONE)
  {
    /* found an entry, display and iterate */
    do
    {
      if ((rc = ofdpaTunnelTenantGet(tunnelId, &config, &status)) == OFDPA_E_NONE)
      {
        displayTenant(tunnelId, &config, &status);
      }
      else
      {
        printf("Error retrieving data for tunnel tenant entry. (id = %x, rc = %d)\n",
               tunnelId, rc);
      }
    } while (ofdpaTunnelTenantNextGet(tunnelId, &tunnelId) == OFDPA_E_NONE);
  }
}

void displayTunnelPortEntries(void)
{
  OFDPA_ERROR_t rc;
  uint32_t tunnelPortId;
  ofdpaTunnelPortConfig_t config;
  ofdpaTunnelPortStatus_t status;

  tunnelPortId = 0;

  if ((rc = ofdpaTunnelPortGet(tunnelPortId, NULL, NULL)) != OFDPA_E_NONE)
  {
    if ((rc = ofdpaTunnelPortNextGet(tunnelPortId, &tunnelPortId)) != OFDPA_E_NONE)
    {
      printf("No tunnel port entries found.\n");
    }
  }

  if (rc == OFDPA_E_NONE)
  {
    /* found an entry, display and iterate */
    do
    {
      if ((rc = ofdpaTunnelPortGet(tunnelPortId, &config, &status)) == OFDPA_E_NONE)
      {
        displayTunnelPort(tunnelPortId, &config, &status);
      }
      else
      {
        printf("Error retrieving data for tunnel port entry. (id = %x, rc = %d)\n",
               tunnelPortId, rc);
      }
    } while (ofdpaTunnelPortNextGet(tunnelPortId, &tunnelPortId) == OFDPA_E_NONE);
  }
}

void displayNextHopEntries(void)
{
  OFDPA_ERROR_t rc;
  uint32_t nhId;
  ofdpaTunnelNextHopConfig_t config;
  ofdpaTunnelNextHopStatus_t status;

  nhId = 0;

  if ((rc = ofdpaTunnelNextHopGet(nhId, NULL, NULL)) != OFDPA_E_NONE)
  {
    if ((rc = ofdpaTunnelNextHopNextGet(nhId, &nhId)) != OFDPA_E_NONE)
    {
      printf("No tunnel port entries found.\n");
    }
  }

  if (rc == OFDPA_E_NONE)
  {
    /* found an entry, display and iterate */
    do
    {
      if ((rc = ofdpaTunnelNextHopGet(nhId, &config, &status)) == OFDPA_E_NONE)
      {
        displayNextHop(nhId, &config, &status);
      }
      else
      {
        printf("Error retrieving data for next hop entry. (id = %x, rc = %d)\n",
               nhId, rc);
      }
    } while (ofdpaTunnelNextHopNextGet(nhId, &nhId) == OFDPA_E_NONE);
  }
}

void displayEcmpNextHopEntries(void)
{
  OFDPA_ERROR_t rc;
  uint32_t nhId;
  ofdpaTunnelEcmpNextHopGroupConfig_t config;
  ofdpaTunnelEcmpNextHopGroupStatus_t status;

  nhId = 0;

  if ((rc = ofdpaTunnelEcmpNextHopGroupGet(nhId, NULL, NULL)) != OFDPA_E_NONE)
  {
    if ((rc = ofdpaTunnelEcmpNextHopGroupNextGet(nhId, &nhId)) != OFDPA_E_NONE)
    {
      printf("No tunnel ECMP next hop entries found.\n");
    }
  }

  if (rc == OFDPA_E_NONE)
  {
    /* found an entry, display and iterate */
    do
    {
      if ((rc = ofdpaTunnelEcmpNextHopGroupGet(nhId, &config, &status)) == OFDPA_E_NONE)
      {
        displayTunnelEcmpGroup(nhId, &config, &status);
      }
      else
      {
        printf("Error retrieving data for ECMP next hop entry. (id = %x, rc = %d)\n",
               nhId, rc);
      }
    } while (ofdpaTunnelEcmpNextHopGroupNextGet(nhId, &nhId) == OFDPA_E_NONE);
  }
}

int main(int argc, char *argv[])
{
  OFDPA_ERROR_t rc;
  char client_name[] = "ofdpa tunnel_dump client";

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    printf("Error from ofdpaClientInitialize(). (rc == %d)", rc);
    return rc;
  }

  printf("--- Tunnel Tenant Table ---\n");
  displayTenantEntries();
  printf("--- Tunnel Port Table ---\n");
  displayTunnelPortEntries();
  printf("--- Tunnel Next Hop Table ---\n");
  displayNextHopEntries();
  printf("--- Tunnel ECMP Next Hop Table ---\n");
  displayEcmpNextHopEntries();

  return 0;
}
