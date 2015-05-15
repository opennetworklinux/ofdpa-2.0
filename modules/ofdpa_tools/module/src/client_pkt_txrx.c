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
* @filename     client_pkt_txrx.c
*
* @purpose      Packet tx rx client program. Uses RPC calls.
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



const char *argp_program_version = "client_pkt_txrx v1.0";

/* Arguments as follows:
 * argv[1] - how long to block on receive, in seconds. -1 to block forever.
 * argv[2] - port number. When 3rd arg is 0, this is the port to send on  .
 *           When 3rd arg is 1, this is the port to pretend the packet was received on.
 * argv[3] - non-zero value indicates packet is submitted to the pipeline rather than .
 *           being transmitted directly on a port.
 */
int main(int argc, char *argv[])
{
  int rc;
  char client_name[20] = "ofdpa client";

#if 0
  /* This stuff can be used to build an ARP Request packet to transmit */
  char buf[255];
  char destMac[6] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
  char srcMac[6] = { 0x00, 0xC0, 0x9F, 0xA1, 0xA2, 0xA7 };
  uint32_t targetIp = htonl(0xac010101);
  uint32_t srcIp = htonl(0xac010102);
  uint16_t etherType = htons(0x0806);
  uint16_t dot1qType = htons(0x8100);
  uint16_t vlanId = htons(0xa);
  uint16_t hwType = htons(0x1);
  uint16_t pType = htons(0x0800);
  uint16_t op = htons(0x1);
#endif
  int32_t wait;
  uint32_t portNum;
  uint32_t pipeline;
  OFDPA_ERROR_t err;
  ofdpa_buffdesc pkt;

  uint32_t maxPktSize;
  ofdpaPacket_t rxPkt;
  uint32_t i;
  struct timeval timeout;
  struct timeval *tv = NULL;

  if (argc != 4)
  {
    printf("\r\nUsage client_pkt_txrx <wait> <port> <pipeline>");
    printf("\r\n wait - how long to block on receive, in seconds. -1 to block forever");
    printf("\r\n port - port number. When <pipeline> is 0, this is the port to send on.\n"
               "        When pipeline is 1, this is the port to pretend the packet was received on.");
    printf("\r\n pipeline - non-zero value indicates packet is submitted to the pipeline rather than\n"
               "            being transmitted directly on a port.\n");
    exit(1);
  }

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }

  rc = ofdpaClientPktSockBind();
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }

  wait = atoi(argv[1]);
  portNum = atoi(argv[2]);
  pipeline = atoi(argv[3]);

  /* Avoid compiler warnings */
  wait = wait;
  portNum = portNum;
  pipeline = pipeline;

#if 0
  /* Ethernet - tagged */
  memset(buf, 0, 255);
  memcpy(buf, destMac, 6);
  memcpy(&buf[6], srcMac, 6);
  /* 802.1q */
  memcpy(&buf[12], &dot1qType, 2);
  memcpy(&buf[14], &vlanId, 2);
  memcpy(&buf[16], &etherType, 2);

  /* ARP */
  memcpy(&buf[18], &hwType, 2);
  memcpy(&buf[20], &pType, 2);
  buf[22] = 6;
  buf[23] = 4;
  memcpy(&buf[24], &op, 2);
  memcpy(&buf[26], srcMac, 6);
  memcpy(&buf[32], &srcIp, 4);
  memcpy(&buf[42], &targetIp, 4);
  /* No need to put FCS trailer on frame */

  pkt.pstart = buf;
  pkt.size = 100;          /* No need to pad */

  if (pipeline)
  {
    /* Send through pipeline */
    err = ofdpaPktSend(&pkt, OFDPA_PKT_LOOKUP, 0, portNum);
    if (err != OFDPA_E_NONE)
    {
      printf("\nTagged packet send through pipeline failed with error %d\r\n", err);
    }
  }
  else
  {
    err = ofdpaPktSend(&pkt, 0, portNum, 0);
    if (err != OFDPA_E_NONE)
    {
      printf("\nTagged packet send failed with error %d\r\n", err);
    }
  }

#endif

  /* Wait for received packets */
  if (wait >= 0)
  {
    timeout.tv_sec = wait;
    timeout.tv_usec = 0;
    tv = &timeout;
  }

  /* Determine how large receive buffer must be */
  if (ofdpaMaxPktSizeGet(&maxPktSize) != OFDPA_E_NONE)
  {
    printf("\nFailed to determine maximum receive packet size.\r\n");
    exit(-1);
  }

  memset(&rxPkt, 0, sizeof(ofdpaPacket_t));
  rxPkt.pktData.pstart = (char*) malloc(maxPktSize);
  if (rxPkt.pktData.pstart == NULL)
  {
    printf("\nFailed to allocate receive packet buffer\r\n");
    exit(-1);
  }
  rxPkt.pktData.size = maxPktSize;

  rc = ofdpaPktReceive(tv, &rxPkt);
  while (rc == OFDPA_E_NONE)
  {
    printf("\nClient received packet");
    printf("\n Reason:  %d", rxPkt.reason);
    printf("\n Table ID:  %d", rxPkt.tableId);
    printf("\n Ingress port:  %u", rxPkt.inPortNum);
    printf("\n Size:  %u\r\n", rxPkt.pktData.size);
    for (i = 0; i < rxPkt.pktData.size; i++)
    {
      if (i && ((i % 16) == 0))
        printf("\r\n");
      printf("%02x ", (unsigned int) *(rxPkt.pktData.pstart + i));
    }
    printf("\r\n");

    /* Now resubmit the packet to the pipeline */
    pkt.size = rxPkt.pktData.size - 4;         /* Don't include FCS */
    pkt.pstart = rxPkt.pktData.pstart;
    /* Fiddle with one byte so we can tell the packet is one we sent from
     * CPU vs just being forwarded in hardware. */
    pkt.pstart[48] = 0xFF;

    if (pipeline)
      err = ofdpaPktSend(&pkt, OFDPA_PKT_LOOKUP, portNum, rxPkt.inPortNum);
    else
      err = ofdpaPktSend(&pkt, 0, portNum, 0);
    if (err != OFDPA_E_NONE)
    {
      printf("\npacket send failed with error %d\r\n", err);
    }
    rc = ofdpaPktReceive(tv, &rxPkt);
  }

  exit(0);
}
