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
* @filename     client_port.c
*
* @purpose      Port API client program. Uses RPC calls.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <argp.h>
#include <libgen.h>

#include "ofdpa_api.h"

#define DEFAULT_PORT           1
#define DEFAULT_ADMINSTATE     1
#define DEFAULT_QUEUEID        0
#define DEFAULT_QUEUEMINRATE  20
#define DEFAULT_QUEUEMAXRATE  1000

#define ARG_CLEAR "clear"
#define ARG_LIST  "list"
#define ARG_PROP   "properties"

#define KEY_INTF          1
#define KEY_STATS         2
#define KEY_ADMINSTATE    3
#define KEY_ADVFEATURES   4
#define KEY_QUEUEID       5
#define KEY_QUEUEMINRATE  6
#define KEY_QUEUEMAXRATE  7
#define KEY_QUEUERATE     8
#define KEY_QUEUESTATS    9

#define VERSION           1.0

typedef struct
{
  int      port;
  int      properties;
  int      stats;
  OFDPA_PORT_STATE_t adminState;
  int      adminStateFlag;
  OFDPA_PORT_FEATURE_t advFeature;
  int      advFeatureFlag;
  int      queueId;
  int      queueFlag;
  int      queueMinRate;
  int      queueMaxRate;
  int      queueRate;
  int      queueStats;
  int      list;
  int      clear;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "intf",           KEY_INTF,           "INTERFACE", 0, "Interface ID.",                                                       },
  { 0,                0,                  0,           0, "Options:",                                                            },
  { "stats",          KEY_STATS,          0,           0, "List/Clear interface statistics.",                                    },
  { "adminstate",     KEY_ADMINSTATE,     "STATE",     0, "Configure interface admin state. (enable(0)|(disable(1))",            },
  { "advfeat",        KEY_ADVFEATURES,    "FEATURE",   0, "Configure interface advertising features.",                           },
  { "queueId",        KEY_QUEUEID,        "QUEUEID",   0, "Queue Id to be configured on an interface.",                          },
  { "queueminrate",   KEY_QUEUEMINRATE,   "MINRATE",   0, "Configure minimum rate on an interface queue.",                       },
  { "queuemaxrate",   KEY_QUEUEMAXRATE,   "MAXRATE",   0, "Configure maximum rate on an interface queue.",                       },
  { "queuerate",      KEY_QUEUERATE,      0,           0, "List minimum and maximum queue rates configured on an interface.",    },
  { "queuestats",     KEY_QUEUESTATS,     0,           0, "List/Clear queue statistics on an interface.",                        },
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
    case KEY_INTF:
      errno = 0;
      arguments->port = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid interface \"%s\"", arg);
        return errno;
      }
      break;
    case KEY_STATS:
        arguments->stats = 1;
        break;
    case KEY_ADMINSTATE:
      errno = 0;
      arguments->adminState = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid admin state \"%s\"", arg);
        return errno;
      }
      arguments->adminStateFlag = 1;
      break;
    case KEY_ADVFEATURES:
       errno = 0;
       arguments->advFeature = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid advertising feature \"%s\"", arg);
        return errno;
      }
      arguments->advFeatureFlag = 1;
      break;
    case KEY_QUEUEID:
      errno = 0;
      arguments->queueId = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid Queue ID \"%s\"", arg);
        return errno;
      }
      arguments->queueFlag = 1;
      break;
    case KEY_QUEUEMINRATE:
      errno = 0;
      arguments->queueMinRate = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid minimum queue rate \"%s\"", arg);
        return errno;
      }
      arguments->queueFlag = 1;
      break;
    case KEY_QUEUEMAXRATE:
      errno = 0;
      arguments->queueMaxRate = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid maximum queue rate \"%s\"", arg);
        return errno;
      }
      arguments->queueFlag = 1;
      break;
    case KEY_QUEUERATE:
      arguments->queueRate = 1;
      break;
    case KEY_QUEUESTATS:
      arguments->queueStats = 1;
      break;
    case ARGP_KEY_ARG:
      if (0 == strcasecmp(ARG_PROP, arg))
      {
        arguments->properties = 1;
      }
      else if (0 == strcasecmp(ARG_LIST, arg))
      {
        arguments->list = 1;
      }
      else if (0 == strcasecmp(ARG_CLEAR, arg))
      {
        arguments->clear = 1;
      }
      break;
    case ARGP_KEY_NO_ARGS:
      break;
    case ARGP_KEY_END:
      break;
    default:
      return ARGP_ERR_UNKNOWN;

  }
  return 0;
}

void displayPortProperties(int portNum)
{
  OFDPA_ERROR_t rc;
  ofdpaMacAddr_t mac;
  ofdpa_buffdesc nameDesc;
  OFDPA_PORT_STATE_t  state = 0;
  OFDPA_PORT_CONFIG_t config = 0;
  char buff[64];
  ofdpaPortFeature_t  feature;
  uint32_t speed;

  memset(buff, 0, sizeof(buff));
  nameDesc.pstart = buff;
  nameDesc.size = OFDPA_PORT_NAME_STRING_SIZE;

  rc = ofdpaPortNameGet(portNum, &nameDesc);
  if (rc != OFDPA_E_NONE)
  {
    printf("Failed to get Port Name. (rc = %d)\n", rc);
  }

  printf("\nPort %d(%s)\n", portNum, nameDesc.pstart);

  rc = ofdpaPortMacGet(portNum, &mac);
  if (rc != OFDPA_E_NONE)
  {
    printf("Failed to get Port MAC. (rc = %d)\n", rc);
  }

  printf("\tMAC: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",
       mac.addr[0],mac.addr[1],mac.addr[2],
       mac.addr[3],mac.addr[4],mac.addr[5]);

  rc = ofdpaPortConfigGet(portNum, &config);
  if (rc != OFDPA_E_NONE)
  {
    printf("Failed to get Port Admin State. (rc = %d)\n", rc);
  }
  printf("\tAdmin State: %s\n", (config & OFDPA_PORT_CONFIG_DOWN)? "disabled": "enabled");

  rc = ofdpaPortStateGet(portNum, &state);
  if (rc != OFDPA_E_NONE)
  {
    printf("Failed to get Port State. (rc = %d)\n", rc);
  }
  printf("\tState: 0x%x (%s, %s, %s)\n",
         state,
         (state & OFDPA_PORT_STATE_LIVE) ? "live" : "not live",
         (state & OFDPA_PORT_STATE_BLOCKED) ? "blocked" : "unblocked",
         (state & OFDPA_PORT_STATE_LINK_DOWN) ? "down" : "up"); 

  rc = ofdpaPortMaxSpeedGet(portNum, &speed);
  if (rc != OFDPA_E_NONE)
  {
    printf("Failed to get Port Max Speed. (rc = %d)\n", rc);
  }
  printf("\tMax Speed (kbps): %d\n", speed);


  rc = ofdpaPortCurrSpeedGet(portNum, &speed);
  if ((rc != OFDPA_E_NONE) && (rc != OFDPA_E_UNAVAIL))
  {
    printf("Failed to get Port Current Speed. (rc = %d)\n", rc);
  }
  printf("\tCurrent Speed (kbps): %d\n", speed);

  rc = ofdpaPortFeatureGet(portNum, &feature);
  if (rc != OFDPA_E_NONE)
  {
    printf("Failed to get Port Features. (rc = %d)\n", rc);
  }
  printf("\tCurrFeature: 0x%x\n", feature.curr);
  printf("\tAdvertFeature: 0x%x\n", feature.advertised);
  printf("\tSupportedFeature: 0x%x\n", feature.supported);
  printf("\tPeerFeature: 0x%x\n", feature.peer);

  return;
}


int main(int argc, char *argv[])
{
  int i;
  char client_name[] = "ofdpa port client";
  char docBuffer[300];
  char versionBuf[100];

  OFDPA_ERROR_t rc;
  ofdpaPortStats_t stats;
  int portNum = 0;
  uint32_t numQueues = 0;
  uint32_t queueId;
  uint32_t maxRate;
  uint32_t minRate;
  ofdpaPortQueueStats_t queueStats;

  arguments_t arguments =
    {
      .port           = DEFAULT_PORT,
      .properties     = 0,
      .stats          = 0,
      .adminState     = DEFAULT_ADMINSTATE,
      .adminStateFlag = 0,
      .advFeature     = 0,
      .advFeatureFlag = 0,
      .queueId        = DEFAULT_QUEUEID,
      .queueFlag      = 0,
      .queueMinRate   = DEFAULT_QUEUEMINRATE,
      .queueMaxRate   = DEFAULT_QUEUEMAXRATE,
      .queueRate      = 0,
      .queueStats     = 0,
      .list           = 0,
      .clear          = 0
    };

  /* Our argp parser. */
  struct argp argp =
    {
      .doc      = docBuffer,
      .options  = options,
      .parser   = parse_opt,
      .args_doc = "[" ARG_PROP "] [" ARG_LIST "] [" ARG_CLEAR "]",
    };

  sprintf(versionBuf, "%s v%.1f", basename(strdup(__FILE__)), VERSION);
  argp_program_version = versionBuf;


  strcpy(docBuffer, "\r\nConfigures/lists ports and port queues.\vDefault values:\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "PORT         = %d\n", DEFAULT_PORT);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "ADMINSTATE   = %d\n", DEFAULT_ADMINSTATE);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "QUEUEID      = %d\n", DEFAULT_QUEUEID);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "QUEUEMINRATE = %d\n", DEFAULT_QUEUEMINRATE);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "QUEUEMAXRATE = %d\n", DEFAULT_QUEUEMAXRATE);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "\n");




  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }

  portNum = arguments.port;

  if (arguments.properties == 1)
  {
    displayPortProperties(portNum);
  }
  else if (arguments.list)
  {
    if (arguments.stats == 1)
    {
      memset(&stats, 0, sizeof(stats));

      rc = ofdpaPortStatsGet(portNum, &stats);
      if (rc != OFDPA_E_NONE)
      {
        printf("Failed to get Port Statistics. (rc = %d)\n", rc);
      }

      printf("\nPort %d statistics:\n", portNum);
      printf("\trx pkts: %llu, tx pkts: %llu\n", (unsigned long long int)stats.rx_packets, (unsigned long long int)stats.tx_packets);
      printf("\trx bytes: %llu, tx bytes: %llu\n", (unsigned long long int)stats.rx_bytes, (unsigned long long int)stats.tx_bytes);
      printf("\trx errors: %llu, tx errors: 0x%llx\n", (unsigned long long int)stats.rx_errors, (unsigned long long int)stats.tx_errors);
      printf("\trx drops: %llu, tx drops: %llu\n", (unsigned long long int)stats.rx_drops, (unsigned long long int)stats.tx_drops);
      printf("\trx frame err: %llu, rx over err: %llu\n", (unsigned long long int)stats.rx_frame_err, (unsigned long long int)stats.rx_over_err);
      printf("\trx crc err: %llu\n", (unsigned long long int)stats.rx_crc_err);
      printf("\tduration: %u\n", stats.duration_seconds);
    }
    else if (arguments.queueRate == 1)
    {
      rc = ofdpaNumQueuesGet(portNum, &numQueues);
      if (rc != OFDPA_E_NONE)
      {
        printf("Failed to get number of port queues. (rc = %d)\n", rc);
      }
      else
      {
        printf("Port : %d\n", portNum);
        for (queueId = 0; queueId < numQueues; queueId++)
        {
          rc = ofdpaQueueRateGet(portNum, queueId, &minRate, &maxRate);
          if (rc != OFDPA_E_NONE)
          {
            printf("Failed to get port queue rate on queue %d. (rc = %d)\n", queueId, rc);
            break;
          }
          else
          {
            printf("Queue ID %d - min rate: %d max rate: %d\n", queueId, minRate, maxRate);
          }
        }
      }
    }
    else if (arguments.queueStats == 1)
    {
      rc = ofdpaNumQueuesGet(portNum, &numQueues);
      if (rc != OFDPA_E_NONE)
      {
        printf("Failed to get number of port queues. (rc = %d)\n", rc);
      }
      else
      {
        printf("\tNo. of queues on port %d: %d\n", portNum, numQueues);
        memset(&queueStats, 0, sizeof(ofdpaPortQueueStats_t));
        for (queueId = 0; queueId < numQueues; queueId++)
        {
          rc = ofdpaQueueStatsGet(portNum, queueId, &queueStats);
          if (rc != OFDPA_E_NONE)
          {
            printf("Failed to get port queue statistics. (rc = %d)\n", rc);
            break;
          }
          else
          {
            printf("\n");
            printf("\tPort Queue ID: %d - TX packets: %llu TX bytes: %llu\n",
                   queueId, (unsigned long long int)queueStats.txPkts, (unsigned long long int)queueStats.txBytes);
            printf("\tDuration since the queue %d is up: %u secs\n", queueId, queueStats.duration_seconds);
          }
        }
      }
    }
    else
    {
      displayPortProperties(portNum);
    }
  }
  else if (arguments.clear == 1)
  {
    if (arguments.stats == 1)
    {
      rc = ofdpaPortStatsClear(portNum);
      if (rc != OFDPA_E_NONE)
      {
        printf("Failed to clear Port Statistics. (rc = %d)\n", rc);
      }
      else
      {
        printf("Port Statistics cleared. \n");
      }
    }
    else if (arguments.queueStats == 1)
    {
      rc = ofdpaNumQueuesGet(portNum, &numQueues);
      if (rc != OFDPA_E_NONE)
      {
        printf("Failed to get number of port queues. (rc = %d)\n", rc);
      }
      else
      {
        for (queueId = 0; queueId < numQueues; queueId++)
        {
          rc = ofdpaQueueStatsClear(portNum, queueId);
          if (rc != OFDPA_E_NONE)
          {
            printf("Failed to clear port queue statistics. (rc = %d)\n", rc);
            break;
          }
        }
        if (rc == OFDPA_E_NONE)
        {
          printf("\tQueue stats on port %d are cleared successfully.\n", portNum);
        }
      }
    }
    else
    {
      printf("Please provide a valid option for %s.\n", ARG_CLEAR);
    }
  }
  else if (arguments.adminStateFlag == 1)
  {
    rc = ofdpaPortConfigSet(portNum, arguments.adminState);
    if (rc != OFDPA_E_NONE)
    {
      printf("Failed to configure Port Admin State. (rc = %d)\n", rc);
    }
    else
    {
      printf("Port Admin State configured. \n");
    }
  }
  else if (arguments.advFeatureFlag == 1)
  {
    rc = ofdpaPortAdvertiseFeatureSet(portNum, arguments.advFeature);
    if (rc != OFDPA_E_NONE)
    {
      printf("Failed to configure Port Advertise Features. (rc = %d)\n", rc);
    }
    else
    {
      printf("Port Advertised Features configured. \n");
    }
  }
  else if (arguments.queueFlag == 1)
  {
    rc = ofdpaNumQueuesGet(portNum, &numQueues);
    if (rc != OFDPA_E_NONE)
    {
      printf("Failed to get number of port queues. (rc = %d)\n", rc);
    }
    else
    {
      if (arguments.queueId >= numQueues)
      {
        printf("Invalid queue ID. (queueId = %d)\n", arguments.queueId);
      }
      else
      {
        rc = ofdpaQueueRateSet(portNum, arguments.queueId, arguments.queueMinRate, arguments.queueMaxRate);
        if (rc != OFDPA_E_NONE)
        {
          printf("Failed to set min and max rates on port queue %d. (rc = %d)\n", arguments.queueId, rc);
        }
        else
        {
          printf("Port queue min and max rates set successfully on port %d.\n", portNum);
        }
      }
    }
  }
  else
  {
    (void)displayPortProperties(portNum);
  }

  return 0;
}
