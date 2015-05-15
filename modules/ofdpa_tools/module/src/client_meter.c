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
* @filename     client_meter.c
*
* @purpose      Add Meters. Uses RPC calls.
*
* @component    OF-DPA
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
#include <sys/types.h>
#include <sys/socket.h>
#include <libgen.h>

#include "ofdpa_api.h"
#include "ofdpa_datatypes.h"

#define VERSION              1.0

#define ARG_DELETE "delete"
#define ARG_LIST   "list"
#define ARG_STATS  "stats"

typedef enum
{
  KEY_METERID = 1001,
  KEY_METERFLAG,
  KEY_YELLOWBANDTYPE,
  KEY_YELLOWBANDRATE,
  KEY_YELLOWBANDBURST,
  KEY_REDBANDTYPE,
  KEY_REDBANDRATE,
  KEY_REDBANDBURST,
} meterKeys_t;

typedef struct
{
  ofdpaMeterEntry_t meter;
  int list;
  int delete;
  int stats;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  {"meterid",         KEY_METERID,             "METERID",           0, "Meter Id.",                   },
  {"meterflag",       KEY_METERFLAG,           "KEY_METERFLAG",     0, "Meter Flag.",                 },

  {0,                  0,                      0,                   0, "Meter Yellow Band:",          },
  {"yellowbandtype",   KEY_YELLOWBANDTYPE,     "YELLOWBANDTYPE",    0, "Yellow Band Type.",           },
  {"yellowbandrate",   KEY_YELLOWBANDRATE,     "YELLOWBANDRATE",    0, "Yellow Band Rate.",           },
  {"yellowbandburst",  KEY_YELLOWBANDBURST,    "YELLOWBANDBURST",   0, "Yellow Band Burst.",          },

  {0,                 0,                       0,                   0, "Meter Red Band:",             },
  {"redbandtype",     KEY_REDBANDTYPE,         "REDBANDTYPE",       0, "Red Band Type.",              },
  {"redbandrate",     KEY_REDBANDRATE,         "REDBANDRATE",       0, "Red Band Rate.",              },
  {"redbandburst",    KEY_REDBANDBURST,        "REDBANDBURST",      0, "Red Band Burst.",             },
  { 0 }
};

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  /* Get the INPUT argument from `argp_parse', which we
     know is a pointer to our arguments structure. */
  arguments_t *arguments = state->input;

  switch(key)
  {
    case KEY_METERID:
      errno = 0;
      arguments->meter.meterId = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid meter ID \"%s\"", arg);
        return errno;
      }

      break;

    case KEY_METERFLAG:
      arguments->meter.meterFlag = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid meter flag \"%s\"", arg);
        return errno;
      }

      break;

    case KEY_YELLOWBANDTYPE:
      arguments->meter.meterBand[0].bandType = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid meter yellow band type \"%s\"", arg);
        return errno;
      }

      break;

    case KEY_YELLOWBANDRATE:
      arguments->meter.meterBand[0].bandRate = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid meter yellow band rate \"%s\"", arg);
        return errno;
      }

      break;

    case KEY_YELLOWBANDBURST:
      arguments->meter.meterBand[0].bandBurst = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid meter yellow band burst \"%s\"", arg);
        return errno;
      }

      break;

    case KEY_REDBANDTYPE:
      arguments->meter.meterBand[1].bandType = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid meter red band type \"%s\"", arg);
        return errno;
      }

      break;

    case KEY_REDBANDRATE:
      arguments->meter.meterBand[1].bandRate = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid meter red band rate \"%s\"", arg);
        return errno;
      }

      break;

    case KEY_REDBANDBURST:
      arguments->meter.meterBand[1].bandBurst = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid meter red band burst \"%s\"", arg);
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
      else if (0 == strcasecmp(ARG_STATS, arg))
      {
        arguments->stats = 1;
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

void meterAdd(arguments_t *arguments)
{
  OFDPA_ERROR_t rc;

  rc = ofdpaMeterAdd(&arguments->meter);
  if (rc != OFDPA_E_NONE)
  {
    printf("Bad return code trying to Add a Meter Entry. (rc = %d)\r\n", rc);
  }
  else
  {
    printf("Meter entry added successfully \n");
  }
}

void meterDelete(uint32_t meterId)
{
  OFDPA_ERROR_t rc;

  rc = ofdpaMeterDelete(meterId);
  if (rc != OFDPA_E_NONE)
  {
    printf("Bad return code trying to delete a Meter Entry. (rc = %d)\r\n", rc);
  }
  else
  {
    printf("Meter entry deleted successfully \r\n");
  }
}

void meterTableList(uint32_t meterId)
{
  OFDPA_ERROR_t rc;
  ofdpaMeterEntry_t meter;
  uint32_t i;

  if (meterId != 0)
  {
    rc = ofdpaMeterGet(meterId, &meter);
    if (rc != OFDPA_E_NONE)
    {
      printf("Bad return code trying to get the Meter Entry. (rc = %d)\r\n", rc);
    }
    else
    {
      printf("Meter Id: 0x%x\r\n", meter.meterId);
      printf("Meter Flag: 0x%x\r\n", meter.meterFlag);

      for (i = 0; i < METER_BANDS_MAX; i++)
      {
        if (meter.meterBand[i].bandType == OFDPA_METER_BAND_YELLOW)
        {
          printf("\r\nYellow Band: \r\n"); 
        }
        else
        {
          printf("\r\nRed Band: \r\n");
        }
        printf("\tBand Type: 0x%x\r\n", meter.meterBand[i].bandType);
        printf("\tBand Rate: %d\r\n", meter.meterBand[i].bandRate);
        printf("\tBand Burst: %d\r\n", meter.meterBand[i].bandBurst);
      }
    }
  }
  else
  {
    printf("Meters:\r\n");
    while (OFDPA_E_NONE == ofdpaMeterNextGet(meterId, &meter))
    {
      meterId = meter.meterId;
      printf("\tMeter Id: 0x%x\r\n", meterId);
    }
  }
}

void meterStats(uint32_t meterId)
{
  OFDPA_ERROR_t rc;
  ofdpaMeterEntryStats_t meterStats;

  rc = ofdpaMeterStatsGet(meterId, &meterStats);
  if (rc != OFDPA_E_NONE)
  {
    printf("Bad return code trying to get Meter statistics. (rc = %d)\r\n", rc);
  }
  else
  {
    printf("Meter Id = 0x%x \r\n", meterId);
    printf("\tReference Count = %d \r\n", meterStats.refCount);
    printf("\tDuration = %d \r\n", meterStats.duration);
  }
}

int main(int argc, char *argv[])
{
  OFDPA_ERROR_t  rc;
  char           client_name[20] = "ofdpa client meter";
  char           docBuffer[300];
  char           versionBuf[100];
  arguments_t    arguments;

  memset(&arguments, 0, sizeof(arguments));


  /* Our argp parser. */
  struct argp argp =
    {
      .doc     = docBuffer,
      .options = options,
      .parser  = parse_opt,
      .args_doc = "[" ARG_DELETE "] [" ARG_LIST "] ["ARG_STATS"]",
    };

  sprintf(versionBuf, "%s v%.1f", basename(strdup(__FILE__)), VERSION);
  argp_program_version = versionBuf;

  strcpy(docBuffer, "\nAdds, deletes or lists meters.\n");

  /* Parse our arguments; every option seen by `parse_opt' will be reflected in
     `arguments'. */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }

  if (arguments.list)
  {
    meterTableList(arguments.meter.meterId);
  }
  else if (arguments.delete)
  {
    meterDelete(arguments.meter.meterId);
  }
  else if (arguments.stats)
  {
    meterStats(arguments.meter.meterId);
  }
  else
  {
    meterAdd(&arguments);
  }

  return rc;
}
