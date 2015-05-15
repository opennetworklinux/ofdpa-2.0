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
* @filename     client_mpls_qos.c
*
* @purpose      Example code for MPLS QOS Flow Table. Uses RPC calls.
*
* @component    client example
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

#define VERSION              2.0

#define ARG_DELETE        "delete"
#define ARG_LIST          "list"

#define DEFAULT_COUNT           1
#define DEFAULT_DELETE          0
#define DEFAULT_LIST            0
#define DEFAULT_QOSINDEX        1
#define DEFAULT_MPLSTC          1
#define DEFAULT_TRAFFICCLASS    1 
#define DEFAULT_COLOR           OFDPA_QOS_GREEN

#define KEY_COUNT               1001
#define KEY_QOSINDEX            1002
#define KEY_MPLSTC              1003
#define KEY_TRAFFICCLASS        1004
#define KEY_COLOR               1005

typedef struct
{
  int      count;
  uint8_t  qosIndex;
  uint8_t  mplsTc;

  uint8_t             trafficClass;
  OFDPA_QOS_COLORS_t  color;

  int      delete;
  int      list;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "count",           KEY_COUNT,          "COUNT",            0, "Number of MPLS L2 ports to add."                                              , },
  { "qosIndex",        KEY_QOSINDEX,       "QOS_INDEX",        0, "Index for QOS Trust profile."                                                 , },
  { "mpls_tc",         KEY_MPLSTC,         "MPLS_TC",          0, "EXP field."                                                                   , },
  { 0,                 0,                  0,                  0, "Actions:"                                                                     , },
  { "trafficclass",    KEY_TRAFFICCLASS,   "Traffic Class",    0, "Sets the traffic class value."                                                , },
  { "color",           KEY_COLOR,          "Color",            0, "Sets the packet color."                                                       , },
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
    case KEY_COUNT:                     /* count */
      errno = 0;
      arguments->count = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid count \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_QOSINDEX:                 /* QOS Index */
      errno = 0;
      arguments->qosIndex = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid Qos Index \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_MPLSTC:                  /* MPLS TC */
      errno = 0;
      arguments->mplsTc = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid MPLS TC field \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_TRAFFICCLASS:            /* Traffic Class */
      errno = 0;
      arguments->trafficClass = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid Traffic Class \"%s\"", arg);
        return errno;
      }
      break;

    case KEY_COLOR:                 /* Color */
      errno = 0;
      arguments->color = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid  color\"%s\"", arg);
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

static void displayMplsQos(ofdpaFlowEntry_t *flow, int decodeGroup)
{
  printf("\tQOS INDEX      = %d\n", flow->flowData.mplsQosFlowEntry.match_criteria.qosIndex);
  printf("\tMPLS TC        = %d\n", flow->flowData.mplsQosFlowEntry.match_criteria.mpls_tc);

  printf("\tTRAFFIC CLASS  = %d\n", flow->flowData.mplsQosFlowEntry.trafficClass);
  printf("\tCOLOR          = %d\n", flow->flowData.mplsQosFlowEntry.color);
}

int main(int argc, char *argv[])
{
   int                   i;
  OFDPA_ERROR_t         rc;
  char                  client_name[20] = "ofdpa client";
  char                  docBuffer[300];
  char                  versionBuf[100];
  ofdpaFlowEntry_t      flow;
  ofdpaFlowEntryStats_t flowStats;

  arguments_t arguments =
    {
      .count          = DEFAULT_COUNT,
      .delete         = DEFAULT_DELETE,
      .list           = DEFAULT_LIST,
      .qosIndex       = DEFAULT_QOSINDEX,
      .mplsTc         = DEFAULT_MPLSTC,
      .trafficClass   = 0,
      .color    = 0
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

  strcpy(docBuffer, "Adds an MPLS QOS flow.\vDefault values:\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "COUNT              = %d\n", DEFAULT_COUNT);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "QOS INDEX          = %d\n", DEFAULT_QOSINDEX);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "MPLS TC            = %d\n", DEFAULT_MPLSTC);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "TRAFFIC CLASS      = %d\n", DEFAULT_TRAFFICCLASS);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "COLOR              = %d\n", DEFAULT_COLOR);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "\n");

  /* Parse our arguments; every option seen by `parse_opt' will be reflected in
     `arguments'. */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }

  rc = ofdpaFlowEntryInit(OFDPA_FLOW_TABLE_ID_MPLS_QOS, &flow);
  if (rc != OFDPA_E_NONE)
  {
    printf("\r\nFailed to initialize MPLS QOS Table.(rc = %d)\n", rc);
    return rc;
  }

  flow.flowData.mplsQosFlowEntry.match_criteria.qosIndex     = arguments.qosIndex;
  flow.flowData.mplsQosFlowEntry.match_criteria.mpls_tc      = arguments.mplsTc;

  if (0 == arguments.list)
  {
    flow.flowData.mplsQosFlowEntry.trafficClass = arguments.trafficClass;
    flow.flowData.mplsQosFlowEntry.color        = arguments.color;
  }

  if (arguments.list || arguments.delete)
  {
    printf("%s up to %u MPLS QOS flows.\r\n", arguments.list ? "Listing" : "Deleting", arguments.count);
  }
  else
  {
      printf("Adding %u MPLS QOS flows with the following parameters:\r\n", arguments.count);
      displayMplsQos(&flow, (0 == arguments.list));
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
      displayMplsQos(&flow, 1);

      if (arguments.delete)
      {
        rc = ofdpaFlowDelete(&flow);
        if (rc != 0)
        {
          printf("\r\nError deleting MPLS QOS flow entry rc = %d.\r\n", rc);
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
    printf("\r\nQOS index is incremented in each additional flow.\r\n\r\n");

    for (i = 0; i < arguments.count; i++)
    {
      rc = ofdpaFlowAdd(&flow);

      if (rc != 0)
      {
        printf("\r\nFailed to add MPLS QOS flow entry. rc = %d.\r\n", rc);
        displayMplsQos(&flow, 1);
        break;
      }
      flow.flowData.mplsQosFlowEntry.match_criteria.qosIndex++;
    }
  }

  return 0;
}
