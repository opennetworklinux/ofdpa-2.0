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
* @filename     client_ecmp_nexthop.c
*
* @purpose      Example code for ECMP Next Hop Group Memberss. Uses RPC calls.
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

#define ARG_DELETE        "delete"
#define ARG_LIST          "list"

#define KEY_COUNT         'c'
#define KEY_ECMP_GRP_ID   'e'
#define KEY_NEXT_HOP_ID   'n'

typedef struct
{
  int          count;
  int          delete;
  int          list;

  uint32_t     ecmpNextHopGrpId;
  uint32_t     nextHopId;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "count",       KEY_COUNT,       "COUNT",        0, "Number of ECMP Next Hop Group table entries to delete or list. (Use 0 for all.)",  0 },
  { "ecmpgrp",     KEY_ECMP_GRP_ID, "ECMPGRPID",    0, "Index for the ECMP Next Hop Group table entry.",                                   0 },
  { "nexthop",     KEY_NEXT_HOP_ID, "NEXTHOPID",    0, "Index of a Next Hop table entry that is a memberr of the group.",                  4 },
  { 0 }
};

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  /* Get the INPUT argument from `argp_parse', which we
     know is a pointer to our arguments structure. */
  arguments_t *arguments = state->input;
  uint32_t ecmpGrpId;
  uint32_t nextHopId;

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

  case KEY_ECMP_GRP_ID:
    errno = 0;
    ecmpGrpId = strtoul(arg, NULL, 0);
    if ((errno != 0) ||
        (ecmpGrpId < 1))
    {
      argp_error(state, "Invalid ECMP Next Hop Group ID \"%s\"", arg);
      return errno;
    }
    arguments->ecmpNextHopGrpId = ecmpGrpId;
    break;

  case KEY_NEXT_HOP_ID:
    errno = 0;
    nextHopId = strtoul(arg, NULL, 0);
    if (errno != 0)
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
    break;

  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

void displayTunnelEcmpGroupMember(uint32_t ecmpGrpId,
                                  uint32_t nextHopId)
{
  printf("ECMP Next Hop Group ID  = %d : Next Hop ID = %d\n", ecmpGrpId, nextHopId);
}

int main(int argc, char *argv[])
{
  int i;
  OFDPA_ERROR_t rc;
  char docBuffer[300];
  char versionBuf[100];
  char howmany[20];
  char client_name[] = "ofdpa tunnel ecmp next hop member client";

  arguments_t arguments =
  {
    .count                             = DEFAULT_COUNT,
    .delete                            = 0,
    .list                              = 0,
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

  strcpy(docBuffer, "Adds, deletes or lists ECMP next hop group members.\vDefault values:\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "COUNT     = %d\n", DEFAULT_COUNT);
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

    printf("%s %s member entr%s for ECMP Next Hop Group ID %d : Next Hop ID %d.\n",
           arguments.list ? "Listing" : "Deleting",
           howmany,
           arguments.count == 1 ? "y":"ies",
           arguments.ecmpNextHopGrpId,
           arguments.nextHopId);

    i = 0;
    /* see if entry matches  */
    if (ofdpaTunnelEcmpNextHopGroupMemberGet(arguments.ecmpNextHopGrpId, arguments.nextHopId) != OFDPA_E_NONE)
    {
      /* if no exact match, get the next one if any */
      if (ofdpaTunnelEcmpNextHopGroupMemberNextGet(arguments.ecmpNextHopGrpId, arguments.nextHopId, &arguments.nextHopId) != OFDPA_E_NONE)
      {
        /* no entries found to list */
        printf("No matching ECMP group members found.\n");
        return(0);
      }
    }
    /* got an entry, display or delete it and continue for count */
    do
    {
      i++;
      if (arguments.list)
      {
        displayTunnelEcmpGroupMember(arguments.ecmpNextHopGrpId, arguments.nextHopId);
      }
      else
      {
        if ((rc = ofdpaTunnelEcmpNextHopGroupMemberDelete(arguments.ecmpNextHopGrpId, arguments.nextHopId)) != OFDPA_E_NONE)
        {
          printf("Error deleting tunnel ECMP next hop group member. (ecmpNextHopGrpId = %d, nextHopId = %d, rc = %d)\n",
                 arguments.ecmpNextHopGrpId, arguments.nextHopId, rc);
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
    } while (ofdpaTunnelEcmpNextHopGroupMemberNextGet(arguments.ecmpNextHopGrpId, arguments.nextHopId, &arguments.nextHopId) == OFDPA_E_NONE);
  }
  else
  {
    /* add  */
    printf("Adding tunnel ECMP next hop group member with following parameters.\r\n");
    displayTunnelEcmpGroupMember(arguments.ecmpNextHopGrpId, arguments.nextHopId);

    rc = ofdpaTunnelEcmpNextHopGroupMemberAdd(arguments.ecmpNextHopGrpId, arguments.nextHopId);

    if (rc != OFDPA_E_NONE)
    {
      printf("Error adding ECMP next hop group member. (rc = %d)\r\n", rc);
    }
  }

  return rc;
}
