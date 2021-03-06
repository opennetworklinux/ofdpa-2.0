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
* @filename     client_tunnel_port_tenant.c
*
* @purpose      Example code for Tunnel Logical Port Tenants. Uses RPC calls.
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
#define DEFAULT_TUNNELID          1

#define ARG_DELETE        "delete"
#define ARG_LIST          "list"

#define KEY_COUNT                              1
#define KEY_PORT_INDEX                         2
#define KEY_TUNNEL_ID                          3

typedef struct
{
  int          count;
  int          delete;
  int          list;

  uint32_t     tunnelPortId;
  uint32_t     tunnelId;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "count",       KEY_COUNT,       "COUNT",        0, "Number of tunnel ports to delete or list. (Use 0 for all.)",  0 },
  { "port-index",  KEY_PORT_INDEX,  "INDEX",        0, "Index part of the ifNum of the logical port.",                 0 },
  { "tunnelid",    KEY_TUNNEL_ID,   "TUNNELID",     0, "Tenant tunnel ID.",                                            4 },
  { 0 }
};

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  /* Get the INPUT argument from `argp_parse', which we
     know is a pointer to our arguments structure. */
  arguments_t *arguments = state->input;
  uint32_t portIndex;
  uint32_t tunnelId;

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

  case KEY_TUNNEL_ID:
    errno = 0;
    tunnelId = strtoul(arg, NULL, 0);
    if ((errno != 0) ||
        (tunnelId < 1))
    {
      argp_error(state, "Invalid tunnel ID \"%s\"", arg);
      return errno;
    }
    arguments->tunnelId = tunnelId;
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

void displayTunnelPortTenant(uint32_t portId,
                             uint32_t tunnelId,
                             ofdpaTunnelPortTenantStatus_t *status)
{
  OFDPA_TUNNEL_PORT_TYPE_t portType;
  uint32_t                 portIndex;

  ofdpaPortTypeGet(portId, &portType);
  ofdpaPortIndexGet(portId, &portIndex);
  printf("port ID  = %x (type = %d, index = %d) : tunnelId = %d",
         portId, portType, portIndex, tunnelId);
  if (status)
  {
    printf(" - refCount = %d", status->refCount);
  }
  printf("\r\n");
}

int main(int argc, char *argv[])
{
  int i;
  OFDPA_ERROR_t rc;
  char docBuffer[300];
  char versionBuf[100];
  char howmany[20];
  char client_name[] = "ofdpa tunnel port tenant client";

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

  ofdpaTunnelPortTenantStatus_t status;

  sprintf(versionBuf, "%s v%.1f", basename(strdup(__FILE__)), VERSION);
  argp_program_version = versionBuf;

  ofdpaPortTypeSet(&arguments.tunnelPortId, OFDPA_PORT_TYPE_LOGICAL_TUNNEL);
  ofdpaPortIndexSet(&arguments.tunnelPortId, DEFAULT_PORT_INDEX);
  arguments.tunnelId = DEFAULT_TUNNELID;

  strcpy(docBuffer, "Adds, deletes or lists tenants on a tunnel logical port.\vDefault values:\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "COUNT     = %d\n", DEFAULT_COUNT);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "INDEX     = %d\n", DEFAULT_PORT_INDEX);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "TUNNELID  = %d\n", DEFAULT_TUNNELID);
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

    printf("%s %s entr%s for port ID %x starting at index %d.\n",
           arguments.list ? "Listing" : "Deleting",
           howmany,
           arguments.count == 1 ? "y":"ies",
           arguments.tunnelPortId,
           arguments.tunnelId);

    i = 0;
    /* see if entry matches  */
    if (ofdpaTunnelPortTenantGet(arguments.tunnelPortId, arguments.tunnelId, NULL) != OFDPA_E_NONE)
    {
      /* if no exact match, get the next one if any */
      if (ofdpaTunnelPortTenantNextGet(arguments.tunnelPortId, arguments.tunnelId, &arguments.tunnelId) != OFDPA_E_NONE)
      {
        /* no port tenant entries found to list */
        printf("No matching port tenant entries found.\n");
        return(0);
      }
    }
    /* got an entry, display or delete it and continue for count */
    do
    {
      i++;
      if (arguments.list)
      {
        if ((rc = ofdpaTunnelPortTenantGet(arguments.tunnelPortId, arguments.tunnelId, &status)) == OFDPA_E_NONE)
        {
          displayTunnelPortTenant(arguments.tunnelPortId, arguments.tunnelId, &status);
        }
        else
        {
          printf("Error retrieving data for tunnel port tenant entry. (portId = %x, tunnelId = %d, rc = %d)\n",
                 arguments.tunnelPortId, arguments.tunnelId, rc);
        }
      }
      else
      {
        if ((rc = ofdpaTunnelPortTenantDelete(arguments.tunnelPortId, arguments.tunnelId)) != OFDPA_E_NONE)
        {
          printf("Error deleting tunnel port tenant entry. (portId = %x, tunnelId = %d, rc = %d)\n",
                 arguments.tunnelPortId, arguments.tunnelId, rc);
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

    } while (ofdpaTunnelPortTenantNextGet(arguments.tunnelPortId, arguments.tunnelId, &arguments.tunnelId) == OFDPA_E_NONE);
  }
  else
  {
    /* add  */
    printf("Adding tunnel port tenant entry with following parameters.\r\n");
    displayTunnelPortTenant(arguments.tunnelPortId, arguments.tunnelId, NULL);

    rc = ofdpaTunnelPortTenantAdd(arguments.tunnelPortId, arguments.tunnelId);

    if (rc != OFDPA_E_NONE)
    {
      printf("Error adding tunnel port tenant. (rc = %d)\r\n", rc);
    }
  }

  return rc;
}
