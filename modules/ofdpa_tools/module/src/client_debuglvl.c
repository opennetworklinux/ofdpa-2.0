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
* @filename     client_debuglvl.c
*
* @purpose      Set Debug verbosity level for OFDPA. Uses RPC calls.
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
#include <argp.h>
#include <libgen.h>
#include "ofdpa_api.h"

#define VERSION           1.0

#define ARG_LIST          "list"

#define DEFAULT_LEVEL     0
#define DEFAULT_LIST      0

typedef struct
{
  int      level;
  int      list;
} arguments_t;

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  /* Get the INPUT argument from `argp_parse', which we
     know is a pointer to our arguments structure. */
  arguments_t *arguments = state->input;

  switch (key)
  {
    case ARGP_KEY_ARG:
      if (0 == strcasecmp(ARG_LIST, arg))
      {
        arguments->list = 1;
      }
      else
      {
        errno = 0;
        arguments->level = strtoul(arg, NULL, 0);
        if (errno != 0)
        {
          argp_error(state, "Invalid level \"%s\"", arg);
          return errno;
        }
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

int main(int argc, char *argv[])
{
  int   rc            = 0;
  char  docBuffer[300];
  char  versionBuf[100];
  char  client_name[] = "ofdpa debug client";

  arguments_t arguments =
    {
      .level   = DEFAULT_LEVEL,
      .list    = DEFAULT_LIST,
    };

  /* Our argp parser. */
  struct argp argp =
    {
      .doc      = docBuffer,
      .options  = 0,
      .parser   = parse_opt,
      .args_doc = "<level> | " ARG_LIST,
    };

  sprintf(versionBuf, "%s v%.1f", basename(strdup(__FILE__)), VERSION);
  argp_program_version = versionBuf;

  strcpy(docBuffer, "Sets or lists the debug level.\n");

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
    printf("\r\nCurrent debug level is %d.\r\n", ofdpaDebugLvlGet());
  }
  else
  {
    rc = ofdpaDebugLvl(arguments.level);
    if (rc != 0)
    {
      printf("\r\nInvalid debug level %d.\r\n", arguments.level);
    }
  }

  return rc;
}
