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
* @filename     client_srcmac_learn.c
*
* @purpose      Enables, disables Source MAC learning mode. Uses RPC calls.
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
#include <time.h>
#include <argp.h>
#include <libgen.h>

#include "ofdpa_api.h"

const char *argp_program_version = "client_event v1.0";

#define VERSION           1.0

#define ARG_LIST          "list"

#define DEFAULT_MODE 0
#define DEFAULT_LIST      0

typedef struct
{
  int      mode;
  int      list;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "mode", 'm', "MODE", 0, "Source Mac Learn Mode to set.", 0},
  { 0 }
};


static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  /* Get the INPUT argument from `argp_parse', which we
     know is a pointer to our arguments structure. */
  arguments_t *arguments = state->input;

  switch (key)
  {
    case 'm':                           /* mode */
      errno = 0;
      arguments->mode = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid mode \"%s\"", arg);
        return errno;
      }
      break;

    case ARGP_KEY_ARG:
      if (0 == strcasecmp(ARG_LIST, arg))
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
  return (0);
}

int main(int argc, char *argv[])
{
  int   rc = 0;
  int   i;
  char  docBuffer[300];
  char  versionBuf[100];
  OFDPA_CONTROL_t mode;
  char  client_name[] = "ofdpa source mac learning client";
  ofdpaSrcMacLearnModeCfg_t srcMacLearnModeCfg;


  arguments_t arguments =
    {
      .mode = DEFAULT_MODE,
      .list = DEFAULT_LIST,
    };

  /* Our argp parser. */
  struct argp argp =
    {
      .doc      = docBuffer,
      .options  = options,
      .parser   = parse_opt,
      .args_doc = "[ " ARG_LIST " ]",
    };

  sprintf(versionBuf, "%s v%.1f", basename(strdup(__FILE__)), VERSION);
  argp_program_version = versionBuf;

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }

  strcpy(docBuffer, "Sets or lists the Source Mac Learn Mode.\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "Modes:\n");

  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "\t1 = Enable - Copy the packets with unknown source address to CPU.\n");
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "\t0 = Disable - Switch the packets with unknown source address.\n");

  /* Parse our arguments; every option seen by `parse_opt' will be reflected in
     `arguments'. */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  if (arguments.list)
  {
    memset(&srcMacLearnModeCfg, 0, sizeof(ofdpaSrcMacLearnModeCfg_t));
    if((rc = ofdpaSourceMacLearningGet(&mode, &srcMacLearnModeCfg)) != OFDPA_E_NONE)
    {
      printf("Failed to get Source Mac Learn Mode (rc = %d).\n", rc);
    }
    else
    {
      printf("Mode: %d\n", mode);
      printf("Destination Port: ");
      if (srcMacLearnModeCfg.destPortNum == OFDPA_PORT_CONTROLLER)
      {
        printf("Controller\n");
      }
      else
      {
        printf("%d\n", srcMacLearnModeCfg.destPortNum);
      }
    }
  }
  else
  {
    mode = arguments.mode;
    memset(&srcMacLearnModeCfg, 0, sizeof(srcMacLearnModeCfg));
    srcMacLearnModeCfg.destPortNum = OFDPA_PORT_CONTROLLER; /* Allowed destination port is only Controller port */
    if((rc = ofdpaSourceMacLearningSet(mode, &srcMacLearnModeCfg)) != OFDPA_E_NONE)
    {
      printf("Failed to set Source Mac Learn Mode. mode = %d, rc = %d\n", mode, rc);
    }
  }

  return OFDPA_E_NONE;
}
