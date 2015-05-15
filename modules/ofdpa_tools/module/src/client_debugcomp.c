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
* @filename     client_debugcomp.c
*
* @purpose      Set Debug Mode for OFDPA Components. Uses RPC calls.
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

#define DEFAULT_COMPONENT 0
#define DEFAULT_DISABLE   0
#define DEFAULT_LIST      0

typedef struct
{
  int      component;
  int      disable;
  int      list;
} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "component", 'c', "COMPONENT", 0, "The component ID to set or list.",       0 },
  { "disable",   'd', 0,           0, "Disables debugging for this component.", 1 },
  { 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  /* Get the INPUT argument from `argp_parse', which we
     know is a pointer to our arguments structure. */
  arguments_t *arguments = state->input;

  switch (key)
  {
    case 'c':                           /* component */
      errno = 0;
      arguments->component = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid component \"%s\"", arg);
        return errno;
      }
      break;

    case 'd':                           /* disable */
      arguments->disable = 1;
      break;

    case ARGP_KEY_ARG:
      if (0 == strcasecmp(ARG_LIST, arg))
      {
        if (arguments->disable)
        {
          argp_error(state, "\"" ARG_LIST "\" argument invalid with \'d\' option.");
        }
        else
        {
          arguments->list = 1;
        }
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

int main(int argc, char *argv[])
{
  int   rc           = 0;
  int   i;
  int   j;
  char  docBuffer[300];
  char  versionBuf[100];
  char  buffer[100];
  char client_name[] = "ofdpa debug client";
  ofdpa_buffdesc componentName;

  arguments_t arguments =
    {
      .component = DEFAULT_COMPONENT,
      .disable   = DEFAULT_DISABLE,
      .list      = DEFAULT_LIST,
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

  strcpy(docBuffer, "Sets or lists the debug component.\n");
  i = strlen(docBuffer);
  i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "Valid components are:\n");
  componentName.pstart = buffer;
  componentName.size   = sizeof(buffer);
  j = 1;
  while (0 == ofdpaComponentNameGet(j, &componentName))
  {
    i += snprintf(&docBuffer[i], sizeof(docBuffer) - i, "\t%2d = %s\n", j, componentName.pstart);
    componentName.size = sizeof(buffer);
    j++;
  }

  /* Parse our arguments; every option seen by `parse_opt' will be reflected in
     `arguments'. */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  if (arguments.list)
  {
    componentName.pstart = buffer;
    componentName.size   = sizeof(buffer);
    if (0 == arguments.component)
    {
      printf("\r\n");
      i = 1;
      while (0 == ofdpaComponentNameGet(i, &componentName))
      {
        printf("Component %s is %s for debugging.\r\n", componentName.pstart,
               ofdpaDebugComponentGet(i) ? "enabled" : "disabled");
        componentName.pstart = buffer;
        componentName.size   = sizeof(buffer);
        i++;
      }
    }
    else
    {
      if (0 != ofdpaComponentNameGet(arguments.component, &componentName))
      {
        printf("\r\nInvalid component %d.\r\n", arguments.component);
      }
      else
      {
        printf("\r\nComponent %s is %s for debugging.\r\n", componentName.pstart,
               ofdpaDebugComponentGet(arguments.component) ? "enabled" : "disabled");
      }
    }
    printf("\r\n");
  }
  else
  {
    rc = ofdpaDebugComponentSet(arguments.component, (0 == arguments.disable));
    if (0 != rc)
    {
      printf("\r\nInvalid component %d.\r\n", arguments.component);
    }
  }

  return rc;
}
