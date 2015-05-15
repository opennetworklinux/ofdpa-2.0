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
* @filename     client_drivshell.c
*
* @purpose      Invokes BCM functions. Uses RPC calls.
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
#include "ofdpa_api.h"

int main(int argc, char *argv[])
{
  int i;
  int size;
  int rc;
  char client_name[] = "ofdpa drivshell client";
  char *ptr;
  ofdpa_buffdesc bufdesc;
  char buffer[200];

  size = argc;
  for (i = 1; i < argc; i++)
  {
    size += strlen(argv[i]);
  }

  if (size > sizeof(buffer))
  {
    return -2;
  }

  ptr = buffer;
  for (i = 1; i < argc; i++)
  {
    ptr = stpcpy(ptr, argv[i]);
    *ptr = ' ';
    ptr++;
  }
  *ptr = '\0';
  ptr++;

  bufdesc.size = strlen(buffer) + 1;
  bufdesc.pstart = buffer;

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }

  printf("Calling ofdpaBcmCommand rpc with command = \"%s\".\r\n", buffer);

  rc = ofdpaBcmCommand(bufdesc);

  printf("Returned from ofdpaBcmCommand rpc with rc = %d.\r\n", rc);

  return rc;
}
