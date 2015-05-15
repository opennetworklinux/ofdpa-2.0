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
* @filename     client_oam_dump.c
*
* @purpose      Display OAM configuration and status.
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


struct
{
  OFDPA_OAM_MEG_TYPE_t type;
  char *name;
} oamMegTypeList[] =
{
  {OFDPA_OAM_MEG_TYPE_ETHERNET,      "Ethernet"},
  {OFDPA_OAM_MEG_TYPE_G8113_1,       "MPLS TP"},
};
#define MEG_TYPE_LIST_SIZE (sizeof(oamMegTypeList)/sizeof(oamMegTypeList[0]))

char *getMegTypeName(OFDPA_OAM_MEG_TYPE_t type)
{
  int i;

  for (i=0; i < MEG_TYPE_LIST_SIZE; i++)
  {
    if (oamMegTypeList[i].type == type)
    {
      return(oamMegTypeList[i].name);
    }
  }
  return("Unknown");
}

void displayMeg(uint32_t megIndex,
                ofdpaOamMegConfig_t *config,
                ofdpaOamMegStatus_t *status)
{
  int i;
  char buffer[50];

  memset(buffer, 0, sizeof(buffer));

  printf("MEG Index = %d\r\n", megIndex);
  printf("\tType          = %s\r\n", getMegTypeName(config->megType));

  printf("\tMEG ID        = ");
  for (i = 0; i < sizeof(config->megId); i++)
  {
    printf("%02x ", config->megId[i]);
  }
  printf("\r\n");

  printf("\tLevel         = %d\r\n", config->level);
  printf("\tMgd Inst Type = %d\r\n", config->managedInstanceType);
  printf("\tPrim VID      = %d\r\n", config->primVid);
  printf("\tMIP creation  = %d\r\n", config->mipCreation);

  if (status)
  {
    printf("\tStatus:\n");
    printf("\t\tReference count = %d\n", status->refCount);
  }
}

void displayRMep(uint32_t rmepId,
                 ofdpaOamRemoteMepConfig_t *config)
{
  char buffer[200];
  ofdpaMacAddr_t *mac;

  memset(buffer, 0, sizeof(buffer));

  printf("\t\tRMEP_ID = %d\r\n", rmepId);
  ofdpaGroupDecode(config->groupId, buffer, sizeof(buffer));
  printf("\t\t\tGroup ID      = 0x%x (%s)\r\n", config->groupId, buffer);
  mac = &config->macAddress;
  printf("\t\t\tMAC: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",
         mac->addr[0], mac->addr[1], mac->addr[2], mac->addr[3], mac->addr[4], mac->addr[5]);
}

void displayRMepEntries(uint32_t lmepId)
{
  OFDPA_ERROR_t rc;
  uint16_t rmepId;
  ofdpaOamRemoteMepConfig_t config;

  rmepId = 0;

  if ((rc = ofdpaOamRemoteMepGet(lmepId, rmepId, NULL)) != OFDPA_E_NONE)
  {
    if ((rc = ofdpaOamRemoteMepNextGet(lmepId, rmepId, &rmepId)) != OFDPA_E_NONE)
    {
      printf("\tNo Remote MEP entries found.\n");
      return;
    }
  }

  if (rc == OFDPA_E_NONE)
  {
    /* found an entry, display and iterate */
    printf("\tRemote MEP entries:\n");
    do
    {
      if ((rc = ofdpaOamRemoteMepGet(lmepId, rmepId, &config)) == OFDPA_E_NONE)
      {
        displayRMep(rmepId, &config);
      }
      else
      {
        printf("Error retrieving data for MEP entry. (lmepId = %x, rc = %d)\n",
               lmepId, rc);
      }
    } while (ofdpaOamRemoteMepNextGet(lmepId, rmepId, &rmepId) == OFDPA_E_NONE);
  }
}

void displayMep(uint32_t lmepId,
                ofdpaOamMepConfig_t *config,
                ofdpaOamMepStatus_t *status)
{
  char buffer[50];
  ofdpaMacAddr_t *mac;

  memset(buffer, 0, sizeof(buffer));

  printf("LMEP_ID = %d\r\n", lmepId);
  printf("\tMEG Index       = %d\r\n", config->megIndex);
  printf("\tMEP ID          = %d\r\n", config->mepId);
  printf("\tifIndex         = %d\r\n", config->ifIndex);
  printf("\tdirection       = %d\r\n", config->direction);
  mac = &config->macAddress;
  printf("\tMAC: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",
         mac->addr[0], mac->addr[1], mac->addr[2], mac->addr[3], mac->addr[4], mac->addr[5]);
  printf("\tenable          = %d\r\n", config->enable);
  printf("\tccmPeriod       = %d\r\n", config->ccmPeriod);
  printf("\tccmPriority     = %d\r\n", config->ccmPriority);
  printf("\tccmEnable       = %d\r\n", config->ccmEnable);
  printf("\t--- some config items not displayed ---\n");

  displayRMepEntries(lmepId);

  if (status)
  {
    printf("\tStatus:\n");
    printf("\t\tccmFramesSent     = %d\n", status->ccmFramesSent);
    printf("\t\tccmFramesReceived = %d\n", status->ccmFramesReceived);
    printf("\t\t--- some state items not displayed ---\n");
    printf("\t\tReference count  = %d\n", status->refCount);
  }
}

void displayMegEntries(void)
{
  OFDPA_ERROR_t rc;
  uint32_t megIndex;
  ofdpaOamMegConfig_t config;
  ofdpaOamMegStatus_t status;

  megIndex = 0;

  if ((rc = ofdpaOamMegGet(megIndex, NULL, NULL)) != OFDPA_E_NONE)
  {
    if ((rc = ofdpaOamMegNextGet(megIndex, &megIndex)) != OFDPA_E_NONE)
    {
      printf("No MEG entries found.\n");
      return;
    }
  }

  if (rc == OFDPA_E_NONE)
  {
    /* found an entry, display and iterate */
    do
    {
      if ((rc = ofdpaOamMegGet(megIndex, &config, &status)) == OFDPA_E_NONE)
      {
        displayMeg(megIndex, &config, &status);
      }
      else
      {
        printf("Error retrieving data for MEG entry. (index = %x, rc = %d)\n",
               megIndex, rc);
      }
    } while (ofdpaOamMegNextGet(megIndex, &megIndex) == OFDPA_E_NONE);
  }
}

void displayMepEntries(void)
{
  OFDPA_ERROR_t rc;
  uint32_t lmepId;
  ofdpaOamMepConfig_t config;
  ofdpaOamMepStatus_t status;

  lmepId = 0;

  if ((rc = ofdpaOamMepGet(lmepId, NULL, NULL)) != OFDPA_E_NONE)
  {
    if ((rc = ofdpaOamMepNextGet(lmepId, &lmepId)) != OFDPA_E_NONE)
    {
      printf("No MEP entries found.\n");
      return;
    }
  }

  if (rc == OFDPA_E_NONE)
  {
    /* found an entry, display and iterate */
    do
    {
      if ((rc = ofdpaOamMepGet(lmepId, &config, &status)) == OFDPA_E_NONE)
      {
        displayMep(lmepId, &config, &status);
      }
      else
      {
        printf("Error retrieving data for MEP entry. (lmepId = %x, rc = %d)\n",
               lmepId, rc);
      }
    } while (ofdpaOamMepNextGet(lmepId, &lmepId) == OFDPA_E_NONE);
  }
}

void displayMlpGroup(uint32_t mlpIndex, ofdpaOamMLPGroupConfig_t *config, ofdpaOamMLPGroupStatus_t *status)
{
  OFDPA_ERROR_t rc;
  char buffer[200];
  uint32_t lmepId;
  int first;

  memset(buffer, 0, sizeof(buffer));
  ofdpaGroupDecode(config->ffGroupId, buffer, sizeof(buffer));

  printf("\tmlpIndex = %d - Group ID = 0x%08x (%s), enable = %s ",
         mlpIndex, config->ffGroupId, buffer, (config->enable == 0)?"false":"true ");
  printf("Status: headEndRefCount = %d\r\n",
         status->headEndRefCount);

  lmepId = 0;
  if ((rc = ofdpaOamMepHeadEndProtectionGet(mlpIndex, lmepId)) != OFDPA_E_NONE)
  {
    rc = ofdpaOamMepHeadEndProtectionNextGet(mlpIndex, lmepId, &lmepId);
  }

  if (rc == OFDPA_E_NONE)
  {
    first = 1;
    /* display head end protection MEPs */
    printf("\t\thead-end lmepId: ");
    do
    {
      if (!first)
      {
        printf(", ");
      }
      printf("%d", lmepId);
      first = 0;
    } while (ofdpaOamMepHeadEndProtectionNextGet(mlpIndex, lmepId, &lmepId) == OFDPA_E_NONE);

    printf("\r\n");
  }

  lmepId = 0;
  if ((rc = ofdpaOamMepTailEndProtectionGet(mlpIndex, lmepId)) != OFDPA_E_NONE)
  {
    rc = ofdpaOamMepTailEndProtectionNextGet(mlpIndex, lmepId, &lmepId);
  }

  if (rc == OFDPA_E_NONE)
  {
    first = 1;
    /* display head end protection MEPs */
    printf("\t\ttail-end lmepId: ");
    do
    {
      if (!first)
      {
        printf(", ");
      }
      printf("%d", lmepId);
      first = 0;
    } while (ofdpaOamMepTailEndProtectionNextGet(mlpIndex, lmepId, &lmepId) == OFDPA_E_NONE);

    printf("\r\n");
  }
}

void displayMlpGroupEntries(void)
{
  OFDPA_ERROR_t rc;
  uint32_t mlpIndex;
  ofdpaOamMLPGroupConfig_t config;
  ofdpaOamMLPGroupStatus_t status;

  mlpIndex = 0;

  if ((rc = ofdpaOamMLPGroupGet(mlpIndex, NULL, NULL)) != OFDPA_E_NONE)
  {
    if ((rc = ofdpaOamMLPGroupNextGet(mlpIndex, &mlpIndex)) != OFDPA_E_NONE)
    {
      printf("No MLP Group entries found.\n");
      return;
    }
  }

  if (rc == OFDPA_E_NONE)
  {
    /* found an entry, display and iterate */
    do
    {
      if ((rc = ofdpaOamMLPGroupGet(mlpIndex, &config, &status)) == OFDPA_E_NONE)
      {
        displayMlpGroup(mlpIndex, &config, &status);
      }
      else
      {
        printf("Error retrieving data for MLP entry. (mlpIndex = %x, rc = %d)\n",
               mlpIndex, rc);
      }
    } while (ofdpaOamMLPGroupNextGet(mlpIndex, &mlpIndex) == OFDPA_E_NONE);
  }
}

int main(int argc, char *argv[])
{
  OFDPA_ERROR_t rc;
  char client_name[] = "ofdpa oam dump client";

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    printf("Error from ofdpaClientInitialize(). (rc == %d)", rc);
    return rc;
  }

  printf("--- MEG Table ---\n");
  displayMegEntries();
  printf("--- MEP Table ---\n");
  displayMepEntries();
  printf("--- MLP Group Table ---\n");
  displayMlpGroupEntries();

  return 0;
}
