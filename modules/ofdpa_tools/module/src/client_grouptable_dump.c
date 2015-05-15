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
* @filename     client_grouptable_dump.c
*
* @purpose      Print entries in the group table.
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

typedef struct
{
  int count;
  OFDPA_GROUP_ENTRY_TYPE_t groupType;
  int groupTypeOptionGiven;

} arguments_t;

/* The options we understand. */
static struct argp_option options[] =
{
  { "count", 'c', "COUNT",     0, "Number of entries to display. If not specified or set to 0, all entries displayed.", 0 },
  { "type",  't', "GROUPTYPE", 0, "Group entry type to list. If not specified, all types displayed.",                   0 },
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
    case 'c':                           /* count */
      errno = 0;
      arguments->count = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid count \"%s\"", arg);
        return errno;
      }
      break;

    case 't':
      errno = 0;
      arguments->groupType = strtoul(arg, NULL, 0);
      if (errno != 0)
      {
        argp_error(state, "Invalid group type \"%s\"", arg);
        return errno;
      }
      arguments->groupTypeOptionGiven = 1;
      break;

    case ARGP_KEY_ARG:
    case ARGP_KEY_NO_ARGS:
    case ARGP_KEY_END:
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

void printBucketEntry(ofdpaGroupBucketEntry_t *bucketEntry)
{
  OFDPA_GROUP_ENTRY_TYPE_t groupType;
  uint32_t subType;

  if (ofdpaGroupTypeGet(bucketEntry->groupId, &groupType) != OFDPA_E_NONE)
  {
    printf("Error extracting group type. bucketEntry->groupId = 0x%08x", bucketEntry->groupId);
    return;
  }

  printf("bucketIndex = %d: ", bucketEntry->bucketIndex);

  switch (groupType)
  {
    case OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE:
      printf("outputPort = %d ",
             bucketEntry->bucketData.l2Interface.outputPort);

      printf("popVlanTag = %d ",
             bucketEntry->bucketData.l2Interface.popVlanTag);
      break;

    case OFDPA_GROUP_ENTRY_TYPE_L2_UNFILTERED_INTERFACE:
      printf("outputPort = %d ",
             bucketEntry->bucketData.l2UnfilteredInterface.outputPort);
      break;

    case OFDPA_GROUP_ENTRY_TYPE_L3_INTERFACE:
      printf("referenceGroupId = 0x%08x ", bucketEntry->referenceGroupId);

      printf("vlanId = %d ",
             bucketEntry->bucketData.l3Interface.vlanId);

      printf("srcMac: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X ",
             bucketEntry->bucketData.l3Interface.srcMac.addr[0],
             bucketEntry->bucketData.l3Interface.srcMac.addr[1],
             bucketEntry->bucketData.l3Interface.srcMac.addr[2],
             bucketEntry->bucketData.l3Interface.srcMac.addr[3],
             bucketEntry->bucketData.l3Interface.srcMac.addr[4],
             bucketEntry->bucketData.l3Interface.srcMac.addr[5]
             );
      break;

    case OFDPA_GROUP_ENTRY_TYPE_L3_UNICAST:
      printf("referenceGroupId = 0x%08x ", bucketEntry->referenceGroupId);
      printf("vlanId = %d ", bucketEntry->bucketData.l3Unicast.vlanId);

      printf("srcMac: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X ",
             bucketEntry->bucketData.l3Unicast.srcMac.addr[0],
             bucketEntry->bucketData.l3Unicast.srcMac.addr[1],
             bucketEntry->bucketData.l3Unicast.srcMac.addr[2],
             bucketEntry->bucketData.l3Unicast.srcMac.addr[3],
             bucketEntry->bucketData.l3Unicast.srcMac.addr[4],
             bucketEntry->bucketData.l3Unicast.srcMac.addr[5]
             );

      printf("dstMac: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X ",
             bucketEntry->bucketData.l3Unicast.dstMac.addr[0],
             bucketEntry->bucketData.l3Unicast.dstMac.addr[1],
             bucketEntry->bucketData.l3Unicast.dstMac.addr[2],
             bucketEntry->bucketData.l3Unicast.dstMac.addr[3],
             bucketEntry->bucketData.l3Unicast.dstMac.addr[4],
             bucketEntry->bucketData.l3Unicast.dstMac.addr[5]
             );
      break;

    case OFDPA_GROUP_ENTRY_TYPE_L2_REWRITE:
      printf("referenceGroupId = 0x%08x ", bucketEntry->referenceGroupId);
      printf("vlanId = %d ", bucketEntry->bucketData.l2Rewrite.vlanId);

      printf("srcMac: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X ",
             bucketEntry->bucketData.l2Rewrite.srcMac.addr[0],
             bucketEntry->bucketData.l2Rewrite.srcMac.addr[1],
             bucketEntry->bucketData.l2Rewrite.srcMac.addr[2],
             bucketEntry->bucketData.l2Rewrite.srcMac.addr[3],
             bucketEntry->bucketData.l2Rewrite.srcMac.addr[4],
             bucketEntry->bucketData.l2Rewrite.srcMac.addr[5]
             );

      printf("dstMac: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X ",
             bucketEntry->bucketData.l2Rewrite.dstMac.addr[0],
             bucketEntry->bucketData.l2Rewrite.dstMac.addr[1],
             bucketEntry->bucketData.l2Rewrite.dstMac.addr[2],
             bucketEntry->bucketData.l2Rewrite.dstMac.addr[3],
             bucketEntry->bucketData.l2Rewrite.dstMac.addr[4],
             bucketEntry->bucketData.l2Rewrite.dstMac.addr[5]
             );
      break;

    case OFDPA_GROUP_ENTRY_TYPE_L2_OVERLAY:
      printf("outputPort = 0x%08x ",
             bucketEntry->bucketData.l2Overlay.outputPort);

      break;

    case OFDPA_GROUP_ENTRY_TYPE_L2_MULTICAST:
    case OFDPA_GROUP_ENTRY_TYPE_L2_FLOOD:
    case OFDPA_GROUP_ENTRY_TYPE_L3_MULTICAST:
    case OFDPA_GROUP_ENTRY_TYPE_L3_ECMP:
      printf("referenceGroupId = 0x%08x ", bucketEntry->referenceGroupId);
      break;

    case OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL:
      ofdpaGroupMplsSubTypeGet(bucketEntry->groupId, &subType);

      switch (subType)
      {
        case OFDPA_MPLS_INTERFACE:
          printf("referenceGroupId = 0x%08x ", bucketEntry->referenceGroupId);
          printf("vlanId = %d ", bucketEntry->bucketData.mplsInterface.vlanId);

          printf("srcMac: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X ",
                 bucketEntry->bucketData.mplsInterface.srcMac.addr[0],
                 bucketEntry->bucketData.mplsInterface.srcMac.addr[1],
                 bucketEntry->bucketData.mplsInterface.srcMac.addr[2],
                 bucketEntry->bucketData.mplsInterface.srcMac.addr[3],
                 bucketEntry->bucketData.mplsInterface.srcMac.addr[4],
                 bucketEntry->bucketData.mplsInterface.srcMac.addr[5]
                 );

          printf("dstMac: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X ",
                 bucketEntry->bucketData.mplsInterface.dstMac.addr[0],
                 bucketEntry->bucketData.mplsInterface.dstMac.addr[1],
                 bucketEntry->bucketData.mplsInterface.dstMac.addr[2],
                 bucketEntry->bucketData.mplsInterface.dstMac.addr[3],
                 bucketEntry->bucketData.mplsInterface.dstMac.addr[4],
                 bucketEntry->bucketData.mplsInterface.dstMac.addr[5]
                 );
          break;

        case OFDPA_MPLS_L2_VPN_LABEL:
        case OFDPA_MPLS_L3_VPN_LABEL:
        case OFDPA_MPLS_TUNNEL_LABEL1:
        case OFDPA_MPLS_TUNNEL_LABEL2:
        case OFDPA_MPLS_SWAP_LABEL:
          printf("referenceGroupId = 0x%08x ", bucketEntry->referenceGroupId);
          printf("pushL2Hdr = %d ", bucketEntry->bucketData.mplsLabel.pushL2Hdr);
          printf("pushVlan = %d ", bucketEntry->bucketData.mplsLabel.pushVlan);
          printf("newTpid = 0x%04x ", bucketEntry->bucketData.mplsLabel.newTpid);
          printf("pushMplsHdr = %d ", bucketEntry->bucketData.mplsLabel.pushMplsHdr);
          printf("pushCW = %d ", bucketEntry->bucketData.mplsLabel.pushCW);
          printf("mplsLabel = %d ", bucketEntry->bucketData.mplsLabel.mplsLabel);
          printf("mplsBOS = %d ", bucketEntry->bucketData.mplsLabel.mplsBOS);
          printf("mplsEXP = %d ", bucketEntry->bucketData.mplsLabel.mplsEXP);
          printf("mplsCopyEXPOutwards = %d ", bucketEntry->bucketData.mplsLabel.mplsCopyEXPOutwards);
          printf("mplsEXPRemarkTableIndex = %d ", bucketEntry->bucketData.mplsLabel.mplsEXPRemarkTableIndex);
          printf("mplsTTL = %d ", bucketEntry->bucketData.mplsLabel.mplsTTL);
          printf("mplsCopyTTLOutwards = %d ", bucketEntry->bucketData.mplsLabel.mplsCopyTTLOutwards);
          printf("mplsPriorityRemarkTableIndex = %d ", bucketEntry->bucketData.mplsLabel.mplsPriorityRemarkTableIndex);
          break;

        default:
          printf("Unknown group sub-type");
          break;
      }
      break;

    case OFDPA_GROUP_ENTRY_TYPE_MPLS_FORWARDING:
      ofdpaGroupMplsSubTypeGet(bucketEntry->groupId, &subType);

      switch (subType)
      {
        /* these subtypes are MPLS L2 Replication entries, all have same bucket actions */
        case OFDPA_MPLS_L2_FLOOD:
        case OFDPA_MPLS_L2_MULTICAST:
        case OFDPA_MPLS_L2_LOCAL_FLOOD:
        case OFDPA_MPLS_L2_LOCAL_MULTICAST:
          printf("referenceGroupId = 0x%08x ", bucketEntry->referenceGroupId);
          break;

        case OFDPA_MPLS_FAST_FAILOVER:
          printf("referenceGroupId = 0x%08x ", bucketEntry->referenceGroupId);
          printf("watchPort = 0x%08x", bucketEntry->bucketData.mplsFastFailOver.watchPort);
          break;

        case OFDPA_MPLS_1_1_HEAD_END_PROTECT:
          printf("referenceGroupId = 0x%08x ", bucketEntry->referenceGroupId);
          break;

        case OFDPA_MPLS_ECMP:
          printf("referenceGroupId = 0x%08x ", bucketEntry->referenceGroupId);
          break;

        case OFDPA_MPLS_L2_TAG:
          printf("referenceGroupId = 0x%08x ", bucketEntry->referenceGroupId);
          printf("pushVlan = %d ", bucketEntry->bucketData.mplsL2Tag.pushVlan);
          printf("newTpid = 0x%04x ", bucketEntry->bucketData.mplsL2Tag.newTpid);
          printf("popVlan = %d ", bucketEntry->bucketData.mplsL2Tag.popVlan);
          printf("vlanId = %d ", bucketEntry->bucketData.mplsL2Tag.vlanId);
          break;

        default:
          printf("Unknown group sub-type");
          break;
      }
      break;

    case OFDPA_GROUP_ENTRY_TYPE_LAST:
    default:
      printf("Unknown Group type");
      break;
  }
}

void groupTableList(OFDPA_GROUP_ENTRY_TYPE_t groupType, int groupTypeSpecified, int count)
{
  OFDPA_ERROR_t rc;
  ofdpaGroupEntry_t groupEntry;
  ofdpaGroupEntryStats_t groupStats;
  ofdpaGroupBucketEntry_t bucketEntry;
  OFDPA_GROUP_ENTRY_TYPE_t currentEntryType;
  char buf[200];
  int entriesDisplayedCount = 0;

  memset(&groupEntry, 0, sizeof(groupEntry));

  ofdpaGroupTypeSet(&groupEntry.groupId, groupType);

  /* it is possible that the groupId is an exact match for an entry */
  if ((rc = ofdpaGroupStatsGet(groupEntry.groupId, &groupStats)) != OFDPA_E_NONE)
  {
    rc = ofdpaGroupNextGet(groupEntry.groupId, &groupEntry);
  }

  /* found at least one entry, proceed */
  if (OFDPA_E_NONE == rc)
  {
    do
    {
      /* if groupType specified, only iterate of group entries of that type */
      if (groupTypeSpecified != 0)
      {
        if ((OFDPA_E_NONE != ofdpaGroupTypeGet(groupEntry.groupId, &currentEntryType)) ||
            (groupType != currentEntryType))
        {
          /* retrieved group entry not of requested type, done */
          break;
        }
      }

      /* group entry matches criteria, display it */
      ofdpaGroupDecode(groupEntry.groupId, buf, sizeof(buf));
      printf("groupId = 0x%08x (%s): ", groupEntry.groupId, buf);

      rc = ofdpaGroupStatsGet(groupEntry.groupId, &groupStats);
      if (rc != OFDPA_E_NONE)
      {
        printf("Error retrieving group entry stats. (rc = %d)\r\n", rc);
      }
      else
      {
        printf("duration: %d, refCount:%d\r\n", groupStats.duration, groupStats.refCount);
      }

      memset(&bucketEntry, 0, sizeof(bucketEntry));

      if (ofdpaGroupBucketEntryFirstGet(groupEntry.groupId, &bucketEntry) == OFDPA_E_NONE)
      {
        do
        {
          printf("\t");
          printBucketEntry(&bucketEntry);
          printf("\r\n");
        } while (ofdpaGroupBucketEntryNextGet(bucketEntry.groupId, bucketEntry.bucketIndex, &bucketEntry) == OFDPA_E_NONE);
      }

      entriesDisplayedCount++;
      if ((count != 0) && (entriesDisplayedCount >= count))
      {
        break;
      }

    } while (ofdpaGroupNextGet(groupEntry.groupId, &groupEntry) == OFDPA_E_NONE);
  }

  if (entriesDisplayedCount == 0)
  {
    printf("No entries found.\r\n");
  }

  return;
}

int main(int argc, char *argv[])
{
  OFDPA_ERROR_t  rc;
  char           client_name[20] = "group_table_dump";
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
  };

  sprintf(versionBuf, "%s v%.1f", basename(strdup(__FILE__)), VERSION);
  argp_program_version = versionBuf;

  strcpy(docBuffer, "\nLists group entries.\n");

  /* Parse our arguments; every option seen by `parse_opt' will be reflected in
     `arguments'. */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  rc = ofdpaClientInitialize(client_name);
  if (rc != OFDPA_E_NONE)
  {
    return rc;
  }

  groupTableList(arguments.groupType, arguments.groupTypeOptionGiven, arguments.count);

  return rc;
}
