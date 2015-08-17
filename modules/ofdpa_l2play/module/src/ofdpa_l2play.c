#include <stdio.h>
#include <string.h>

#include <ofdpa_api.h>

#include "patch.h"

char * buffdesc2str(ofdpa_buffdesc desc)
{
    return desc.pstart;    /* should be null terminated */
}

OFDPA_ERROR_t
dump_ports(FILE * fp) {
    OFDPA_ERROR_t rc;
    uint32_t currPort, nextPort;
    int portCount = 0;
    char buf[OFDPA_PORT_NAME_STRING_SIZE+1];

    ofdpa_buffdesc portName;
    memset(buf, 0, sizeof(buf));
    portName.pstart = buf;
    portName.size = OFDPA_PORT_NAME_STRING_SIZE;

    portCount = 0;
    currPort = 0;
    fprintf(fp, "------- List of Ports --------\n");
    while( (rc = ofdpaPortNextGet(currPort, &nextPort)) == OFDPA_E_NONE)
    {   
        currPort = nextPort;
        portCount++;
        rc = ofdpaPortNameGet( currPort, &portName);
        fprintf( fp, "Port #%d: %s \n", portCount, buffdesc2str(portName));
    }   

    if (rc == OFDPA_E_FAIL)
    {
        fprintf(fp, "-------   End    ----------\n");
        return 0;   /* exited normally, per spec */
    }
    else 
        return rc;
}

/****
 * Check if source mac learning is enabled.
 * If disabled, enable it.
 * Log the change
 */

int enable_src_mac_learning(FILE * fp)
{
    OFDPA_ERROR_t rc;
    OFDPA_CONTROL_t status;
    ofdpaSrcMacLearnModeCfg_t cfg;

    if((rc = ofdpaSourceMacLearningGet( &status, &cfg)) != OFDPA_E_NONE)
    {
        fprintf(fp, "ofdpaSourceMacLearningGet() returned error: %d\n", rc);
        return rc;
    }

    fprintf(fp, "Learning Mode: WAS %s for %d\n", 
            status == OFDPA_ENABLE? "enabled" : "disabled",
            cfg.destPortNum);

    cfg.destPortNum = OFDPA_PORT_LOCAL;    /* enable learning for the local switch,
                                   not the CONTROLLER */

    if((rc = ofdpaSourceMacLearningSet(  OFDPA_ENABLE, &cfg)) != OFDPA_E_NONE)
    {
        fprintf(fp, "ofdpaSourceMacLearningSet() returned error: %d\n", rc);
        return rc;
    }
    return 0;
}
int
aim_main(int argc, char * argv[])
{
    OFDPA_ERROR_t rc;
    char * client_name = "ofdpa_l2play";

    rc = ofdpaClientInitialize(client_name);
    if (OFDPA_E_NONE != rc)
    {
        fprintf(stderr, "ofdpaClientInitialize() failed: returned %d n",
                rc);
        return rc;
    }

    printf("Successfully connected to OF-DPA daemon\n");
    if ((rc = dump_ports(stdout)) != 0)
    {
        fprintf(stderr, "Error: dump_ports returned %d\n", rc);
    }

#if 0
    if ((rc = enable_src_mac_learning(stdout)) != 0)
    {
        fprintf(stderr, "Error: failed to enable source mac learning: %d\n", rc);
    }
#endif

    patch(1,2);

    return 0;
}
