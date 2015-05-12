/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <indigo_ofdpa_driver/indigo_ofdpa_driver_config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <AIM/aim.h>

int aim_main(int argc, char* argv[])
{
    printf("indigo_ofdpa_driver Utest Is Empty\n");
    indigo_ofdpa_driver_config_show(&aim_pvs_stdout);
    return 0;
}

