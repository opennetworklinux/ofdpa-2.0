/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <indigo_ofdpa_driver/indigo_ofdpa_driver_config.h>

#include "indigo_ofdpa_driver_log.h"

static int
datatypes_init__(void)
{
#define INDIGO_OFDPA_DRIVER_ENUMERATION_ENTRY(_enum_name, _desc)     AIM_DATATYPE_MAP_REGISTER(_enum_name, _enum_name##_map, _desc,                               AIM_LOG_INTERNAL);
#include <indigo_ofdpa_driver/indigo_ofdpa_driver.x>
    return 0;
}

void __indigo_ofdpa_driver_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
    datatypes_init__();
}

