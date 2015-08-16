/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <ofdpa_l2play/ofdpa_l2play_config.h>

#include "ofdpa_l2play_log.h"

static int
datatypes_init__(void)
{
#define OFDPA_L2PLAY_ENUMERATION_ENTRY(_enum_name, _desc)     AIM_DATATYPE_MAP_REGISTER(_enum_name, _enum_name##_map, _desc,                               AIM_LOG_INTERNAL);
#include <ofdpa_l2play/ofdpa_l2play.x>
    return 0;
}

void __ofdpa_l2play_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
    datatypes_init__();
}

