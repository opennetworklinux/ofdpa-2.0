/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <ofdpa_l2play/ofdpa_l2play_config.h>

/* <auto.start.cdefs(OFDPA_L2PLAY_CONFIG_HEADER).source> */
#define __ofdpa_l2play_config_STRINGIFY_NAME(_x) #_x
#define __ofdpa_l2play_config_STRINGIFY_VALUE(_x) __ofdpa_l2play_config_STRINGIFY_NAME(_x)
ofdpa_l2play_config_settings_t ofdpa_l2play_config_settings[] =
{
#ifdef OFDPA_L2PLAY_CONFIG_INCLUDE_LOGGING
    { __ofdpa_l2play_config_STRINGIFY_NAME(OFDPA_L2PLAY_CONFIG_INCLUDE_LOGGING), __ofdpa_l2play_config_STRINGIFY_VALUE(OFDPA_L2PLAY_CONFIG_INCLUDE_LOGGING) },
#else
{ OFDPA_L2PLAY_CONFIG_INCLUDE_LOGGING(__ofdpa_l2play_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef OFDPA_L2PLAY_CONFIG_LOG_OPTIONS_DEFAULT
    { __ofdpa_l2play_config_STRINGIFY_NAME(OFDPA_L2PLAY_CONFIG_LOG_OPTIONS_DEFAULT), __ofdpa_l2play_config_STRINGIFY_VALUE(OFDPA_L2PLAY_CONFIG_LOG_OPTIONS_DEFAULT) },
#else
{ OFDPA_L2PLAY_CONFIG_LOG_OPTIONS_DEFAULT(__ofdpa_l2play_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef OFDPA_L2PLAY_CONFIG_LOG_BITS_DEFAULT
    { __ofdpa_l2play_config_STRINGIFY_NAME(OFDPA_L2PLAY_CONFIG_LOG_BITS_DEFAULT), __ofdpa_l2play_config_STRINGIFY_VALUE(OFDPA_L2PLAY_CONFIG_LOG_BITS_DEFAULT) },
#else
{ OFDPA_L2PLAY_CONFIG_LOG_BITS_DEFAULT(__ofdpa_l2play_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef OFDPA_L2PLAY_CONFIG_LOG_CUSTOM_BITS_DEFAULT
    { __ofdpa_l2play_config_STRINGIFY_NAME(OFDPA_L2PLAY_CONFIG_LOG_CUSTOM_BITS_DEFAULT), __ofdpa_l2play_config_STRINGIFY_VALUE(OFDPA_L2PLAY_CONFIG_LOG_CUSTOM_BITS_DEFAULT) },
#else
{ OFDPA_L2PLAY_CONFIG_LOG_CUSTOM_BITS_DEFAULT(__ofdpa_l2play_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef OFDPA_L2PLAY_CONFIG_PORTING_STDLIB
    { __ofdpa_l2play_config_STRINGIFY_NAME(OFDPA_L2PLAY_CONFIG_PORTING_STDLIB), __ofdpa_l2play_config_STRINGIFY_VALUE(OFDPA_L2PLAY_CONFIG_PORTING_STDLIB) },
#else
{ OFDPA_L2PLAY_CONFIG_PORTING_STDLIB(__ofdpa_l2play_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef OFDPA_L2PLAY_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
    { __ofdpa_l2play_config_STRINGIFY_NAME(OFDPA_L2PLAY_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS), __ofdpa_l2play_config_STRINGIFY_VALUE(OFDPA_L2PLAY_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS) },
#else
{ OFDPA_L2PLAY_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS(__ofdpa_l2play_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef OFDPA_L2PLAY_CONFIG_INCLUDE_UCLI
    { __ofdpa_l2play_config_STRINGIFY_NAME(OFDPA_L2PLAY_CONFIG_INCLUDE_UCLI), __ofdpa_l2play_config_STRINGIFY_VALUE(OFDPA_L2PLAY_CONFIG_INCLUDE_UCLI) },
#else
{ OFDPA_L2PLAY_CONFIG_INCLUDE_UCLI(__ofdpa_l2play_config_STRINGIFY_NAME), "__undefined__" },
#endif
    { NULL, NULL }
};
#undef __ofdpa_l2play_config_STRINGIFY_VALUE
#undef __ofdpa_l2play_config_STRINGIFY_NAME

const char*
ofdpa_l2play_config_lookup(const char* setting)
{
    int i;
    for(i = 0; ofdpa_l2play_config_settings[i].name; i++) {
        if(strcmp(ofdpa_l2play_config_settings[i].name, setting)) {
            return ofdpa_l2play_config_settings[i].value;
        }
    }
    return NULL;
}

int
ofdpa_l2play_config_show(struct aim_pvs_s* pvs)
{
    int i;
    for(i = 0; ofdpa_l2play_config_settings[i].name; i++) {
        aim_printf(pvs, "%s = %s\n", ofdpa_l2play_config_settings[i].name, ofdpa_l2play_config_settings[i].value);
    }
    return i;
}

/* <auto.end.cdefs(OFDPA_L2PLAY_CONFIG_HEADER).source> */

