/**************************************************************************//**
 *
 * @file
 * @brief ofdpa_l2play Configuration Header
 *
 * @addtogroup ofdpa_l2play-config
 * @{
 *
 *****************************************************************************/
#ifndef __OFDPA_L2PLAY_CONFIG_H__
#define __OFDPA_L2PLAY_CONFIG_H__

#ifdef GLOBAL_INCLUDE_CUSTOM_CONFIG
#include <global_custom_config.h>
#endif
#ifdef OFDPA_L2PLAY_INCLUDE_CUSTOM_CONFIG
#include <ofdpa_l2play_custom_config.h>
#endif

/* <auto.start.cdefs(OFDPA_L2PLAY_CONFIG_HEADER).header> */
#include <AIM/aim.h>
/**
 * OFDPA_L2PLAY_CONFIG_INCLUDE_LOGGING
 *
 * Include or exclude logging. */


#ifndef OFDPA_L2PLAY_CONFIG_INCLUDE_LOGGING
#define OFDPA_L2PLAY_CONFIG_INCLUDE_LOGGING 1
#endif

/**
 * OFDPA_L2PLAY_CONFIG_LOG_OPTIONS_DEFAULT
 *
 * Default enabled log options. */


#ifndef OFDPA_L2PLAY_CONFIG_LOG_OPTIONS_DEFAULT
#define OFDPA_L2PLAY_CONFIG_LOG_OPTIONS_DEFAULT AIM_LOG_OPTIONS_DEFAULT
#endif

/**
 * OFDPA_L2PLAY_CONFIG_LOG_BITS_DEFAULT
 *
 * Default enabled log bits. */


#ifndef OFDPA_L2PLAY_CONFIG_LOG_BITS_DEFAULT
#define OFDPA_L2PLAY_CONFIG_LOG_BITS_DEFAULT AIM_LOG_BITS_DEFAULT
#endif

/**
 * OFDPA_L2PLAY_CONFIG_LOG_CUSTOM_BITS_DEFAULT
 *
 * Default enabled custom log bits. */


#ifndef OFDPA_L2PLAY_CONFIG_LOG_CUSTOM_BITS_DEFAULT
#define OFDPA_L2PLAY_CONFIG_LOG_CUSTOM_BITS_DEFAULT 0
#endif

/**
 * OFDPA_L2PLAY_CONFIG_PORTING_STDLIB
 *
 * Default all porting macros to use the C standard libraries. */


#ifndef OFDPA_L2PLAY_CONFIG_PORTING_STDLIB
#define OFDPA_L2PLAY_CONFIG_PORTING_STDLIB 1
#endif

/**
 * OFDPA_L2PLAY_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
 *
 * Include standard library headers for stdlib porting macros. */


#ifndef OFDPA_L2PLAY_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
#define OFDPA_L2PLAY_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS OFDPA_L2PLAY_CONFIG_PORTING_STDLIB
#endif

/**
 * OFDPA_L2PLAY_CONFIG_INCLUDE_UCLI
 *
 * Include generic uCli support. */


#ifndef OFDPA_L2PLAY_CONFIG_INCLUDE_UCLI
#define OFDPA_L2PLAY_CONFIG_INCLUDE_UCLI 0
#endif



/**
 * All compile time options can be queried or displayed
 */

/** Configuration settings structure. */
typedef struct ofdpa_l2play_config_settings_s {
    /** name */
    const char* name;
    /** value */
    const char* value;
} ofdpa_l2play_config_settings_t;

/** Configuration settings table. */
/** ofdpa_l2play_config_settings table. */
extern ofdpa_l2play_config_settings_t ofdpa_l2play_config_settings[];

/**
 * @brief Lookup a configuration setting.
 * @param setting The name of the configuration option to lookup.
 */
const char* ofdpa_l2play_config_lookup(const char* setting);

/**
 * @brief Show the compile-time configuration.
 * @param pvs The output stream.
 */
int ofdpa_l2play_config_show(struct aim_pvs_s* pvs);

/* <auto.end.cdefs(OFDPA_L2PLAY_CONFIG_HEADER).header> */

#include "ofdpa_l2play_porting.h"

#endif /* __OFDPA_L2PLAY_CONFIG_H__ */
/* @} */
