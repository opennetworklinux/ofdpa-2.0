/**************************************************************************//**
 *
 * @file
 * @brief ofdpa_l2play Porting Macros.
 *
 * @addtogroup ofdpa_l2play-porting
 * @{
 *
 *****************************************************************************/
#ifndef __OFDPA_L2PLAY_PORTING_H__
#define __OFDPA_L2PLAY_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if OFDPA_L2PLAY_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef OFDPA_L2PLAY_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define OFDPA_L2PLAY_MALLOC GLOBAL_MALLOC
    #elif OFDPA_L2PLAY_CONFIG_PORTING_STDLIB == 1
        #define OFDPA_L2PLAY_MALLOC malloc
    #else
        #error The macro OFDPA_L2PLAY_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef OFDPA_L2PLAY_FREE
    #if defined(GLOBAL_FREE)
        #define OFDPA_L2PLAY_FREE GLOBAL_FREE
    #elif OFDPA_L2PLAY_CONFIG_PORTING_STDLIB == 1
        #define OFDPA_L2PLAY_FREE free
    #else
        #error The macro OFDPA_L2PLAY_FREE is required but cannot be defined.
    #endif
#endif

#ifndef OFDPA_L2PLAY_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define OFDPA_L2PLAY_MEMSET GLOBAL_MEMSET
    #elif OFDPA_L2PLAY_CONFIG_PORTING_STDLIB == 1
        #define OFDPA_L2PLAY_MEMSET memset
    #else
        #error The macro OFDPA_L2PLAY_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef OFDPA_L2PLAY_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define OFDPA_L2PLAY_MEMCPY GLOBAL_MEMCPY
    #elif OFDPA_L2PLAY_CONFIG_PORTING_STDLIB == 1
        #define OFDPA_L2PLAY_MEMCPY memcpy
    #else
        #error The macro OFDPA_L2PLAY_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef OFDPA_L2PLAY_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define OFDPA_L2PLAY_STRNCPY GLOBAL_STRNCPY
    #elif OFDPA_L2PLAY_CONFIG_PORTING_STDLIB == 1
        #define OFDPA_L2PLAY_STRNCPY strncpy
    #else
        #error The macro OFDPA_L2PLAY_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef OFDPA_L2PLAY_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define OFDPA_L2PLAY_VSNPRINTF GLOBAL_VSNPRINTF
    #elif OFDPA_L2PLAY_CONFIG_PORTING_STDLIB == 1
        #define OFDPA_L2PLAY_VSNPRINTF vsnprintf
    #else
        #error The macro OFDPA_L2PLAY_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef OFDPA_L2PLAY_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define OFDPA_L2PLAY_SNPRINTF GLOBAL_SNPRINTF
    #elif OFDPA_L2PLAY_CONFIG_PORTING_STDLIB == 1
        #define OFDPA_L2PLAY_SNPRINTF snprintf
    #else
        #error The macro OFDPA_L2PLAY_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef OFDPA_L2PLAY_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define OFDPA_L2PLAY_STRLEN GLOBAL_STRLEN
    #elif OFDPA_L2PLAY_CONFIG_PORTING_STDLIB == 1
        #define OFDPA_L2PLAY_STRLEN strlen
    #else
        #error The macro OFDPA_L2PLAY_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __OFDPA_L2PLAY_PORTING_H__ */
/* @} */
