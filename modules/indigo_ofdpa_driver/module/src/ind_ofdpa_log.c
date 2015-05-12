/*********************************************************************
*
* (C) Copyright Broadcom Corporation 2013-2014
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
* @filename     ind_ofdpa_log.c
*
* @purpose      Indigo OF-DPA driver logs
*
* @component    OF-DPA
*
* @comments     none
*
* @create       6 Nov 2013
*
* @end
*
**********************************************************************/
#include <indigo_ofdpa_driver/ind_ofdpa_log.h>

AIM_LOG_STRUCT_DEFINE(
                      AIM_LOG_OPTIONS_DEFAULT,
                      AIM_LOG_BITS_DEFAULT,
                      NULL,     /* Custom Log Map */
                      0
                      );

void
__ind_ofdpa_driver_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
}

