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
* @filename   ind_ofdpa_util.c
*
* @purpose    This file contains utility functions for Indigo
*
* @component  OF-DPA
*
* @comments   none
*
* @create     6 Nov 2013
*
* @end
*
**********************************************************************/
#include <indigo_ofdpa_driver/ind_ofdpa_util.h>
#include <indigo_ofdpa_driver/ind_ofdpa_log.h>

indigo_error_t indigoConvertOfdpaRv(OFDPA_ERROR_t result)
{
  indigo_error_t indigoRv = INDIGO_ERROR_UNKNOWN;

  switch(result)
  {
    case OFDPA_E_NONE:
      indigoRv = INDIGO_ERROR_NONE;
      break;
    case OFDPA_E_PARAM:
      indigoRv = INDIGO_ERROR_PARAM;
      break;
    case OFDPA_E_FULL:
      indigoRv = INDIGO_ERROR_RESOURCE;
      break;
    case OFDPA_E_EXISTS:
      indigoRv = INDIGO_ERROR_EXISTS;
      break;
    case OFDPA_E_TIMEOUT:
      indigoRv = INDIGO_ERROR_TIME_OUT;
      break;
    case OFDPA_E_UNAVAIL:
      indigoRv = INDIGO_ERROR_NOT_SUPPORTED;
      break;
    case OFDPA_E_NOT_FOUND:
      indigoRv = INDIGO_ERROR_NOT_FOUND;
      break;
    case OFDPA_E_FAIL:
    case OFDPA_E_EMPTY:
    case OFDPA_E_DISABLED:
    case OFDPA_E_ERROR:
    case OFDPA_E_RPC:
    case OFDPA_E_INTERNAL:
    default:
      indigoRv = INDIGO_ERROR_UNKNOWN;
      break;
  }

  return indigoRv;
}


