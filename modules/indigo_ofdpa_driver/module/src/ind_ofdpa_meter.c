/*********************************************************************
*
* (C) Copyright Broadcom Corporation 2014
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
* @filename   ind_ofdpa_meter.c
*
* @purpose    OF-DPA Driver for Indigo
*
* @component  OF-DPA
*
* @comments   none
*
* @create     12 Aug 2014
*
* @end
*
**********************************************************************/
#include <indigo/forwarding.h>
#include <indigo_ofdpa_driver/ind_ofdpa_util.h>
#include <indigo_ofdpa_driver/ind_ofdpa_log.h>

#ifdef OFDPA_FIXUP
indigo_error_t indigo_fwd_meter_add(uint32_t id, uint16_t flag, of_list_meter_band_t *meters)
{
  indigo_error_t err = INDIGO_ERROR_NONE;
  of_meter_band_t of_meter_band;
  int rv;

  LOG_TRACE("meter_add: id %d, flag 0x%x",id, flag);
  OF_LIST_METER_BAND_ITER(meters, &of_meter_band, rv) 
  {
    switch (of_meter_band.header.object_id) {
      case OF_METER_BAND_DROP: {
        uint32_t rate, burst;
        of_meter_band_drop_rate_get(&of_meter_band.drop, &rate);
        of_meter_band_drop_burst_size_get(&of_meter_band.drop, &burst);
        LOG_TRACE("meter_band: %d, %d",rate, burst);
        break;
      }
      case OF_METER_BAND_DSCP_REMARK: {
        uint32_t rate, burst;
        uint8_t prec_level;
        of_meter_band_dscp_remark_rate_get(&of_meter_band.dscp_remark, &rate);
        of_meter_band_dscp_remark_burst_size_get(&of_meter_band.dscp_remark, &burst);
        of_meter_band_dscp_remark_prec_level_get(&of_meter_band.dscp_remark, &prec_level);
        LOG_TRACE("meter_band: %d, %d, %d",rate, burst, prec_level);
        break;
      }
      case OF_METER_BAND_OFDPA_COLOR_SET: {
        uint32_t rate, burst;
        uint8_t  color;
        of_meter_band_ofdpa_color_set_rate_get(&of_meter_band.ofdpa_color_set, &rate);
        of_meter_band_ofdpa_color_set_burst_size_get(&of_meter_band.ofdpa_color_set, &burst);
        of_meter_band_ofdpa_color_set_color_get(&of_meter_band.ofdpa_color_set, &color);
        LOG_TRACE("meter_band: %d, %d, %d",rate, burst, color);
        break;
      }
      default:
          LOG_ERROR("unsupported meter_band %d", of_meter_band.header.object_id);
          return INDIGO_ERROR_COMPAT;
    }
    
  }
  return err;
}
indigo_error_t indigo_fwd_meter_modify(uint32_t id, of_list_meter_band_t *meters)
{
  indigo_error_t err = INDIGO_ERROR_NONE;
  LOG_TRACE("meter_mod: id %d",id);
  return err;
}
indigo_error_t indigo_fwd_meter_delete(uint32_t id)
{
  indigo_error_t err = INDIGO_ERROR_NONE;
  LOG_TRACE("meter_del: id %d",id);
  return err;
}
#endif
