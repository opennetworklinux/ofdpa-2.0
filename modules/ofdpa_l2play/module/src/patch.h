#ifndef PATCH_H
#define PATCH_H

#include <ofdpa_api.h>

/********
 * Make all traffic on port1 go out port2 and vice versa
 *  Limited to untagged traffic currently
 */
int patch(uint32_t port1, uint32_t port2);

#endif
