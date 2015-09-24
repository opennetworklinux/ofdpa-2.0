/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <ofdpa_l2play/ofdpa_l2play_config.h>

#if OFDPA_L2PLAY_CONFIG_INCLUDE_UCLI == 1

#include <uCli/ucli.h>
#include <uCli/ucli_argparse.h>
#include <uCli/ucli_handler_macros.h>

static ucli_status_t
ofdpa_l2play_ucli_ucli__config__(ucli_context_t* uc)
{
    UCLI_HANDLER_MACRO_MODULE_CONFIG(ofdpa_l2play)
}

/* <auto.ucli.handlers.start> */
/* <auto.ucli.handlers.end> */

static ucli_module_t
ofdpa_l2play_ucli_module__ =
    {
        "ofdpa_l2play_ucli",
        NULL,
        ofdpa_l2play_ucli_ucli_handlers__,
        NULL,
        NULL,
    };

ucli_node_t*
ofdpa_l2play_ucli_node_create(void)
{
    ucli_node_t* n;
    ucli_module_init(&ofdpa_l2play_ucli_module__);
    n = ucli_node_create("ofdpa_l2play", NULL, &ofdpa_l2play_ucli_module__);
    ucli_node_subnode_add(n, ucli_module_log_node_create("ofdpa_l2play"));
    return n;
}

#else
void*
ofdpa_l2play_ucli_node_create(void)
{
    return NULL;
}
#endif

