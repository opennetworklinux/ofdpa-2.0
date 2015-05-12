/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <indigo_ofdpa_driver/indigo_ofdpa_driver_config.h>

#if INDIGO_OFDPA_DRIVER_CONFIG_INCLUDE_UCLI == 1

#include <uCli/ucli.h>
#include <uCli/ucli_argparse.h>
#include <uCli/ucli_handler_macros.h>

static ucli_status_t
indigo_ofdpa_driver_ucli_ucli__config__(ucli_context_t* uc)
{
    UCLI_HANDLER_MACRO_MODULE_CONFIG(indigo_ofdpa_driver)
}

/* <auto.ucli.handlers.start> */
/* <auto.ucli.handlers.end> */

static ucli_module_t
indigo_ofdpa_driver_ucli_module__ =
    {
        "indigo_ofdpa_driver_ucli",
        NULL,
        indigo_ofdpa_driver_ucli_ucli_handlers__,
        NULL,
        NULL,
    };

ucli_node_t*
indigo_ofdpa_driver_ucli_node_create(void)
{
    ucli_node_t* n;
    ucli_module_init(&indigo_ofdpa_driver_ucli_module__);
    n = ucli_node_create("indigo_ofdpa_driver", NULL, &indigo_ofdpa_driver_ucli_module__);
    ucli_node_subnode_add(n, ucli_module_log_node_create("indigo_ofdpa_driver"));
    return n;
}

#else
void*
indigo_ofdpa_driver_ucli_node_create(void)
{
    return NULL;
}
#endif

