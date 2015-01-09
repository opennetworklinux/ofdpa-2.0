#include <indigo/forwarding.h>
#include <AIM/aim_memory.h>

void
indigo_fwd_pipeline_get(of_desc_str_t pipeline)
{
    strcpy(pipeline, "default");
}

indigo_error_t
indigo_fwd_pipeline_set(of_desc_str_t pipeline)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

void
indigo_fwd_pipeline_stats_get(of_desc_str_t **pipelines, int *num_pipelines)
{
    of_desc_str_t name = "default";
    *pipelines = aim_memdup(name, sizeof(name));
    *num_pipelines = 1;
}
