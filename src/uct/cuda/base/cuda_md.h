/**
 * Copyright (C) Mellanox Technologies Ltd. 2018.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifndef UCT_CUDA_MD_H
#define UCT_CUDA_MD_H

#include <uct/base/uct_md.h>
#include <nvml.h>


#define UCT_CUDA_BASE_IFACE_DEFAULT_BANDWIDTH (10000.0 * UCS_MBYTE)


ucs_status_t uct_cuda_base_detect_memory_type(uct_md_h md, const void *address,
                                              size_t length,
                                              ucs_memory_type_t *mem_type_p);

ucs_status_t uct_cuda_base_mem_query(uct_md_h md, const void *address,
                                     size_t length, uct_md_mem_attr_t *mem_attr);

double uct_cuda_base_get_bw(ucs_sys_device_t local_sys_device,
                            ucs_sys_device_t remote_sys_device);

ucs_status_t
uct_cuda_base_get_nvml_device_from_bus_id(int bus_id, nvmlDevice_t *device);

ucs_status_t
uct_cuda_base_query_md_resources(uct_component_t *component,
                                 uct_md_resource_desc_t **resources_p,
                                 unsigned *num_resources_p);

#endif
