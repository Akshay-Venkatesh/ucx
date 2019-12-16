/**
 * Copyright (C) Mellanox Technologies Ltd. 2019.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */


#ifndef UCS_MEMORY_TYPE_H_
#define UCS_MEMORY_TYPE_H_

#include <ucs/sys/compiler_def.h>

BEGIN_C_DECLS


/* Memory types accessible from CPU  */
#define UCS_MEMORY_TYPES_CPU_ACCESSIBLE \
    (UCS_BIT(UCS_MEMORY_TYPE_HOST) | \
     UCS_BIT(UCS_MEMORY_TYPE_CUDA_MANAGED) | \
     UCS_BIT(UCS_MEMORY_TYPE_ROCM_MANAGED))


/*
 * Memory types
 */
typedef enum ucs_memory_type {
    UCS_MEMORY_TYPE_HOST,          /**< Default system memory */
    UCS_MEMORY_TYPE_CUDA,          /**< NVIDIA CUDA memory */
    UCS_MEMORY_TYPE_CUDA_MANAGED,  /**< NVIDIA CUDA managed (or unified) memory*/
    UCS_MEMORY_TYPE_ROCM,          /**< AMD ROCM memory */
    UCS_MEMORY_TYPE_ROCM_MANAGED,  /**< AMD ROCM managed system memory */
    UCS_MEMORY_TYPE_LAST
} ucs_memory_type_t;

/*
 * Device location details
 */
typedef struct ucs_device_id {
    int bus_id;    /**< If pcie device, then bus_id associated with it */
    int is_numa;   /**< If CPU NUMA node or not */
    int numa_node; /**< If not CPU NUMA node,
                     then NUMA node associated with pcie device
                     else numa_node and bus_id is the same (for NUMA node)*/
} ucs_device_id_t;

/**
 * Array of string names for each memory type
 */
extern const char *ucs_memory_type_names[];


END_C_DECLS

#endif
