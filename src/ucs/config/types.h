/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2019. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef UCS_CONFIG_TYPES_H
#define UCS_CONFIG_TYPES_H


#include <ucs/sys/compiler_def.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>

#define UCS_FPATH_MAX_LEN 256

/**
 * Logging levels.
 */
typedef enum {
    UCS_LOG_LEVEL_FATAL,        /* Immediate termination */
    UCS_LOG_LEVEL_ERROR,        /* Error is returned to the user */
    UCS_LOG_LEVEL_WARN,         /* Something's wrong, but we continue */
    UCS_LOG_LEVEL_INFO,         /* Information */
    UCS_LOG_LEVEL_DEBUG,        /* Low-volume debugging */
    UCS_LOG_LEVEL_TRACE,        /* High-volume debugging */
    UCS_LOG_LEVEL_TRACE_REQ,    /* Every send/receive request */
    UCS_LOG_LEVEL_TRACE_DATA,   /* Data sent/received on the transport */
    UCS_LOG_LEVEL_TRACE_ASYNC,  /* Asynchronous progress engine */
    UCS_LOG_LEVEL_TRACE_FUNC,   /* Function calls */
    UCS_LOG_LEVEL_TRACE_POLL,   /* Polling functions */
    UCS_LOG_LEVEL_LAST,
    UCS_LOG_LEVEL_PRINT         /* Temporary output */
} ucs_log_level_t;


/**
 * Async progress mode.
 */
typedef enum {
    UCS_ASYNC_MODE_SIGNAL,
    UCS_ASYNC_MODE_THREAD,     /* Deprecated, keep for backward compatibility */
    UCS_ASYNC_MODE_THREAD_SPINLOCK = UCS_ASYNC_MODE_THREAD,
    UCS_ASYNC_MODE_THREAD_MUTEX,
    UCS_ASYNC_MODE_POLL,       /* TODO keep only in debug version */
    UCS_ASYNC_MODE_LAST
} ucs_async_mode_t;


extern const char *ucs_async_mode_names[];


/**
 * Ternary logic value.
 */
typedef enum ucs_ternary_value {
    UCS_NO  = 0,
    UCS_YES = 1,
    UCS_TRY = 2,
    UCS_TERNARY_LAST
} ucs_ternary_value_t;


/**
 * On/Off/Auto logic value.
 */
typedef enum ucs_on_off_auto_value {
    UCS_CONFIG_OFF  = 0,
    UCS_CONFIG_ON   = 1,
    UCS_CONFIG_AUTO = 2,
    UCS_CONFIG_ON_OFF_LAST
} ucs_on_off_auto_value_t;


/**
 * Error handling modes
 */
typedef enum {
    UCS_HANDLE_ERROR_BACKTRACE, /* Print backtrace */
    UCS_HANDLE_ERROR_FREEZE,    /* Freeze and wait for a debugger */
    UCS_HANDLE_ERROR_DEBUG,     /* Attach debugger */
    UCS_HANDLE_ERROR_LAST
} ucs_handle_error_t;


/**
 * Configuration printing flags
 */
typedef enum {
    UCS_CONFIG_PRINT_CONFIG        = UCS_BIT(0),
    UCS_CONFIG_PRINT_HEADER        = UCS_BIT(1),
    UCS_CONFIG_PRINT_DOC           = UCS_BIT(2),
    UCS_CONFIG_PRINT_HIDDEN        = UCS_BIT(3)
} ucs_config_print_flags_t;

/**
 * Memory Unit type
 */
typedef enum {
    UCS_MM_UNIT_CPU = 0, /* CPU Memory        */
    UCS_MM_UNIT_CUDA,    /* NVIDIA GPU Memory */
    UCS_MM_UNIT_LAST
} ucs_mm_unit_enum_t;


/**
 * System device type
 */
typedef enum {
    UCS_SYS_DEVICE_IB = 0, /* Infiniband Device */
    UCS_SYS_DEVICE_CUDA,   /* NVIDIA GPU Device */
    UCS_SYS_DEVICE_LAST
} ucs_sys_device_enum_t;


/**
 * PCIe distance categories and answers what needs to be crossed to reach
 */
typedef enum {
    UCS_SYS_DEV_DIST_PIX = 0, /* traverse 1 PCIe switch */
    UCS_SYS_DEV_DIST_PXB,     /* traverse >1 PCIe switches */
    UCS_SYS_DEV_DIST_PHB,     /* traverse host bridge */
    UCS_SYS_DEV_DIST_NODE,    /* traverse host bridge in the same numa node */
    UCS_SYS_DEV_DIST_SYS      /* traverse CPU interconnect (like QPI) */
} ucs_sys_dev_dist_enum_t;


/**
 * Structure type for array configuration. Should be used inside the configuration
 * structure declaration.
 */
#define UCS_CONFIG_ARRAY_FIELD(_type, _array_name) \
    struct { \
        _type    *_array_name; \
        unsigned count; \
        unsigned pad; \
    }


/* Specific structure for an array of strings */
#define UCS_CONFIG_STRING_ARRAY_FIELD(_array_name) \
    UCS_CONFIG_ARRAY_FIELD(char*, _array_name)


typedef UCS_CONFIG_STRING_ARRAY_FIELD(names) ucs_config_names_array_t;

/**
 * @ingroup UCS_RESOURCE
 * BSD socket address specification.
 */
typedef struct ucs_sock_addr {
    const struct sockaddr   *addr;      /**< Pointer to socket address */
    socklen_t                addrlen;   /**< Address length */
} ucs_sock_addr_t;

/**
 * @ingroup UCS_RESOURCE
 * Memory unit abstraction
 */
typedef struct ucs_mm_unit {
    ucs_mm_unit_enum_t mm_unit_type;             /**< Type of memory unit */
    unsigned int       id;                       /**< Index of the unit */
    unsigned int       bus_id;                   /**< bus ID of of the device if applicable*/
    unsigned int       numa_node;                /**< NUMA node assoicated with the device*/
    char               fpath[UCS_FPATH_MAX_LEN];
    char               rpath[UCS_FPATH_MAX_LEN];
} ucs_mm_unit_t;

/**
 * @ingroup UCS_RESOURCE
 * System Device abstraction
 */
typedef struct ucs_sys_device {
    ucs_sys_device_enum_t sys_dev_type;             /**< Type of system device*/
    unsigned int          id;                       /**< Index of the unit */
    unsigned int          bus_id;                   /**< bus ID of of the device*/
    unsigned int          numa_node;                /**< NUMA node assoicated with the device*/
    char                  fpath[UCS_FPATH_MAX_LEN];
    char                  rpath[UCS_FPATH_MAX_LEN];
} ucs_sys_device_t;

#endif /* TYPES_H_ */
