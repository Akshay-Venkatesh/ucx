/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2018. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifndef UCT_CUDA_IPC_IFACE_H
#define UCT_CUDA_IPC_IFACE_H

#include <uct/base/uct_iface.h>
#include <uct/cuda/base/cuda_iface.h>
#include <ucs/datastruct/khash.h>
#include <ucs/arch/cpu.h>
#include <cuda.h>

#include "cuda_ipc_md.h"
#include "cuda_ipc_ep.h"
#include "cuda_ipc_cache.h"


KHASH_MAP_INIT_INT(cuda_ipc_queue_desc, uct_cuda_queue_desc_t*);


typedef struct uct_cuda_ipc_per_ctx_rsc {
    CUcontext                   cuda_ctx;
    unsigned long long          ctx_id;
    /* pool of cuda events to check completion of memcpy operations */
    ucs_mpool_t                 cuda_event_desc;
    /* array of queue descriptors for each src/dst memory type combination */
    khash_t(cuda_ipc_queue_desc) queue_desc_map;
} uct_cuda_ipc_per_ctx_rsc_t;


KHASH_MAP_INIT_INT64(cuda_ipc_ctx_rscs, struct uct_cuda_ipc_per_ctx_rsc*);


typedef struct uct_cuda_ipc_iface {
    uct_cuda_iface_t super;
    int              eventfd;              /* get event notifications */
    khash_t(cuda_ipc_ctx_rscs) ctx_rscs;
    ucs_queue_head_t           active_queue;
    struct {
        unsigned                max_poll;            /* query attempts w.o success */
        unsigned                max_cuda_ipc_events; /* max mpool entries */
        int                     enable_cache;        /* enable/disable ipc handle cache */
        ucs_on_off_auto_value_t enable_get_zcopy;    /* enable get_zcopy except for specific platorms */
        double                  bandwidth;
    } config;
} uct_cuda_ipc_iface_t;


typedef struct uct_cuda_ipc_iface_config {
    uct_iface_config_t      super;
    unsigned                max_poll;
    int                     enable_cache;
    ucs_on_off_auto_value_t enable_get_zcopy;
    unsigned                max_cuda_ipc_events;
    double                  bandwidth;
} uct_cuda_ipc_iface_config_t;


typedef struct uct_cuda_ipc_event_desc {
    CUevent           event;
    void              *mapped_addr;
    uct_completion_t  *comp;
    ucs_queue_elem_t  queue;
    uct_cuda_ipc_ep_t *ep;
    uintptr_t         d_bptr;
    pid_t             pid;
} uct_cuda_ipc_event_desc_t;


ucs_status_t uct_cuda_ipc_iface_init_streams(uct_cuda_ipc_iface_t *iface);
ucs_status_t uct_cuda_ipc_get_queue_desc(uct_cuda_ipc_per_ctx_rsc_t *ctx_rsc, int index,
                                         uct_cuda_queue_desc_t **q_desc_p);
ucs_status_t uct_cuda_ipc_get_ctx_rscs(uct_cuda_ipc_iface_t *iface,
                                       CUcontext cuda_ctx,
                                       uct_cuda_ipc_per_ctx_rsc_t **ctx_rsc_p);
#endif
