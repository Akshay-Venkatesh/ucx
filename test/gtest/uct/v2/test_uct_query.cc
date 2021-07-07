/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

extern "C" {
#include <uct/api/uct.h>
#include <ucs/sys/topo.h>
#include <uct/api/v2/uct_v2.h>
}

#include <gtest/uct/uct_p2p_test.h>
#include <gtest/common/mem_buffer.h>

class test_uct_query : public uct_p2p_test {
public:
    test_uct_query() : uct_p2p_test(0)
    {
    }
};

UCS_TEST_P(test_uct_query, query_perf)
{
    size_t buffer_size = 4096;
    void *buffer;
    uct_md_mem_attr_t mem_attr;
    uct_perf_attr_t perf_attr;
    ucs_status_t status;

    perf_attr.field_mask         = UCT_PERF_ATTR_FIELD_OPERATION |
                                   UCT_PERF_ATTR_FIELD_LOCAL_MEMORY_TYPE |
                                   UCT_PERF_ATTR_FIELD_REMOTE_MEMORY_TYPE |
                                   UCT_PERF_ATTR_FIELD_LOCAL_SYS_DEVICE |
                                   UCT_PERF_ATTR_FIELD_REMOTE_SYS_DEIVCE |
                                   UCT_PERF_ATTR_FIELD_OVERHEAD |
                                   UCT_PERF_ATTR_FIELD_BANDWIDTH;
    perf_attr.operation          = UCT_OP_AM_SHORT;
    perf_attr.local_memory_type  = UCS_MEMORY_TYPE_HOST;
    perf_attr.remote_memory_type = UCS_MEMORY_TYPE_HOST;
    perf_attr.local_sys_device   = UCS_SYS_DEVICE_ID_UNKNOWN;
    perf_attr.remote_sys_device  = UCS_SYS_DEVICE_ID_UNKNOWN;
    status                       = uct_iface_estimate_perf(sender().iface(),
                                                           &perf_attr);
    EXPECT_EQ(status, UCS_OK);

    perf_attr.remote_memory_type = UCS_MEMORY_TYPE_CUDA;
    perf_attr.operation          = UCT_OP_PUT_SHORT;
    status                       = uct_iface_estimate_perf(sender().iface(),
                                                           &perf_attr);

    /* At least one type of bandwidth must be non-zero */
    EXPECT_NE(0, perf_attr.bandwidth.shared + perf_attr.bandwidth.dedicated);

    if (has_transport("cuda_copy") ||
        has_transport("gdr_copy")  ||
        has_transport("rocm_copy")) {
        uct_perf_attr_t perf_attr_get;
        perf_attr_get.field_mask = UCT_PERF_ATTR_FIELD_OPERATION |
                                   UCT_PERF_ATTR_FIELD_BANDWIDTH;
        perf_attr_get.operation  = UCT_OP_GET_SHORT;
        status = uct_iface_estimate_perf(sender().iface(), &perf_attr_get);
        EXPECT_EQ(status, UCS_OK);

        /* Put and get operations have different bandwidth in cuda_copy
           and gdr_copy transports */
        EXPECT_NE(perf_attr.bandwidth.shared, perf_attr_get.bandwidth.shared);

        if (sender().md_attr().cap.detect_mem_types & UCS_BIT(UCS_MEMORY_TYPE_CUDA)) {

            perf_attr_get.field_mask = UCT_PERF_ATTR_FIELD_OPERATION |
                                       UCT_PERF_ATTR_FIELD_LOCAL_MEMORY_TYPE |
                                       UCT_PERF_ATTR_FIELD_REMOTE_MEMORY_TYPE |
                                       UCT_PERF_ATTR_FIELD_LOCAL_SYS_DEVICE |
                                       UCT_PERF_ATTR_FIELD_REMOTE_SYS_DEIVCE |
                                       UCT_PERF_ATTR_FIELD_OVERHEAD |
                                       UCT_PERF_ATTR_FIELD_BANDWIDTH;

            buffer = mem_buffer::allocate(buffer_size, UCS_MEMORY_TYPE_CUDA);

            mem_attr.field_mask = UCT_MD_MEM_ATTR_FIELD_SYS_DEV;
            status = uct_md_mem_query(sender().md(), buffer, buffer_size, &mem_attr);
            EXPECT_EQ(status, UCS_OK);

            mem_buffer::release(buffer, UCS_MEMORY_TYPE_CUDA);

            perf_attr_get.local_memory_type  = UCS_MEMORY_TYPE_CUDA;
            perf_attr_get.remote_memory_type = UCS_MEMORY_TYPE_HOST;
            perf_attr_get.local_sys_device   = mem_attr.sys_dev;
            perf_attr_get.remote_sys_device  = UCS_SYS_DEVICE_ID_UNKNOWN;

            status = uct_iface_estimate_perf(sender().iface(), &perf_attr_get);
            EXPECT_EQ(status, UCS_OK);

            perf_attr_get.local_memory_type  = UCS_MEMORY_TYPE_HOST;
            perf_attr_get.remote_memory_type = UCS_MEMORY_TYPE_CUDA;
            perf_attr_get.local_sys_device   = UCS_SYS_DEVICE_ID_UNKNOWN;
            perf_attr_get.remote_sys_device  = mem_attr.sys_dev;

            status = uct_iface_estimate_perf(sender().iface(), &perf_attr_get);
            EXPECT_EQ(status, UCS_OK);

            perf_attr_get.local_memory_type  = UCS_MEMORY_TYPE_CUDA;
            perf_attr_get.remote_memory_type = UCS_MEMORY_TYPE_CUDA;
            perf_attr_get.local_sys_device   = mem_attr.sys_dev;
            perf_attr_get.remote_sys_device  = mem_attr.sys_dev;

            status = uct_iface_estimate_perf(sender().iface(), &perf_attr_get);
            EXPECT_EQ(status, UCS_OK);
        }
    }
}

UCT_INSTANTIATE_TEST_CASE(test_uct_query)
