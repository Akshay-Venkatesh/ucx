/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2016.  ALL RIGHTS RESERVED.
* Copyright (C) Advanced Micro Devices, Inc. 2018. ALL RIGHTS RESERVED.
* Copyright (C) NVIDIA Corporation. 2020. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef HAVE_CONFIG_H
#  define HAVE_CONFIG_H /* Force using config.h, so test would fail if header
                           actually tries to use it */
#endif

/*
 * UCP hello world client / server example utility
 * -----------------------------------------------
 *
 * Server side:
 *
 *    ./ucp_hello_world
 *
 * Client side:
 *
 *    ./ucp_hello_world -n <server host name>
 *
 * Notes:
 *
 *    - Client acquires Server UCX address via TCP socket
 *
 *
 * Author:
 *
 *    Ilya Nelkenbaum <ilya@nelkenbaum.com>
 *    Sergey Shalnov <sergeysh@mellanox.com> 7-June-2016
 */

#include "ucx_hello_world.h"

#include <ucp/api/ucp.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <assert.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  /* getopt */
#include <ctype.h>   /* isprint */
#include <pthread.h> /* pthread_self */
#include <errno.h>   /* errno */
#include <time.h>
#include <signal.h>  /* raise */

#define ADDR_MAX_BUF_SIZE 1024
#define RKEY_MAX_BUF_SIZE 1024

struct msg {
    uint64_t        data_len;
};

struct ucx_context {
    int             completed;
};

enum ucp_test_mode_t {
    TEST_MODE_PROBE,
    TEST_MODE_WAIT,
    TEST_MODE_EVENTFD
} ucp_test_mode = TEST_MODE_PROBE;

static struct err_handling {
    ucp_err_handling_mode_t ucp_err_mode;
    int                     failure;
} err_handling_opt;

typedef struct {
    char     addr[ADDR_MAX_BUF_SIZE];
    size_t   addr_len;
    char     rkey_buffer[RKEY_MAX_BUF_SIZE];
    size_t   rkey_size;
    uint64_t ptr;
} exchange_key_t;

static uint16_t server_port = 13337;
static long test_string_length = 16;
static const ucp_tag_t tag  = 0x1337a880u;
static const ucp_tag_t tag_mask = UINT64_MAX;
static ucp_address_t *local_addr;
static ucp_address_t *peer_addr;

exchange_key_t *exchange_info = NULL;
exchange_key_t *peer_exchange_info = NULL;
char *window = NULL;

static size_t local_addr_len;
static size_t peer_addr_len;

static ucs_status_t parse_cmd(int argc, char * const argv[], char **server_name);

static void request_init(void *request)
{
    struct ucx_context *ctx = (struct ucx_context *) request;
    ctx->completed = 0;
}

static void send_handler(void *request, ucs_status_t status)
{
    struct ucx_context *context = (struct ucx_context *) request;

    context->completed = 1;

    printf("[0x%x] send handler called with status %d (%s)\n",
           (unsigned int)pthread_self(), status, ucs_status_string(status));
}

static void recv_handler(void *request, ucs_status_t status,
                        ucp_tag_recv_info_t *info)
{
    struct ucx_context *context = (struct ucx_context *) request;

    context->completed = 1;

    printf("[0x%x] receive handler called with status %d (%s), length %lu\n",
           (unsigned int)pthread_self(), status, ucs_status_string(status),
           info->length);
}

static void wait(ucp_worker_h ucp_worker, struct ucx_context *context)
{
    while (context->completed == 0) {
        ucp_worker_progress(ucp_worker);
    }
}

static int run_ucx_client(ucp_worker_h ucp_worker)
{
    ucs_status_t status;
    ucp_ep_h server_ep;
    ucp_ep_params_t ep_params;
    struct ucx_context *request = 0;
    struct msg *msg = 0;
    size_t msg_len = 0;
    int ret = -1;
    char *temp_window = NULL;
    ucp_rkey_h rkey;

    /* Send client UCX address to server */
    ep_params.field_mask      = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS |
                                UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE;
    ep_params.address         = peer_addr;
    ep_params.err_mode        = err_handling_opt.ucp_err_mode;

    status = ucp_ep_create(ucp_worker, &ep_params, &server_ep);
    CHKERR_JUMP(status != UCS_OK, "ucp_ep_create\n", err);

    status = ucp_ep_rkey_unpack(server_ep, peer_exchange_info->rkey_buffer,
                                &rkey);
    CHKERR_JUMP(status != UCS_OK, "ucp_ep_rkey_unpack\n", err);

    request = ucp_get_nb(server_ep, window, test_string_length, peer_exchange_info->ptr,
                        rkey, send_handler);
    if (UCS_PTR_IS_ERR(request)) {
        fprintf(stderr, "unable to perform get_nb\n");
        goto err_ep;
    } else if (UCS_PTR_IS_PTR(request)) {
        wait(ucp_worker, request);
        request->completed = 0; /* Reset request state before recycling it */
        ucp_request_release(request);
    }

    request = ucp_worker_flush_nb(ucp_worker, 0, send_handler);
    if (UCS_PTR_IS_ERR(request)) {
        fprintf(stderr, "unable to perform flush_nb\n");
        goto err_ep;
    } else if (UCS_PTR_IS_PTR(request)) {
        wait(ucp_worker, request);
        request->completed = 0; /* Reset request state before recycling it */
        ucp_request_release(request);
    }

    temp_window = mem_type_malloc(test_string_length);
    CHKERR_JUMP(temp_window == NULL, "allocate memory\n", err_ep);

    mem_type_memset(temp_window, 'd', test_string_length);

    request = ucp_put_nb(server_ep, temp_window, test_string_length, peer_exchange_info->ptr,
                        rkey, send_handler);
    if (UCS_PTR_IS_ERR(request)) {
        fprintf(stderr, "unable to perform put_nb\n");
        goto err_ep;
    } else if (UCS_PTR_IS_PTR(request)) {
        wait(ucp_worker, request);
        request->completed = 0; /* Reset request state before recycling it */
        ucp_request_release(request);
    }

    request = ucp_worker_flush_nb(ucp_worker, 0, send_handler);
    if (UCS_PTR_IS_ERR(request)) {
        fprintf(stderr, "unable to perform flush_nb\n");
        goto err_ep;
    } else if (UCS_PTR_IS_PTR(request)) {
        wait(ucp_worker, request);
        request->completed = 0; /* Reset request state before recycling it */
        ucp_request_release(request);
    }

    ucp_rkey_destroy(rkey);

    /* send token message because server calling progress seems necessary */
    msg_len = 1;
    msg     = malloc(msg_len);
    CHKERR_JUMP(msg == NULL, "allocate memory\n", err_ep);
    memset(msg, 0, msg_len);

    request = ucp_tag_send_nb(server_ep, msg, msg_len,
                              ucp_dt_make_contig(1), tag,
                              send_handler);
    if (UCS_PTR_IS_ERR(request)) {
        fprintf(stderr, "unable to send UCX address message\n");
        free(msg);
        goto err_ep;
    } else if (UCS_PTR_IS_PTR(request)) {
        wait(ucp_worker, request);
        request->completed = 0; /* Reset request state before recycling it */
        ucp_request_release(request);
    }

    free(msg);

    ret = 0;

err_ep:
    ucp_ep_destroy(server_ep);

err:
    return ret;
}

static int run_ucx_server(ucp_worker_h ucp_worker)
{
    ucp_tag_recv_info_t info_tag;
    ucp_tag_message_h msg_tag;
    struct msg *msg = 0;
    struct ucx_context *request = 0;
    int ret;

    /* recv token message */
    do {
        /* Progressing before probe to update the state */
        ucp_worker_progress(ucp_worker);

        /* Probing incoming events in non-block mode */
        msg_tag = ucp_tag_probe_nb(ucp_worker, tag, tag_mask, 1, &info_tag);
    } while (msg_tag == NULL);

    msg = malloc(info_tag.length);
    CHKERR_ACTION(msg == NULL, "allocate memory\n", ret = -1; goto err);
    request = ucp_tag_msg_recv_nb(ucp_worker, msg, info_tag.length,
                                  ucp_dt_make_contig(1), msg_tag, recv_handler);

    if (UCS_PTR_IS_ERR(request)) {
        fprintf(stderr, "unable to receive UCX address message (%s)\n",
                ucs_status_string(UCS_PTR_STATUS(request)));
        free(msg);
        ret = -1;
        goto err;
    } else {
        /* ucp_tag_msg_recv_nb() cannot return NULL */
        assert(UCS_PTR_IS_PTR(request));
        wait(ucp_worker, request);
        request->completed = 0;
        ucp_request_release(request);
        printf("UCX address message was received\n");
    }

    ret = 0;
err:
    return ret;
}
static int run_test(const char *client_target_name, ucp_worker_h ucp_worker)
{
    if (client_target_name != NULL) {
        return run_ucx_client(ucp_worker);
    } else {
        return run_ucx_server(ucp_worker);
    }
}

int main(int argc, char **argv)
{
    /* UCP temporary vars */
    ucp_params_t ucp_params;
    ucp_worker_params_t worker_params;
    ucp_config_t *config;
    ucs_status_t status;

    /* UCP handler objects */
    ucp_context_h ucp_context;
    ucp_worker_h ucp_worker;

    /* OOB connection vars */
    char *client_target_name = NULL;
    int oob_sock = -1;
    int ret = -1;

    /* 1-sided vars */
    ucp_mem_h memh;
    ucp_mem_map_params_t params;
    char *rkey_buffer;
    size_t rkey_size;
    char *str;

    memset(&ucp_params, 0, sizeof(ucp_params));
    memset(&worker_params, 0, sizeof(worker_params));

    /* Parse the command line */
    status = parse_cmd(argc, argv, &client_target_name);
    CHKERR_JUMP(status != UCS_OK, "parse_cmd\n", err);

    /* UCP initialization */
    status = ucp_config_read(NULL, NULL, &config);
    CHKERR_JUMP(status != UCS_OK, "ucp_config_read\n", err);

    ucp_params.field_mask   = UCP_PARAM_FIELD_FEATURES |
                              UCP_PARAM_FIELD_REQUEST_SIZE |
                              UCP_PARAM_FIELD_REQUEST_INIT;
    ucp_params.features     = UCP_FEATURE_TAG | UCP_FEATURE_RMA;
    if (ucp_test_mode == TEST_MODE_WAIT || ucp_test_mode == TEST_MODE_EVENTFD) {
        ucp_params.features |= UCP_FEATURE_WAKEUP;
    }
    ucp_params.request_size    = sizeof(struct ucx_context);
    ucp_params.request_init    = request_init;

    status = ucp_init(&ucp_params, config, &ucp_context);

    ucp_config_print(config, stdout, NULL, UCS_CONFIG_PRINT_CONFIG);

    ucp_config_release(config);
    CHKERR_JUMP(status != UCS_OK, "ucp_init\n", err);

    worker_params.field_mask  = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;

    status = ucp_worker_create(ucp_context, &worker_params, &ucp_worker);
    CHKERR_JUMP(status != UCS_OK, "ucp_worker_create\n", err_cleanup);

    status = ucp_worker_get_address(ucp_worker, &local_addr, &local_addr_len);
    CHKERR_JUMP(status != UCS_OK, "ucp_worker_get_address\n", err_worker);

    printf("[0x%x] local address length: %lu\n",
           (unsigned int)pthread_self(), local_addr_len);

    /* create remotely accessible memory region and rkey */

    window = mem_type_malloc(test_string_length * sizeof(char));

    params.field_mask = UCP_MEM_MAP_PARAM_FIELD_ADDRESS |
                        UCP_MEM_MAP_PARAM_FIELD_LENGTH;
    params.address    = window;
    params.length     = test_string_length;
    params.flags      = 0;

    status = ucp_mem_map(ucp_context, &params, &memh);
    CHKERR_JUMP(status != UCS_OK, "ucp_mem_map\n", err_worker);

    status = ucp_rkey_pack(ucp_context, memh, (void **) &rkey_buffer, &rkey_size);
    CHKERR_JUMP(status != UCS_OK, "ucp_rkey_pack\n", err_worker);
    CHKERR_JUMP(rkey_size > RKEY_MAX_BUF_SIZE, "rkey too big\n", err_worker);

    exchange_info = malloc(sizeof(exchange_key_t));
    CHKERR_JUMP(exchange_info == NULL, "malloc\n", err_worker);

    peer_exchange_info = malloc(sizeof(exchange_key_t));
    CHKERR_JUMP(peer_exchange_info == NULL, "malloc\n", err_worker);

    memset(exchange_info, 0, sizeof(exchange_key_t));
    memset(peer_exchange_info, 0, sizeof(exchange_key_t));

    exchange_info->addr_len  = local_addr_len;
    exchange_info->rkey_size = rkey_size;
    exchange_info->ptr       = (uint64_t) window;
    memcpy(exchange_info->addr, local_addr, local_addr_len);
    memcpy(exchange_info->rkey_buffer, rkey_buffer, rkey_size);

    printf("local: addr_len = %ld, rkey_size = %ld, ptr = %ld\n", 
            exchange_info->addr_len, exchange_info->rkey_size, 
            (long) exchange_info->ptr);

    /* OOB connection establishment */
    if (client_target_name) {
        str = calloc(1, test_string_length);
        if (str != NULL) {
            generate_test_string(str, test_string_length);
            printf("client_window initially: \n");
            printf("%s\n", str);
        } else {
            fprintf(stderr, "Memory allocation failed\n");
        }

        mem_type_memcpy(window, str, test_string_length);
        free(str);

        peer_addr_len = local_addr_len;

        oob_sock = client_connect(client_target_name, server_port);
        CHKERR_JUMP(oob_sock < 0, "client_connect\n", err_addr);

        ret = recv(oob_sock, peer_exchange_info, sizeof(exchange_key_t), MSG_WAITALL);
        CHKERR_JUMP_RETVAL(ret != (int)sizeof(exchange_key_t),
                           "receive exchange\n", err_peer_addr, ret);

        ret = send(oob_sock, exchange_info, sizeof(exchange_key_t), 0);
        CHKERR_JUMP_RETVAL(ret != (int)sizeof(exchange_key_t), "send exchange\n",
                           err_peer_addr, ret);

        peer_addr_len = peer_exchange_info->addr_len;
        peer_addr = malloc(peer_addr_len);
        CHKERR_JUMP(!peer_addr, "allocate memory\n", err_addr);

        memcpy(peer_addr, peer_exchange_info->addr, peer_addr_len);

    } else {
        mem_type_memset(window, 's', test_string_length);
        oob_sock = server_connect(server_port);
        CHKERR_JUMP(oob_sock < 0, "server_connect\n", err_peer_addr);

        ret = send(oob_sock, exchange_info, sizeof(exchange_key_t), 0);
        CHKERR_JUMP_RETVAL(ret != (int)sizeof(exchange_key_t), "send exchange\n",
                           err_peer_addr, ret);

        ret = recv(oob_sock, peer_exchange_info, sizeof(exchange_key_t), MSG_WAITALL);
        CHKERR_JUMP_RETVAL(ret != (int)sizeof(exchange_key_t),
                           "receive exchange\n", err_peer_addr, ret);
    }

    printf("peer: addr_len = %ld, rkey_size = %ld, ptr = %ld\n", 
            peer_exchange_info->addr_len, peer_exchange_info->rkey_size, 
            (long) peer_exchange_info->ptr);

    ret = run_test(client_target_name, ucp_worker);

    if (!ret && !err_handling_opt.failure) {
        /* Make sure remote is disconnected before destroying local worker */
        ret = barrier(oob_sock);
    }
    close(oob_sock);

    str = calloc(1, test_string_length);
    if (str != NULL) {
        mem_type_memcpy(str, window, test_string_length);
        printf("\n\n----- UCP TEST SUCCESS ----\n\n");
        printf("%s", str);
        printf("\n\n---------------------------\n\n");
        free(str);
    } else {
        fprintf(stderr, "Memory allocation failed\n");
    }

err_peer_addr:
    free(peer_addr);

err_addr:
    free(exchange_info);
    free(peer_exchange_info);
    ucp_rkey_buffer_release(rkey_buffer);
    ucp_mem_unmap(ucp_context, memh);
    mem_type_free(window);
    ucp_worker_release_address(ucp_worker, local_addr);

err_worker:
    ucp_worker_destroy(ucp_worker);

err_cleanup:
    ucp_cleanup(ucp_context);

err:
    return ret;
}

ucs_status_t parse_cmd(int argc, char * const argv[], char **server_name)
{
    int c = 0, index = 0;
    opterr = 0;

    err_handling_opt.ucp_err_mode   = UCP_ERR_HANDLING_MODE_NONE;
    err_handling_opt.failure        = 0;

    while ((c = getopt(argc, argv, "wfben:p:s:m:h")) != -1) {
        switch (c) {
        case 'w':
            ucp_test_mode = TEST_MODE_WAIT;
            break;
        case 'f':
            ucp_test_mode = TEST_MODE_EVENTFD;
            break;
        case 'b':
            ucp_test_mode = TEST_MODE_PROBE;
            break;
        case 'e':
            err_handling_opt.ucp_err_mode   = UCP_ERR_HANDLING_MODE_PEER;
            err_handling_opt.failure        = 1;
            break;
        case 'n':
            *server_name = optarg;
            break;
        case 'p':
            server_port = atoi(optarg);
            if (server_port <= 0) {
                fprintf(stderr, "Wrong server port number %d\n", server_port);
                return UCS_ERR_UNSUPPORTED;
            }
            break;
        case 's':
            test_string_length = atol(optarg);
            if (test_string_length <= 0) {
                fprintf(stderr, "Wrong string size %ld\n", test_string_length);
                return UCS_ERR_UNSUPPORTED;
            }	
            break;
        case 'm':
            test_mem_type = parse_mem_type(optarg);
            if (test_mem_type == UCS_MEMORY_TYPE_LAST) {
                return UCS_ERR_UNSUPPORTED;
            }
            break;
        case '?':
            if (optopt == 's') {
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            } else if (isprint (optopt)) {
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            } else {
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            }
            /* Fall through */
        case 'h':
        default:
            fprintf(stderr, "Usage: ucp_hello_world [parameters]\n");
            fprintf(stderr, "UCP hello world client/server example utility\n");
            fprintf(stderr, "\nParameters are:\n");
            fprintf(stderr, "  -w      Select test mode \"wait\" to test "
                    "ucp_worker_wait function\n");
            fprintf(stderr, "  -f      Select test mode \"event fd\" to test "
                    "ucp_worker_get_efd function with later poll\n");
            fprintf(stderr, "  -b      Select test mode \"busy polling\" to test "
                    "ucp_tag_probe_nb and ucp_worker_progress (default)\n");
            fprintf(stderr, "  -e      Emulate unexpected failure on server side"
                    "and handle an error on client side with enabled "
                    "UCP_ERR_HANDLING_MODE_PEER\n");
            print_common_help();
            fprintf(stderr, "\n");
            return UCS_ERR_UNSUPPORTED;
        }
    }
    fprintf(stderr, "INFO: UCP_HELLO_WORLD mode = %d server = %s port = %d\n",
            ucp_test_mode, *server_name, server_port);

    for (index = optind; index < argc; index++) {
        fprintf(stderr, "WARNING: Non-option argument %s\n", argv[index]);
    }
    return UCS_OK;
}
