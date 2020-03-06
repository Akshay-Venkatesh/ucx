/**
* Copyright (C) NVIDIA Corporation. 2019.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include <ucs/sys/topo.h>
#include <ucs/type/status.h>
#include <stdio.h>

#include <ucs/sys/checker.h>
#include <ucs/sys/sys.h>
#include <ucs/sys/topo.h>
#include <ucs/debug/log.h>
#include <ucs/time/time.h>
#include <ucm/util/sys.h>

#include <sys/types.h>
#include <net/if.h>
#include <dirent.h>

#include <numaif.h>
#include <math.h>

static int ucs_get_bus_id(char *name)
{
    char delim[] = ":";
    char *rval   = NULL;
    char *str    = NULL;
    char *str_p  = NULL;
    int count    = 0;
    int bus_id   = 0;
    size_t idx;
    int value;
    int pow_factor;
    size_t len;

    if (NULL == strchr(name, (int) ':')) {
        /* if no colon in path name then no valid bus id */
        return -1;
    }


    str = ucs_malloc(sizeof(char) * strlen(name), "ucs_get_bus_id str");
    if (NULL == str) {
        return -1;
    }
    str_p = str;
    strcpy(str, name);

    do {
        rval = strtok(str, delim);
        str = NULL;
        count++;
    } while ((count < 2) && (rval != NULL)); /* for 0000:0c:00.0 bus id = 0c */

    if (rval == NULL) {
        ucs_error("unable to find bus_id from path; setting bus_id = -1");
        ucs_free(str_p);
        return -1;
    }

    len = strlen(rval);
    for (idx = 0; idx < len; idx++) {
        pow_factor = pow(16, len - 1 - idx);
        value = (rval[idx] >= 'a') ? ((rval[idx] - 'a') + 10) : (rval[idx] - '0');
        value *= pow_factor;
        bus_id += value;
    }

    ucs_warn("dev name = %s bus_id = %d", name, bus_id);
    ucs_free(str_p);

    return bus_id;
}

ucs_status_t ucs_topo_get_sys_device(char *dev_loc, char *match,
                                     unsigned *num_devices,
                                     ucs_sys_device_t **sys_devices)
{
    char *dest, *src;
    struct dirent **namelist;
    int n, i;
    char *fpaths;
    ucs_sys_device_t *sys_dev_p;
    ucs_status_t status = UCS_OK;

    *num_devices = 0;

    n = scandir(dev_loc, &namelist, NULL, alphasort);
    if (n < 0) {
        perror("scandir");
    }
    else {
        fpaths = ucs_malloc(sizeof(char) * PATH_MAX * n, "mm_fpaths allocation");
        if (NULL == fpaths) {
            ucs_error("Failed to allocate memory for mm_fpaths");
            return UCS_ERR_NO_MEMORY;
        }

        for (i = 0; i < n; i++) {
            if (!strncmp(namelist[i]->d_name, match, strlen(match))) {
                ucs_assert(strlen(namelist[i]->d_name) <= PATH_MAX);
                dest = (char *) fpaths + (*num_devices * (sizeof(char) * PATH_MAX));
                strcpy(dest, namelist[i]->d_name);
                *num_devices = *num_devices + 1;
            }
            free(namelist[i]);
        }
        free(namelist);
    }

    if (0 == *num_devices) {
        status = UCS_OK;
        goto out;
    }

    *sys_devices = ucs_malloc(*num_devices * sizeof(ucs_sys_device_t), "ucs_sys_device_t array");
    if (*sys_devices == NULL) {
        ucs_error("failed to allocate sys_devices");
        status = UCS_ERR_NO_MEMORY;
        goto out;
    }

    sys_dev_p   = *sys_devices;

    for (i = 0; i < *num_devices; i++) {
        src = (char *) fpaths + (i * PATH_MAX);
        sys_dev_p->bus_id.bus = ucs_get_bus_id(src);
        sys_dev_p             = sys_dev_p + 1;
    }

out:

    ucs_free(fpaths);

    return status;
}

ucs_status_t ucs_topo_put_sys_device(ucs_sys_device_t *sys_devices)
{
    ucs_free(sys_devices);
    return UCS_OK;
}

ucs_status_t ucs_topo_find_device_by_bus_id(const ucs_sys_bus_id_t *bus_id,
                                            const ucs_sys_device_t **sys_dev)
{
    return UCS_OK;
}


ucs_status_t ucs_topo_get_distance(const ucs_sys_device_t *device1,
                                   const ucs_sys_device_t *device2,
                                   ucs_sys_dev_distance_t *distance)
{
    return UCS_OK;
}


void ucs_topo_print_info(FILE *stream)
{
}
