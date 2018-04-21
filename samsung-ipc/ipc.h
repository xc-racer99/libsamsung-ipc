/*
 * This file is part of libsamsung-ipc.
 *
 * Copyright (C) 2011 Simon Busch <morphis@gravedo.de>
 * Copyright (C) 2014 Paul Kocialkowski <contact@paulk.fr>
 *
 * libsamsung-ipc is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * libsamsung-ipc is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libsamsung-ipc.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <time.h>

#include <samsung-ipc.h>

#ifndef __IPC_H__
#define __IPC_H__

/*
 * Structures
 */

struct ipc_client_ops {
    int (*boot)(struct ipc_client *client);
    int (*send)(struct ipc_client *client, struct ipc_message *message);
    int (*recv)(struct ipc_client *client, struct ipc_message *message);
};

struct ipc_client_handlers {
    /* Transport handlers */
    int (*open)(void *transport_data, int type);
    int (*close)(void *transport_data);

    int (*read)(void *transport_data, void *buffer, size_t length);
    int (*write)(void *transport_data, const void *buffer, size_t length);
    int (*poll)(void *transport_data, struct ipc_poll_fds *fds, struct timeval *timeout);

    void *transport_data;

    /* Power handlers */
    int (*power_on)(void *power_data);
    int (*power_off)(void *power_data);

    void *power_data;

    /* GPRS handlers */
    int (*gprs_activate)(void *gprs_data, unsigned int cid);
    int (*gprs_deactivate)(void *gprs_data, unsigned int cid);

    void *gprs_data;

    /* Data */
    int (*data_create)(void **transport_data, void **power_data, void **gprs_data);
    int (*data_destroy)(void *transport_data, void *power_data, void *gprs_data);
};

struct ipc_client_gprs_specs {
    char *(*gprs_get_iface)(unsigned int cid);
    int (*gprs_get_capabilities)(struct ipc_client_gprs_capabilities *capabilities);
};

struct ipc_client_nv_data_specs {
    char *efs_root;
    char *nv_data_path;
    char *nv_data_md5_path;
    char *nv_data_backup_path;
    char *nv_data_backup_md5_path;
    char *nv_data_secret;
    size_t nv_data_size;
    size_t nv_data_chunk_size;
};

struct ipc_client {
    int type;

    void (*log_callback)(void *log_data, const char *message);
    void *log_data;

    struct ipc_client_ops *ops;
    struct ipc_client_handlers *handlers;
    struct ipc_client_gprs_specs *gprs_specs;
    struct ipc_client_nv_data_specs *nv_data_specs;
};

/*
 * Helpers
 */

void ipc_client_log(struct ipc_client *client, const char *message, ...);

#endif

// vim:ts=4:sw=4:expandtab
