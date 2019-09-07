/*
 * This file is part of libsamsung-ipc.
 *
 * Copyright (C) 2010-2011 Joerie de Gram <j.de.gram@gmail.com>
 * Copyright (C) 2012 Simon Busch <morphis@gravedo.de>
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
 */

#include <time.h>

#ifndef __SAMSUNG_IPC_H__
#define __SAMSUNG_IPC_H__

/*
 * Values
 */

#define IPC_CLIENT_TYPE_FMT                                     0x00
#define IPC_CLIENT_TYPE_RFS                                     0x01

/*
 * Structures
 */

struct ipc_client;
struct ipc_handlers;

struct ipc_fmt_header;
struct ipc_rfs_header;

struct ipc_message {
    unsigned char mseq;
    unsigned char aseq;
    unsigned short command;
    unsigned char type;
    void *data;
    size_t size;
};

struct ipc_client_gprs_capabilities {
    unsigned int cid_count;
};

struct ipc_poll_fds {
    int *fds;
    unsigned int count;
};

/*
 * Helpers
 */

int ipc_device_detect(void);

struct ipc_client *ipc_client_create(int type);
int ipc_client_destroy(struct ipc_client *client);

int ipc_client_transport_handlers_register(struct ipc_client *client,
    int (*open)(void *transport_data, int type),
    int (*close)(void *transport_data),
    int (*read)(void *transport_data, void *data, size_t size),
    int (*write)(void *transport_data, const void *data, size_t size),
    int (*poll)(void *transport_data, struct ipc_poll_fds *fds, struct timeval *timeout),
    void *transport_data);
int ipc_client_power_handlers_register(struct ipc_client *client,
    int (*power_on)(void *power_data), int (*power_off)(void *power_data),
    void *power_data);
int ipc_client_gprs_handlers_register(struct ipc_client *client,
    int (*gprs_activate)(void *gprs_data, unsigned int cid),
    int (*gprs_deactivate)(void *gprs_data, unsigned int cid), void *gprs_data);

void ipc_client_log(struct ipc_client *client, const char *message, ...);
int ipc_client_log_callback_register(struct ipc_client *client,
    void (*log_callback)(void *log_data, const char *message), void *log_data);

int ipc_client_boot(struct ipc_client *client);
int ipc_client_send(struct ipc_client *client, unsigned char mseq,
    unsigned short command, unsigned char type, const void *data, size_t size);
int ipc_client_recv(struct ipc_client *client, struct ipc_message *message);

int ipc_client_open(struct ipc_client *client);
int ipc_client_close(struct ipc_client *client);
int ipc_client_poll(struct ipc_client *client, struct ipc_poll_fds *fds, struct timeval *timeout);
int ipc_client_power_on(struct ipc_client *client);
int ipc_client_power_off(struct ipc_client *client);
int ipc_client_gprs_activate(struct ipc_client *client, unsigned int cid);
int ipc_client_gprs_deactivate(struct ipc_client *client, unsigned int cid);
int ipc_client_data_create(struct ipc_client *client);
int ipc_client_data_destroy(struct ipc_client *client);

char *ipc_client_gprs_get_iface(struct ipc_client *client, unsigned int cid);
int ipc_client_gprs_get_capabilities(struct ipc_client *client,
    struct ipc_client_gprs_capabilities *capabilities);

char *ipc_client_efs_root(struct ipc_client *client);
char *ipc_client_nv_data_path(struct ipc_client *client);
char *ipc_client_nv_data_md5_path(struct ipc_client *client);
char *ipc_client_nv_data_backup_path(struct ipc_client *client);
char *ipc_client_nv_data_backup_md5_path(struct ipc_client *client);
char *ipc_client_nv_data_secret(struct ipc_client *client);
size_t ipc_client_nv_data_size(struct ipc_client *client);
size_t ipc_client_nv_data_chunk_size(struct ipc_client *client);

int ipc_seq_valid(unsigned char seq);

const char *ipc_request_type_string(unsigned char type);
const char *ipc_response_type_string(unsigned char type);
const char *ipc_command_string(unsigned short command);

int ipc_data_dump(struct ipc_client *client, const void *data, size_t size);
void ipc_client_log_send(struct ipc_client *client, struct ipc_message *message,
    const char *prefix);
void ipc_client_log_recv(struct ipc_client *client, struct ipc_message *message,
    const char *prefix);

int ipc_fmt_header_setup(struct ipc_fmt_header *header,
    const struct ipc_message *message);
int ipc_fmt_message_setup(const struct ipc_fmt_header *header,
    struct ipc_message *message);
int ipc_rfs_header_setup(struct ipc_rfs_header *header,
    const struct ipc_message *message);
int ipc_rfs_message_setup(const struct ipc_rfs_header *header,
    struct ipc_message *message);

void *file_data_read(const char *path, size_t size, size_t chunk_size,
    unsigned int offset);
int file_data_write(const char *path, const void *data, size_t size,
    size_t chunk_size, unsigned int offset);
int network_iface_up(const char *iface, int domain, int type);
int network_iface_down(const char *iface, int domain, int type);
int sysfs_value_read(const char *path);
int sysfs_value_write(const char *path, int value);
char *sysfs_string_read(const char *path, size_t length);
int sysfs_string_write(const char *path, const char *buffer, size_t length);
size_t data2string_length(const void *data, size_t size);
char *data2string(const void *data, size_t size);
size_t string2data_size(const char *string);
void *string2data(const char *string);
unsigned short crc16_xmodem(unsigned char *ptr, int count);

/*
 * Samsung-IPC protocol
 */

#include "protocol.h"
#include "pwr.h"
#include "call.h"
#include "sms.h"
#include "sec.h"
#include "pb.h"
#include "disp.h"
#include "net.h"
#include "snd.h"
#include "misc.h"
#include "svc.h"
#include "ss.h"
#include "gprs.h"
#include "sat.h"
#include "imei.h"
#include "rfs.h"
#include "gen.h"

#endif

// vim:ts=4:sw=4:expandtab
