/*
 * This file is part of libsamsung-ipc.
 *
 * Copyright (C) 2011-2013 Paul Kocialkowski <contact@paulk.fr>
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

#include <samsung-ipc.h>

#ifndef __SAMSUNG_IPC_RFS_H__
#define __SAMSUNG_IPC_RFS_H__

/*
 * Commands
 */

#define IPC_RFS_NV_READ_ITEM                                    0x4201
#define IPC_RFS_NV_WRITE_ITEM                                   0x4202

/*
 * Values
 */

#define NV_DATA_SECRET                          "Samsung_Android_RIL"
#define NV_DATA_SIZE                                            0x200000
#define NV_DATA_CHUNK_SIZE                                      0x1000

/*
 * Structures
 */

struct ipc_rfs_nv_read_item_request_data {
    unsigned int offset;
    unsigned int length;
} __attribute__((__packed__));

struct ipc_rfs_nv_read_item_response_header {
    unsigned char confirm;
    unsigned int offset;
    unsigned int length;
} __attribute__((__packed__));

struct ipc_rfs_nv_write_item_request_header {
    unsigned int offset;
    unsigned int length;
} __attribute__((__packed__));

struct ipc_rfs_nv_write_item_response_data {
    unsigned char confirm;
    unsigned int offset;
    unsigned int length;
} __attribute__((__packed__));

/*
 * Helpers
 */

char *ipc_nv_data_md5_calculate(const char *path, const char *secret,
    size_t size, size_t chunk_size);
int ipc_nv_data_path_check(struct ipc_client *client);
int ipc_nv_data_md5_path_check(struct ipc_client *client);
int ipc_nv_data_backup_path_check(struct ipc_client *client);
int ipc_nv_data_backup_md5_path_check(struct ipc_client *client);
int ipc_nv_data_check(struct ipc_client *client);
int ipc_nv_data_backup_check(struct ipc_client *client);
int ipc_nv_data_backup(struct ipc_client *client);
int ipc_nv_data_restore(struct ipc_client *client);
void *ipc_nv_data_load(struct ipc_client *client);
void *ipc_nv_data_read(struct ipc_client *client, size_t size,
    unsigned int offset);
int ipc_nv_data_write(struct ipc_client *client, const void *data, size_t size,
    unsigned int offset);
size_t ipc_rfs_nv_data_item_size_setup(struct ipc_rfs_nv_read_item_response_header *header,
    const void *nv_data, size_t nv_size);
void *ipc_rfs_nv_read_item_setup(struct ipc_rfs_nv_read_item_response_header *header,
    const void *nv_data, size_t nv_size);
size_t ipc_rfs_nv_write_item_size_extract(const void *data, size_t size);
void *ipc_rfs_nv_write_item_extract(const void *data, size_t size);

#endif

// vim:ts=4:sw=4:expandtab
