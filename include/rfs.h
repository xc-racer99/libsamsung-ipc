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
#define IPC_RFS_READ_FILE                                       0x4203
#define IPC_RFS_WRITE_FILE                                      0x4204
#define IPC_RFS_LSEEK_FILE                                      0x4205
#define IPC_RFS_CLOSE_FILE                                      0x4206
#define IPC_RFS_PUT_FILE                                        0x4207
#define IPC_RFS_GET_FILE                                        0x4208
#define IPC_RFS_RENAME_FILE                                     0x4209
#define IPC_RFS_GET_FILE_INFO                                   0x420a
#define IPC_RFS_UNLINK_FILE                                     0x420b
#define IPC_RFS_MAKE_DIR                                        0x420c
#define IPC_RFS_REMOVE_DIR                                      0x420d
#define IPC_RFS_OPEN_DIR                                        0x420e
#define IPC_RFS_READ_DIR                                        0x420f
#define IPC_RFS_CLOSE_DIR                                       0x4210
#define IPC_RFS_OPEN_FILE                                       0x4211
#define IPC_RFS_FTRUNCATE_FILE                                  0x4212
#define IPC_RFS_GET_HANDLE_INFO                                 0x4213
#define IPC_RFS_CREATE_FILE                                     0x4214
#define IPC_RFS_NV_WRITE_ALL_ITEM                               0x4215

/*
 * Values
 */

#define NV_DATA_SECRET                          "Samsung_Android_RIL"
#define NV_DATA_SIZE                                            0x200000
#define NV_DATA_CHUNK_SIZE                                      0x1000
#define IPC_RFS_TYPE_UNKNOWN                                    0x0
#define IPC_RFS_TYPE_DIRECTORY                                  0x1
#define IPC_RFS_TYPE_FILE                                       0x2

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

struct ipc_rfs_generic_io_response_header {
    int ret;
    int err;
} __attribute__((__packed__));

struct ipc_rfs_read_dir_response_header {
    int ret;
    int len;
    int err;
} __attribute__((__packed__));

struct ipc_rfs_file_info_response_data {
    unsigned int ret;
    unsigned short type;
    unsigned int size;
    unsigned char c_year;
    unsigned char c_month;
    unsigned char c_day;
    unsigned char c_hour;
    unsigned char c_min;
    unsigned char c_sec;
    unsigned char m_year;
    unsigned char m_month;
    unsigned char m_day;
    unsigned char m_hour;
    unsigned char m_min;
    unsigned char m_sec;
    unsigned int err;
} __attribute__((__packed__));

struct ipc_rfs_read_file_request_header {
    int fd;
    int len;
} __attribute__((__packed__));

struct ipc_rfs_write_file_request_header {
    int fd;
    int len;
} __attribute__((__packed__));

struct ipc_rfs_lseek_file_request_header {
    int fd;
    int offset;
    int whence;
} __attribute__((__packed__));

struct ipc_rfs_close_file_request_header {
    int fd;
} __attribute__((__packed__));

struct ipc_rfs_get_file_info_request_header {
    int path_len;
} __attribute__((__packed__));

struct ipc_rfs_rename_file_request_header {
    int path_len;
} __attribute__((__packed__));

struct ipc_rfs_unlink_file_request_header {
    int path_len;
} __attribute__((__packed__));

struct ipc_rfs_make_dir_request_header {
    int path_len;
} __attribute__((__packed__));

struct ipc_rfs_remove_dir_request_header {
    int path_len;
} __attribute__((__packed__));

struct ipc_rfs_open_dir_request_header {
    int path_len;
} __attribute__((__packed__));

struct ipc_rfs_read_dir_request_header {
    unsigned int addr;
} __attribute__((__packed__));

struct ipc_rfs_close_dir_request_header {
    unsigned int addr;
} __attribute__((__packed__));

struct ipc_rfs_open_file_request_header {
    unsigned int flags; // | O_DSYNC
    unsigned int path_len;
} __attribute__((__packed__));

struct ipc_rfs_get_handle_info_request_header {
    int fd;
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
int ipc_rfs_nv_read_item(struct ipc_client *client, struct ipc_message *message);
int ipc_rfs_nv_write_item(struct ipc_client *client, struct ipc_message *message);
int ipc_rfs_read_dir(struct ipc_client *client, struct ipc_message *message);
int ipc_rfs_generic_io(struct ipc_client *client, struct ipc_message *message);
int ipc_rfs_file_info(struct ipc_client *client, struct ipc_message *message);

#endif

// vim:ts=4:sw=4:expandtab
