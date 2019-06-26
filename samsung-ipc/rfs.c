/*
 * This file is part of libsamsung-ipc.
 *
 * Copyright (C) 2011-2014 Paul Kocialkowski <contact@paulk.fr>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>     /* PATH_MAX */

#include <openssl/md5.h>

#include <samsung-ipc.h>

#include <ipc.h>

char *ipc_nv_data_md5_calculate(const char *path, const char *secret,
    size_t size, size_t chunk_size)
{
    void *data = NULL;
    char *md5_string = NULL;
    unsigned char md5_hash[MD5_DIGEST_LENGTH] = { 0 };
    MD5_CTX ctx;
    int rc;

    if (secret == NULL)
        return NULL;

    data = file_data_read(path, size, chunk_size, 0);
    if (data == NULL)
        return NULL;

    MD5_Init(&ctx);
    MD5_Update(&ctx, data, size);
    MD5_Update(&ctx, secret, strlen(secret));
    MD5_Final((unsigned char *) &md5_hash, &ctx);

    md5_string = data2string(&md5_hash, sizeof(md5_hash));

    return md5_string;
}

int ipc_nv_data_path_check(struct ipc_client *client)
{
    struct stat st;
    char *path;
    size_t size;
    int rc;

    if (client == NULL)
        return -1;

    path = ipc_client_nv_data_path(client);
    size = ipc_client_nv_data_size(client);
    if (path == NULL || size == 0)
        return -1;

    rc = stat(path, &st);
    if (rc < 0) {
        ipc_client_log(client, "Checking nv_data path failed");
        return -1;
    }

    if (st.st_size != size) {
        ipc_client_log(client, "Checking nv_data size failed");
        return -1;
    }

    ipc_client_log(client, "Checked nv_data path");

    return 0;
}

int ipc_nv_data_md5_path_check(struct ipc_client *client)
{
    struct stat st;
    char *md5_path;
    int rc;

    if (client == NULL)
        return -1;

    md5_path = ipc_client_nv_data_md5_path(client);
    if (md5_path == NULL)
        return -1;

    rc = stat(md5_path, &st);
    if (rc < 0) {
        ipc_client_log(client, "Checking nv_data md5 path failed");
        return -1;
    }

    if (st.st_size < 2 * sizeof(char) * MD5_DIGEST_LENGTH) {
        ipc_client_log(client, "Checking nv_data md5 size failed");
        return -1;
    }

    ipc_client_log(client, "Checked nv_data md5 path");

    return 0;
}

int ipc_nv_data_backup_path_check(struct ipc_client *client)
{
    struct stat st;
    char *backup_path;
    size_t size;
    int rc;

    if (client == NULL)
        return -1;

    backup_path = ipc_client_nv_data_backup_path(client);
    size = ipc_client_nv_data_size(client);
    if (backup_path == NULL || size == 0)
        return -1;

    rc = stat(backup_path, &st);
    if (rc < 0) {
        ipc_client_log(client, "Checking nv_data backup path failed");
        return -1;
    }

    if (st.st_size != size) {
        ipc_client_log(client, "Checking nv_data backup size failed");
        return -1;
    }

    ipc_client_log(client, "Checked nv_data backup path");

    return 0;
}

int ipc_nv_data_backup_md5_path_check(struct ipc_client *client)
{
    struct stat st;
    char *backup_md5_path;
    int rc;

    if (client == NULL)
        return -1;

    backup_md5_path = ipc_client_nv_data_backup_md5_path(client);
    if (backup_md5_path == NULL)
        return -1;

    rc = stat(backup_md5_path, &st);
    if (rc < 0) {
        ipc_client_log(client, "Checking nv_data backup md5 path failed");
        return -1;
    }

    if (st.st_size < 2 * sizeof(char) * MD5_DIGEST_LENGTH) {
        ipc_client_log(client, "Checking nv_data backup md5 size failed");
        return -1;
    }

    ipc_client_log(client, "Checked nv_data backup md5 path");

    return 0;
}

int ipc_nv_data_check(struct ipc_client *client)
{
    char *path;
    char *md5_path;
    char *secret;
    size_t size;
    size_t chunk_size;
    char *md5_string = NULL;
    void *buffer = NULL;
    char *string = NULL;
    size_t length;
    int rc;

    if (client == NULL)
        return -1;

    path = ipc_client_nv_data_path(client);
    md5_path = ipc_client_nv_data_md5_path(client);
    secret = ipc_client_nv_data_secret(client);
    size = ipc_client_nv_data_size(client);
    chunk_size = ipc_client_nv_data_chunk_size(client);
    if (path == NULL || md5_path == NULL || secret == NULL || size == 0 || chunk_size == 0)
        return -1;

    rc = ipc_nv_data_path_check(client);
    if (rc < 0) {
        ipc_client_log(client, "Checking nv_data path failed");
        goto error;
    }

    rc = ipc_nv_data_md5_path_check(client);
    if (rc < 0) {
        ipc_client_log(client, "Checking nv_data md5 path failed");
        goto error;
    }

    md5_string = ipc_nv_data_md5_calculate(path, secret, size, chunk_size);
    if (md5_string == NULL) {
        ipc_client_log(client, "Calculating nv_data md5 failed");
        goto error;
    }
    ipc_client_log(client, "Calculated nv_data md5: %s", md5_string);

    length = strlen(md5_string);

    buffer = file_data_read(md5_path, length, length, 0);
    if (buffer == NULL) {
        ipc_client_log(client, "Reading nv_data md5 failed");
        goto error;
    }

    string = strndup(buffer, length);
    ipc_client_log(client, "Read nv_data md5: %s", string);

    rc = strncmp(md5_string, string, length);
    if (rc != 0) {
        ipc_client_log(client, "Matching nv_data md5 failed");
        goto error;
    }

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (string != NULL)
        free(string);

    if (buffer != NULL)
        free(buffer);

    if (md5_string != NULL)
        free(md5_string);

    return rc;
}

int ipc_nv_data_backup_check(struct ipc_client *client)
{
    char *backup_path;
    char *backup_md5_path;
    char *secret;
    size_t size;
    size_t chunk_size;
    char *backup_md5_string = NULL;
    void *buffer = NULL;
    char *string = NULL;
    size_t length;
    int rc;

    if (client == NULL)
        return -1;

    backup_path = ipc_client_nv_data_backup_path(client);
    backup_md5_path = ipc_client_nv_data_backup_md5_path(client);
    secret = ipc_client_nv_data_secret(client);
    size = ipc_client_nv_data_size(client);
    chunk_size = ipc_client_nv_data_chunk_size(client);
    if (backup_path == NULL || backup_md5_path == NULL || secret == NULL || size == 0 || chunk_size == 0)
        return -1;

    rc = ipc_nv_data_backup_path_check(client);
    if (rc < 0) {
        ipc_client_log(client, "Checking nv_data backup path failed");
        goto error;
    }

    rc = ipc_nv_data_backup_md5_path_check(client);
    if (rc < 0) {
        ipc_client_log(client, "Checking nv_data backup md5 path failed");
        goto error;
    }

    backup_md5_string = ipc_nv_data_md5_calculate(backup_path, secret, size, chunk_size);
    if (backup_md5_string == NULL) {
        ipc_client_log(client, "Calculating nv_data backup md5 failed");
        goto error;
    }
    ipc_client_log(client, "Calculated nv_data backup md5: %s", backup_md5_string);

    length = strlen(backup_md5_string);

    buffer = file_data_read(backup_md5_path, length, length, 0);
    if (buffer == NULL) {
        ipc_client_log(client, "Reading nv_data backup md5 failed");
        goto error;
    }

    string = strndup(buffer, length);
    ipc_client_log(client, "Read nv_data backup md5: %s", string);

    rc = strncmp(backup_md5_string, string, length);
    if (rc != 0) {
        ipc_client_log(client, "Matching nv_data backup md5 failed");
        goto error;
    }

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (string != NULL)
        free(string);

    if (buffer != NULL)
        free(buffer);

    if (backup_md5_string != NULL)
        free(backup_md5_string);

    return rc;
}

int ipc_nv_data_backup(struct ipc_client *client)
{
    void *data = NULL;
    char *path;
    char *backup_path;
    char *backup_md5_path;
    char *secret;
    size_t size;
    size_t chunk_size;
    char *md5_string = NULL;
    size_t length;
    int rc;

    if (client == NULL)
        return -1;

    path = ipc_client_nv_data_path(client);
    backup_path = ipc_client_nv_data_backup_path(client);
    backup_md5_path = ipc_client_nv_data_backup_md5_path(client);
    secret = ipc_client_nv_data_secret(client);
    size = ipc_client_nv_data_size(client);
    chunk_size = ipc_client_nv_data_chunk_size(client);
    if (path == NULL || backup_path == NULL || backup_md5_path == NULL || secret == NULL || size == 0 || chunk_size == 0)
        return -1;

    rc = ipc_nv_data_path_check(client);
    if (rc < 0) {
        ipc_client_log(client, "Checking nv_data path failed");
        goto error;
    }

    data = file_data_read(path, size, chunk_size, 0);
    if (data == NULL) {
        ipc_client_log(client, "Reading nv_data failed");
        goto error;
    }

    md5_string = ipc_nv_data_md5_calculate(path, secret, size, chunk_size);
    if (md5_string == NULL) {
        ipc_client_log(client, "Calculating nv_data md5 failed");
        goto error;
    }

    length = strlen(md5_string);

    rc = unlink(backup_path);
    if (rc < 0)
        ipc_client_log(client, "Removing nv_data backup path failed");

    rc = file_data_write(backup_path, data, size, chunk_size, 0);
    if (rc < 0) {
        ipc_client_log(client, "Writing nv_data backup failed");
        goto error;
    }

    rc = unlink(backup_md5_path);
    if (rc < 0)
        ipc_client_log(client, "Removing nv_data backup md5 path failed");

    rc = file_data_write(backup_md5_path, md5_string, length, length, 0);
    if (rc < 0) {
        ipc_client_log(client, "Writing nv_data backup md5 failed");
        goto error;
    }

    ipc_client_log(client, "Backed up nv_data");

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (md5_string != NULL)
        free(md5_string);

    if (data != NULL)
        free(data);

    return rc;
}

int ipc_nv_data_restore(struct ipc_client *client)
{
    void *data = NULL;
    char *path;
    char *md5_path;
    char *backup_path;
    char *backup_md5_path;
    char *secret;
    size_t size;
    size_t chunk_size;
    size_t length;
    int rc;

    if (client == NULL)
        return -1;

    path = ipc_client_nv_data_path(client);
    md5_path = ipc_client_nv_data_md5_path(client);
    backup_path = ipc_client_nv_data_backup_path(client);
    backup_md5_path = ipc_client_nv_data_backup_md5_path(client);
    secret = ipc_client_nv_data_secret(client);
    size = ipc_client_nv_data_size(client);
    chunk_size = ipc_client_nv_data_chunk_size(client);
    if (path == NULL || md5_path == NULL || backup_path == NULL || backup_md5_path == NULL || secret == NULL || size == 0 || chunk_size == 0)
        return -1;

    rc = ipc_nv_data_backup_check(client);
    if (rc < 0) {
        ipc_client_log(client, "Checking nv_data backup failed");
        goto error;
    }

    data = file_data_read(backup_path, size, chunk_size, 0);
    if (data == NULL) {
        ipc_client_log(client, "Reading nv_data backup failed");
        goto error;
    }

    rc = unlink(path);
    if (rc < 0)
        ipc_client_log(client, "Removing nv_data path failed");

    rc = file_data_write(path, data, size, chunk_size, 0);
    if (rc < 0) {
        ipc_client_log(client, "Writing nv_data failed");
        goto error;
    }

    free(data);
    data = NULL;

    length = 2 * sizeof(char) * MD5_DIGEST_LENGTH;

    data = file_data_read(backup_md5_path, length, length, 0);
    if (data == NULL) {
        ipc_client_log(client, "Reading nv_data backup md5 failed");
        goto error;
    }

    rc = unlink(md5_path);
    if (rc < 0)
        ipc_client_log(client, "Removing nv_data md5 path failed");

    rc = file_data_write(md5_path, data, length, length, 0);
    if (rc < 0) {
        ipc_client_log(client, "Writing nv_data md5 failed");
        goto error;
    }

    ipc_client_log(client, "Restored nv_data");

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (data != NULL)
        free(data);

    return rc;
}

void *ipc_nv_data_load(struct ipc_client *client)
{
    void *data;
    char *path;
    size_t size;
    size_t chunk_size;
    int rc;

    if (client == NULL)
        return NULL;

    path = ipc_client_nv_data_path(client);
    size = ipc_client_nv_data_size(client);
    chunk_size = ipc_client_nv_data_chunk_size(client);
    if (path == NULL || size == 0 || chunk_size == 0)
        return NULL;

    rc = ipc_nv_data_check(client);
    if (rc < 0) {
        ipc_client_log(client, "Checking nv_data failed");

        rc = ipc_nv_data_restore(client);
        if (rc < 0) {
            ipc_client_log(client, "Restoring nv_data failed");
            return NULL;
        }

        rc = ipc_nv_data_check(client);
        if (rc < 0) {
            ipc_client_log(client, "Checking nv_data failed");
            return NULL;
        }
    }

    rc = ipc_nv_data_backup_path_check(client);
    if (rc < 0) {
        ipc_client_log(client, "Checking nv_data backup path failed");

        rc = ipc_nv_data_backup(client);
        if (rc < 0)
            ipc_client_log(client, "Backing up nv_data failed");
    }

    data = file_data_read(path, size, chunk_size, 0);
    if (data == NULL) {
        ipc_client_log(client, "Reading nv_data failed");
        return NULL;
    }

    return data;
}

void *ipc_nv_data_read(struct ipc_client *client, size_t size,
    unsigned int offset)
{
    void *data;
    char *path;
    size_t chunk_size;
    int rc;

    if (client == NULL)
        return NULL;

    path = ipc_client_nv_data_path(client);
    chunk_size = ipc_client_nv_data_chunk_size(client);
    if (path == NULL || chunk_size == 0)
        return NULL;

    rc = ipc_nv_data_path_check(client);
    if (rc < 0) {
        ipc_client_log(client, "Checking nv_data path failed");
        return NULL;
    }

    data = file_data_read(path, size, chunk_size > size ? size : chunk_size, offset);
    if (data == NULL) {
        ipc_client_log(client, "Reading nv_data failed");
        return NULL;
    }

    return data;
}

int ipc_nv_data_write(struct ipc_client *client, const void *data, size_t size,
    unsigned int offset)
{
    char *path;
    char *md5_path;
    char *secret;
    size_t chunk_size;
    char *md5_string = NULL;
    size_t length;
    int rc;

    if (client == NULL)
        return -1;

    path = ipc_client_nv_data_path(client);
    md5_path = ipc_client_nv_data_md5_path(client);
    secret = ipc_client_nv_data_secret(client);
    chunk_size = ipc_client_nv_data_chunk_size(client);
    if (path == NULL || md5_path == NULL || secret == NULL || chunk_size == 0)
        return -1;

    rc = ipc_nv_data_path_check(client);
    if (rc < 0) {
        ipc_client_log(client, "Checking nv_data path failed");
        goto error;
    }

    rc = file_data_write(path, data, size, chunk_size > size ? size : chunk_size, offset);
    if (rc < 0) {
        ipc_client_log(client, "Writing nv_data failed");
        goto error;
    }

    size = ipc_client_nv_data_size(client);
    if (size == 0)
        goto error;

    md5_string = ipc_nv_data_md5_calculate(path, secret, size, chunk_size);
    if (md5_string == NULL) {
        ipc_client_log(client, "Calculating nv_data md5 failed");
        goto error;
    }

    length = strlen(md5_string);

    rc = unlink(md5_path);
    if (rc < 0) {
        ipc_client_log(client, "Removing nv_data md5 path failed");
        goto error;
    }

    rc = file_data_write(md5_path, md5_string, length, length, 0);
    if (rc < 0) {
        ipc_client_log(client, "Writing nv_data md5 failed");
        goto error;
    }

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (md5_string != NULL)
        free(md5_string);

    return rc;
}

size_t ipc_rfs_nv_data_item_size_setup(struct ipc_rfs_nv_read_item_response_header *header,
    const void *nv_data, size_t nv_size)
{
    size_t size;

    if (header == NULL || nv_data == NULL || nv_size == 0)
        return 0;

    size = sizeof(struct ipc_rfs_nv_read_item_response_header) + size;

    return size;
}

void *ipc_rfs_nv_read_item_setup(struct ipc_rfs_nv_read_item_response_header *header,
    const void *nv_data, size_t nv_size)
{
    void *data;
    size_t size;
    unsigned char *p;

    if (header == NULL || nv_data == NULL || nv_size == 0)
        return NULL;

    size = ipc_rfs_nv_data_item_size_setup(header, nv_data, nv_size);
    if (size == 0)
        return NULL;

    data = calloc(1, size);

    p = (unsigned char *) data;

    memcpy(p, header, sizeof(struct ipc_rfs_nv_read_item_response_header));
    p += sizeof(struct ipc_rfs_nv_read_item_response_header);

    memcpy(p, nv_data, nv_size);
    p += nv_size;

    return data;
}

size_t ipc_rfs_nv_write_item_size_extract(const void *data, size_t size)
{
    struct ipc_rfs_nv_write_item_request_header *header;

    if (data == NULL || size < sizeof(struct ipc_rfs_nv_write_item_request_header))
        return 0;

    header = (struct ipc_rfs_nv_write_item_request_header *) data;
    if (header->length == 0 || header->length > size - sizeof(struct ipc_rfs_nv_write_item_request_header))
        return 0;

    return header->length;
}

void *ipc_rfs_nv_write_item_extract(const void *data, size_t size)
{
    struct ipc_rfs_nv_write_item_request_header *header;
    void *nv_data;

    if (data == NULL || size < sizeof(struct ipc_rfs_nv_write_item_request_header))
        return NULL;

    header = (struct ipc_rfs_nv_write_item_request_header *) data;
    if (header->length == 0 || header->length > size - sizeof(struct ipc_rfs_nv_write_item_request_header))
        return NULL;

    nv_data = (void *) ((unsigned char *) data + sizeof(struct ipc_rfs_nv_write_item_request_header));

    return nv_data;
}

int ipc_rfs_nv_read_item(struct ipc_client *client, struct ipc_message *message)
{
    struct ipc_rfs_nv_read_item_response_header response_header;
    struct ipc_rfs_nv_read_item_request_data *data;
    struct ipc_rfs_data *ipc_rfs_data;
    void *response_data = NULL;
    size_t response_size = 0;
    void *nv_data = NULL;
    int rc;

    if (message == NULL || message->data == NULL || message->size < sizeof(struct ipc_rfs_nv_read_item_request_data))
        return -1;

    data = (struct ipc_rfs_nv_read_item_request_data *) message->data;

    memset(&response_header, 0, sizeof(response_header));

    nv_data = ipc_nv_data_read(client, data->length, data->offset);
    if (nv_data == NULL) {
        ipc_client_log(client, "Reading %d nv_data bytes at offset 0x%x failed", data->length, data->offset);

        response_header.confirm = 0;

        rc = ipc_client_send(client, message->aseq, IPC_RFS_NV_READ_ITEM, IPC_TYPE_RESP, (void *) &response_header, sizeof(response_header));
        if (rc < 0)
            goto complete;

        goto complete;
    }

    ipc_client_log(client, "Read %d nv_data bytes at offset 0x%x", data->length, data->offset);

    response_header.confirm = 1;
    response_header.offset = data->offset;
    response_header.length = data->length;

    response_size = ipc_rfs_nv_data_item_size_setup(&response_header, nv_data, data->length);
    if (response_size == 0)
        goto complete;

    response_data = ipc_rfs_nv_read_item_setup(&response_header, nv_data, data->length);
    if (response_data == NULL)
        goto complete;

    rc = ipc_client_send(client, message->aseq, IPC_RFS_NV_READ_ITEM, IPC_TYPE_RESP, response_data, response_size);
    if (rc < 0)
        goto complete;

    goto complete;

complete:
    if (response_data != NULL && response_size > 0)
        free(response_data);

    if (nv_data != NULL)
        free(nv_data);

    return 0;
}

int ipc_rfs_nv_write_item(struct ipc_client *client, struct ipc_message *message)
{
    struct ipc_rfs_nv_write_item_request_header *header;
    struct ipc_rfs_nv_write_item_response_data data;
    struct ipc_rfs_data *ipc_rfs_data;
    void *nv_data;
    size_t nv_size;
    int rc;

    if (message == NULL || message->data == NULL || message->size < sizeof(struct ipc_rfs_nv_write_item_request_header))
        return -1;
    header = (struct ipc_rfs_nv_write_item_request_header *) message->data;

    nv_size = ipc_rfs_nv_write_item_size_extract(message->data, message->size);
    if (nv_size == 0)
        return 0;

    nv_data = ipc_rfs_nv_write_item_extract(message->data, message->size);
    if (nv_data == NULL)
        return 0;

    memset(&data, 0, sizeof(data));

    rc = ipc_nv_data_write(client, nv_data, header->length, header->offset);
    if (rc < 0) {
        ipc_client_log(client, "Writing %d nv_data byte(s) at offset 0x%x failed", header->length, header->offset);

        data.confirm = 0;
    } else {
        ipc_client_log(client, "Wrote %d nv_data byte(s) at offset 0x%x", header->length, header->offset);

        data.confirm = 1;
        data.offset = header->offset;
        data.length = header->length;
    }

    rc = ipc_client_send(client, message->aseq, IPC_RFS_NV_WRITE_ITEM, IPC_TYPE_RESP, (void *) &data, sizeof(data));
    if (rc < 0)
        return 0;

    return 0;
}

int ipc_rfs_read_dir(struct ipc_client *client, struct ipc_message *message)
{
    struct ipc_rfs_read_dir_request_header *header;
    struct ipc_rfs_read_dir_response_header *response_header;
    struct dirent *dirent;
    DIR *dirp;
    void *buffer = NULL;
    size_t len;
    int rc;

    if (message == NULL || message->data == NULL || message->size < sizeof(struct ipc_rfs_read_dir_request_header))
        return -1;

    header = (struct ipc_rfs_read_dir_request_header *) message->data;

    dirp = (DIR *) header->addr;

    /* Clear errno before readdir call */
    errno = 0;

    dirent = readdir(dirp);
    if (dirent == NULL) {
        len = sizeof(struct ipc_rfs_read_dir_response_header);
        buffer = alloca(len);
        if (buffer == NULL)
            return -1;
        response_header = (struct ipc_rfs_read_dir_response_header *) buffer;
        response_header->ret = -1;
        response_header->len = 0;
        response_header->err = errno;
    } else {
        len = sizeof(struct ipc_rfs_read_dir_response_header) + strlen(dirent->d_name);
        buffer = alloca(len);
        if (buffer == NULL)
            return -1;
        response_header = (struct ipc_rfs_read_dir_response_header *) buffer;
        response_header->ret = 0;
        response_header->len = strlen(dirent->d_name);
        response_header->err = 0;
        strcpy((char *) buffer + sizeof(struct ipc_rfs_read_dir_response_header), dirent->d_name);
    }

    rc = ipc_client_send(client, message->aseq, IPC_RFS_READ_DIR, IPC_TYPE_RESP, buffer, len);

    return 0;
}

int mkdir_p(char *file_path)
{
    char *p;
    for (p = strchr(file_path + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (mkdir(file_path, S_IRWXU | S_IRWXG) == -1) {
            if (errno != EEXIST) {
                *p = '/';
                return -1;
            }
        }
        *p = '/';
    }

    return 0;
}

int ipc_rfs_make_path(struct ipc_client *client, char *path, char *rel_path, int rel_path_len)
{
    char *efs_root;
    char *p;

    if (rel_path == NULL) {
        ipc_client_log(client, "rel_path is null");
        return -1;
    }

    efs_root = ipc_client_efs_root(client);
    if (efs_root == NULL) {
        ipc_client_log(client, "Failed to read efs_root");
        return -1;
    }

    /* Combine efs_root and rel_path */
    strcpy(path, efs_root);
    strncat(path, rel_path, rel_path_len);

    p = realpath(path, NULL);

    /* Make sure we're not trying to go above efs_root */
    if (p == NULL) {
        /* Conditionally allow ENOENT and ENOTDIR as they might be creating something */
        if (errno == ENOENT || errno == ENOTDIR) {
            if (strstr(path, "/../") != NULL) {
                ipc_client_log(client, "path %s contains /../ and realpath() failed with errno %d, denying access", path, errno);
                return -1;
            }
        } else {
            ipc_client_log(client, "realpath() failed on %s with errno %d, denying access", path, errno);
            return -1;
        }
    } else if (strncmp(efs_root, p, strlen(efs_root))) {
        ipc_client_log(client, "WARNING: RIL is trying to access %s which is outside of %s, denying access", p, efs_root);
        return -1;
    }

    ipc_client_log(client, "Created path %s", path);

    return 0;
}

int ipc_rfs_generic_io(struct ipc_client *client, struct ipc_message *message)
{
    struct ipc_rfs_generic_io_response_header data;
    struct ipc_rfs_data *ipc_rfs_data;
    int rc;

    if (message == NULL || message->data == NULL)
        return -1;

    memset(&data, 0, sizeof(data));

    switch (message->command) {
        case IPC_RFS_READ_FILE:
        {
            if (message->size < sizeof(struct ipc_rfs_read_file_request_header))
                return -1;

            struct ipc_rfs_read_file_request_header *header =
                    (struct ipc_rfs_read_file_request_header *) message->data;
            struct ipc_rfs_generic_io_response_header *response;

            /* Special case - we need a bigger buffer */
            void *buf = alloca(sizeof(struct ipc_rfs_generic_io_response_header) + header->len);
            if (buf == NULL) {
                ipc_client_log(client, "alloca failed");
                goto error;
            }

            rc = read(header->fd,
                    (char *) ((char *) buf + sizeof(struct ipc_rfs_generic_io_response_header)),
                    header->len);

            response = buf;

            response->ret = rc;

            if (response->ret == 0)
                response->err = ENOENT;
            else if (response->ret < 0)
                response->err = errno;
            else
                response->err = 0;

            rc = ipc_client_send(client, message->aseq, message->command, IPC_TYPE_RESP, response,
                    sizeof(struct ipc_rfs_generic_io_response_header) + response->ret);

            return 0;
        }
        case IPC_RFS_WRITE_FILE:
        {
            if (message->size < sizeof(struct ipc_rfs_write_file_request_header))
                return -1;

            struct ipc_rfs_write_file_request_header *header =
                    (struct ipc_rfs_write_file_request_header *) message->data;

            data.ret = write(header->fd,
                    header + sizeof(struct ipc_rfs_write_file_request_header),
                    header->len);
            break;
        }
        case IPC_RFS_LSEEK_FILE:
        {
            if (message->size < sizeof(struct ipc_rfs_lseek_file_request_header))
                return -1;

            struct ipc_rfs_lseek_file_request_header *header =
                    (struct ipc_rfs_lseek_file_request_header *) message->data;
            data.ret = lseek(header->fd, header->offset, header->whence);
            break;
        }
        case IPC_RFS_CLOSE_FILE:
        {
            if (message->size < sizeof(struct ipc_rfs_close_file_request_header))
                return -1;

            struct ipc_rfs_close_file_request_header *header =
                    (struct ipc_rfs_close_file_request_header *) message->data;
            data.ret = close(header->fd);
            break;
        }
        case IPC_RFS_RENAME_FILE:
        {
            if (message->size < sizeof(struct ipc_rfs_rename_file_request_header))
                return -1;

            struct ipc_rfs_rename_file_request_header *header1 =
                    (struct ipc_rfs_rename_file_request_header *) message->data;
            struct ipc_rfs_rename_file_request_header *header2 =
                    (struct ipc_rfs_rename_file_request_header *)
                    ((char *) message->data
                    + sizeof(struct ipc_rfs_rename_file_request_header)
                    + header1->path_len);
            char oldpath[PATH_MAX];
            char newpath[PATH_MAX];;

            rc = ipc_rfs_make_path(client, oldpath,
                    (char *) header1 + sizeof(struct ipc_rfs_rename_file_request_header),
                    header1->path_len);

            if (rc < 0) {
                ipc_client_log(client, "ipc_rfs_make_path failed");
                goto error;
            }

            rc = ipc_rfs_make_path(client, newpath,
                    (char *) header2 + sizeof(struct ipc_rfs_rename_file_request_header),
                    header2->path_len);

            if (rc < 0) {
                ipc_client_log(client, "ipc_rfs_make_path failed");
                goto error;
            }

            data.ret = rename(oldpath, newpath);
            break;
        }
        case IPC_RFS_UNLINK_FILE:
        {
            if (message->size < sizeof(struct ipc_rfs_unlink_file_request_header))
                return -1;

            struct ipc_rfs_unlink_file_request_header *header =
                    (struct ipc_rfs_unlink_file_request_header *) message->data;
            char path[PATH_MAX];
            rc = ipc_rfs_make_path(client, path,
                    (char *) message->data + sizeof(struct ipc_rfs_unlink_file_request_header),
                    header->path_len);
            if (rc < 0)
                goto error;
            rc = unlink(path);
            if (rc < 0 && errno == ENOENT)
                rc = 0;
            data.ret = rc;

            break;
        }
        case IPC_RFS_MAKE_DIR:
        {
            if (message->size < sizeof(struct ipc_rfs_make_dir_request_header))
                return -1;

            struct stat buf;
            struct ipc_rfs_make_dir_request_header *header =
                    (struct ipc_rfs_make_dir_request_header *) message->data;
            char path[PATH_MAX];
            rc = ipc_rfs_make_path(client, path,
                    (char *) message->data + sizeof(struct ipc_rfs_make_dir_request_header),
                    header->path_len);
            if (rc < 0)
                goto error;
            rc = stat(path, &buf);
            if (rc < 0 && errno == ENOENT)
                rc = mkdir(path, 0660);
            data.ret = rc;
            break;
        }
        case IPC_RFS_REMOVE_DIR:
        {
            if (message->size < sizeof(struct ipc_rfs_remove_dir_request_header))
                return -1;

            struct ipc_rfs_remove_dir_request_header *header =
                    (struct ipc_rfs_remove_dir_request_header *) message->data;
            char path[PATH_MAX];
            rc = ipc_rfs_make_path(client, path,
                    (char *) message->data + sizeof(struct ipc_rfs_remove_dir_request_header),
                    header->path_len);
            if (rc < 0)
                goto error;
            data.ret = rmdir(path);
            break;
        }
        case IPC_RFS_OPEN_DIR:
        {
            if (message->size < sizeof(struct ipc_rfs_open_dir_request_header))
                return -1;

            DIR *dirp;
            struct ipc_rfs_open_dir_request_header *header =
                    (struct ipc_rfs_open_dir_request_header *) message->data;
            char path[PATH_MAX];
            rc = ipc_rfs_make_path(client, path,
                    (char *) message->data + sizeof(struct ipc_rfs_open_dir_request_header),
                    header->path_len);
            if (rc < 0)
                goto error;
            dirp = opendir(path);
            if (dirp) {
                data.ret = (int) dirp;
                /**
                 * Explicitly clear errno here, as dirp can be considered
                 * negative below, leading to errors if errno was already set
                 */
                errno = 0;
            } else {
                data.ret = -1;
            }
            break;
        }
        case IPC_RFS_CLOSE_DIR:
        {
            if (message->size < sizeof(struct ipc_rfs_close_dir_request_header))
                return -1;

            struct ipc_rfs_close_dir_request_header *header =
                    (struct ipc_rfs_close_dir_request_header *) message->data;
            data.ret = closedir((DIR *) header->addr);
            break;
        }
        case IPC_RFS_OPEN_FILE:
        {
            if (message->size < sizeof(struct ipc_rfs_open_file_request_header))
                return -1;

            struct ipc_rfs_open_file_request_header *header =
                    (struct ipc_rfs_open_file_request_header *) message->data;
            char path[PATH_MAX];
            rc = ipc_rfs_make_path(client, path,
                    (char *) message->data + sizeof(struct ipc_rfs_open_file_request_header),
                    header->path_len);
            if (rc < 0)
                goto error;
            if (header->flags & O_CREAT) {
                ipc_client_log(client, "Recursively creating directory and files");

                char *index = strrchr(path, '/');
                if (index != NULL)
                    mkdir_p(path);
            }
            data.ret = open(path, header->flags | O_DSYNC, 0644);
            break;
        }
        default:
        {
            ipc_client_log(client, "Unknown generic IO command %d", message->command);
            goto error;
        }
    }

    if (data.ret < 0)
        data.err = errno;

    rc = ipc_client_send(client, message->aseq, message->command, IPC_TYPE_RESP, &data,
            sizeof(struct ipc_rfs_generic_io_response_header));

    return 0;

error:
    data.ret = -1;
    data.err = EPERM;

    rc = ipc_client_send(client, message->aseq, message->command, IPC_TYPE_RESP, &data,
            sizeof(struct ipc_rfs_generic_io_response_header));

    return 0;
}

int ipc_rfs_file_info(struct ipc_client *client, struct ipc_message *message)
{
    struct ipc_rfs_data *ipc_rfs_data;
    struct ipc_rfs_file_info_response_data data;
    struct stat buf;
    struct tm result;
    char path[PATH_MAX];
    int rc;

    if (message == NULL || message->data == NULL)
        return -1;

    memset(&data, 0, sizeof(data));

    if (message->command == IPC_RFS_GET_FILE_INFO) {
        if (message->size < sizeof(struct ipc_rfs_get_file_info_request_header))
            return -1;

        struct ipc_rfs_get_file_info_request_header *header =
                (struct ipc_rfs_get_file_info_request_header *) message->data;

        rc = ipc_rfs_make_path(client, path,
                (char*) message->data + sizeof(struct ipc_rfs_get_file_info_request_header),
                header->path_len);
        if (rc < 0) {
            data.ret = -1;
            data.err = EPERM;
            goto out;
        }

        rc = stat(path, &buf);
    } else if (message->command == IPC_RFS_GET_HANDLE_INFO) {
        if (message->size < sizeof(struct ipc_rfs_get_handle_info_request_header))
            return -1;

        struct ipc_rfs_get_handle_info_request_header *header =
                (struct ipc_rfs_get_handle_info_request_header *) message->data;

        rc = fstat(header->fd, &buf);
    } else {
        ipc_client_log(client, "Unknown/unimplemented rfs command: %d", message->command);
        return -1;
    }

    if (rc < 0) {
        data.ret = rc;
        data.err = errno;
    } else {
        if (S_ISDIR(buf.st_mode)) {
            data.type = IPC_RFS_TYPE_DIRECTORY;
        } else if (S_ISREG(buf.st_mode)) {
            data.type = IPC_RFS_TYPE_FILE;
        } else {
            ipc_client_log(client, "Unknown file type, setting to 0");
            data.type = IPC_RFS_TYPE_UNKNOWN;
        }
        data.size = buf.st_size;

        // Store creation times
        localtime_r((time_t *) &buf.st_ctime, &result);
        data.c_year = (unsigned char) (result.tm_year  - 100);
        data.c_month = (unsigned char) (result.tm_mon + 1);
        data.c_day = (unsigned char) result.tm_mday;
        data.c_hour = (unsigned char) result.tm_hour;
        data.c_min = (unsigned char) result.tm_min;
        data.c_sec = (unsigned char) result.tm_sec;

        // Store modification times
        localtime_r((time_t *) &buf.st_mtime, &result);
        data.m_year = (unsigned char) (result.tm_year  - 100);
        data.m_month = (unsigned char) (result.tm_mon + 1);
        data.m_day = (unsigned char) result.tm_mday;
        data.m_hour = (unsigned char) result.tm_hour;
        data.m_min = (unsigned char) result.tm_min;
        data.m_sec = (unsigned char) result.tm_sec;
    }

out:
    rc = ipc_client_send(client, message->aseq, message->command, IPC_TYPE_RESP, (void *) &data, sizeof(data));

    return 0;
}

int ipc_rfs_handle_msg(struct ipc_client *client, struct ipc_message *message)
{
    switch(message->command)
    {
        case IPC_RFS_NV_READ_ITEM:
            return ipc_rfs_nv_read_item(client, message);
        case IPC_RFS_NV_WRITE_ITEM:
            return ipc_rfs_nv_write_item(client, message);
        case IPC_RFS_GET_FILE_INFO:
        case IPC_RFS_GET_HANDLE_INFO:
            return ipc_rfs_file_info(client, message);
        case IPC_RFS_READ_DIR:
            return ipc_rfs_read_dir(client, message);
        default:
            return ipc_rfs_generic_io(client, message);
    }
}

// vim:ts=4:sw=4:expandtab
