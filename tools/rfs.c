/*
 * This file is part of Samsung-RIL.
 *
 * Copyright (C) 2011-2014 Paul Kocialkowski <contact@paulk.fr>
 *
 * Samsung-RIL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Samsung-RIL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Samsung-RIL.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <limits.h>     /* PATH_MAX */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "rfs.h"

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
		printf("Reading %d nv_data bytes at offset 0x%x failed", data->length, data->offset);

		response_header.confirm = 0;

		rc = ipc_client_send(client, message->aseq, IPC_RFS_NV_READ_ITEM, IPC_TYPE_RESP, (void *) &response_header, sizeof(response_header));
		if (rc < 0)
			goto complete;

		goto complete;
	}

	printf("Read %d nv_data bytes at offset 0x%x", data->length, data->offset);

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
		printf("Writing %d nv_data byte(s) at offset 0x%x failed", header->length, header->offset);

		data.confirm = 0;
	} else {
		printf("Wrote %d nv_data byte(s) at offset 0x%x", header->length, header->offset);

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

	dirent = readdir(dirp);
	if (dirent == NULL) {
		len = sizeof(struct ipc_rfs_read_dir_response_header);
		buffer = alloca(len);
		if (buffer == NULL)
			return -1;
		response_header = (struct ipc_rfs_read_dir_response_header *) buffer;
		response_header->ret = -1;
		response_header->err = errno;
	} else {
		len = sizeof(struct ipc_rfs_read_dir_response_header) + strlen(dirent->d_name);
		buffer = alloca(len);
		if (buffer == NULL)
			return -1;
		response_header = (struct ipc_rfs_read_dir_response_header *) buffer;
		response_header->len = strlen(dirent->d_name);
		strcpy((char *) buffer + sizeof(struct ipc_rfs_read_dir_response_header), dirent->d_name);
	}

	rc = ipc_client_send(client, message->aseq, IPC_RFS_READ_DIR, IPC_TYPE_RESP, buffer, len);

	return 0;
}

int mkdir_p(const char *path, size_t len)
{
    /* Adapted from http://stackoverflow.com/a/2336245/119527 */
    char _path[PATH_MAX];
    char *p;

    errno = 0;

    /* Copy string so its mutable */
    if (len > sizeof(_path)-1) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strncpy(_path, path, len);

    /* Iterate the string */
    for (p = _path + 1; *p; p++) {
        if (*p == '/') {
            /* Temporarily truncate */
            *p = '\0';

            if (mkdir(_path, S_IRWXU) != 0) {
                if (errno != EEXIST)
                    return -1;
            }

            *p = '/';
        }
    }

    if (mkdir(_path, S_IRWXU) != 0) {
        if (errno != EEXIST)
            return -1;
    }

    return 0;
}

int ipc_rfs_make_path(struct ipc_client *client, char *path, char *rel_path, int rel_path_len)
{
	int rel_path_pos = 0;
	char *p;
	char *efs_root;

	if (rel_path == NULL) {
		printf("rel_path is null");
		return -1;
	}

	efs_root = ipc_client_efs_root(client);
	if (efs_root == NULL) {
		printf("Failed to read efs_root");
		return -1;
	}

	/* Combine efs_root and rel_path */
	strcpy(path, efs_root);
	strncat(path, rel_path, rel_path_len);

	/* See how many subdirectories we start in */
	p = efs_root;
	while (strstr(p, "/") != NULL) {
		p += 1;
		rel_path_pos--;
	}

	/* Count number of times we go up a directory */
	p = path;
	while (strstr(p, "/../") != NULL) {
		p += 4;
		rel_path_pos--;
	}

	/* Count number of directory separators */
	p = path;
	while (strstr(p, "/") != NULL) {
		p += 1;
		rel_path_pos++;
	}

	/* Count number of doubled directory separators */
	p = path;
	while (strstr(p, "//") != NULL) {
		p += 1;
		rel_path_pos--;
	}

	/* Make sure we're not trying to go above efs_root */
	if (rel_path_pos < 0) {
		printf("WARNING: RIL is trying to access files outside of /efs/, denying access");
		return -1;
	}

	printf("Created path %s", path);

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
				printf("alloca failed");
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
				printf("ipc_rfs_make_path failed");
				goto error;
			}

			rc = ipc_rfs_make_path(client, newpath,
					(char *) header2 + sizeof(struct ipc_rfs_rename_file_request_header),
					header2->path_len);

			if (rc < 0) {
				printf("ipc_rfs_make_path failed");
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
			if (dirp)
				data.ret = (int) dirp;
			else
				data.ret = -1;
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
				printf("Recursively creating directory and files");

				char *index = strrchr(path, '/');
				if (index != NULL)
					mkdir_p(path, index - path);
			}
			data.ret = open(path, header->flags | O_DSYNC, 0644);
			break;
		}
		default:
		{
			printf("Unknown generic IO command %d", message->command);
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
		printf("Unknown command %d for %s", message->command, __func__);
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
			printf("Unknown file type, setting to 0");
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
