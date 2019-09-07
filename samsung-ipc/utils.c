/*
 * This file is part of libsamsung-ipc.
 *
 * Copyright (C) 2013-2014 Paul Kocialkowski <contact@paulk.fr>
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
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <net/if.h>


void *file_data_read(const char *path, size_t size, size_t chunk_size,
    unsigned int offset)
{
    void *data = NULL;
    int fd = -1;
    size_t count;
    off_t seek;
    unsigned char *p;
    int rc;

    if (path == NULL || size == 0 || chunk_size == 0 || chunk_size > size)
        return NULL;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        goto error;

    seek = lseek(fd, (off_t) offset, SEEK_SET);
    if (seek < (off_t) offset)
        goto error;

    data = calloc(1, size);

    p = (unsigned char *) data;

    count = 0;
    while (count < size) {
        rc = read(fd, p, size - count > chunk_size ? chunk_size : size - count);
        if (rc <= 0)
            goto error;

        p += rc;
        count += rc;
    }

    goto complete;

error:
    if (data != NULL) {
        free(data);
        data = NULL;
    }

complete:
    if (fd >= 0)
        close(fd);

    return data;
}

int file_data_write(const char *path, const void *data, size_t size,
    size_t chunk_size, unsigned int offset)
{
    int fd = -1;
    size_t count;
    off_t seek;
    unsigned char *p;
    int rc;

    if (path == NULL || data == NULL || size == 0 || chunk_size == 0 || chunk_size > size)
        return -1;

    fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0)
        goto error;

    seek = lseek(fd, (off_t) offset, SEEK_SET);
    if (seek < (off_t) offset)
        goto error;

    p = (unsigned char *) data;

    count = 0;
    while (count < size) {
        rc = write(fd, p, size - count > chunk_size ? chunk_size : size - count);
        if (rc <= 0)
            goto error;

        p += rc;
        count += rc;
    }

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (fd >= 0)
        close(fd);

    return rc;
}

int network_iface_up(const char *iface, int domain, int type)
{
    struct ifreq ifr;
    int fd = -1;
    int rc;

    if (iface == NULL)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);

    fd = socket(domain, type, 0);
    if (fd < 0)
        goto error;

    rc = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (rc < 0)
        goto error;

    ifr.ifr_flags |= IFF_UP;

    rc = ioctl(fd, SIOCSIFFLAGS, &ifr);
    if (rc < 0)
        goto error;

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (fd >= 0)
        close(fd);

    return rc;
}

int network_iface_down(const char *iface, int domain, int type)
{
    struct ifreq ifr;
    int fd = -1;
    int rc;

    if (iface == NULL)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);

    fd = socket(domain, type, 0);
    if (fd < 0)
        goto error;

    rc = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (rc < 0)
        goto error;

    ifr.ifr_flags = (ifr.ifr_flags & (~IFF_UP));

    rc = ioctl(fd, SIOCSIFFLAGS, &ifr);
    if (rc < 0)
        goto error;

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (fd >= 0)
        close(fd);

    return rc;
}

int sysfs_value_read(const char *path)
{
    char buffer[100];
    int value;
    int fd = -1;
    int rc;

    if (path == NULL)
        return -1;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        goto error;

    rc = read(fd, &buffer, sizeof(buffer));
    if (rc <= 0)
        goto error;

    value = atoi(buffer);
    goto complete;

error:
    value = -1;

complete:
    if (fd >= 0)
        close(fd);

    return value;
}

int sysfs_value_write(const char *path, int value)
{
    char buffer[100];
    int fd = -1;
    int rc;

    if (path == NULL)
        return -1;

    fd = open(path, O_WRONLY);
    if (fd < 0)
        goto error;

    snprintf((char *) &buffer, sizeof(buffer), "%d\n", value);

    rc = write(fd, buffer, strlen(buffer));
    if (rc < (int) strlen(buffer))
        goto error;

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (fd >= 0)
        close(fd);

    return rc;
}

char *sysfs_string_read(const char *path, size_t length)
{
    char *string = NULL;
    int fd = -1;
    int rc;

    if (path == NULL || length == 0)
        return NULL;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        goto error;

    string = (char *) calloc(1, length);

    rc = read(fd, string, length);
    if (rc <= 0)
        goto error;

    goto complete;

error:
    if (string != NULL) {
        free(string);
        string = NULL;
    }

complete:
    if (fd >= 0)
        close(fd);

    return string;
}

int sysfs_string_write(const char *path, const char *buffer, size_t length)
{
    int fd = -1;
    int rc;

    if (path == NULL || buffer == NULL || length == 0)
        return -1;

    fd = open(path, O_WRONLY);
    if (fd < 0)
        goto error;

    rc = write(fd, buffer, length);
    if (rc < (int) length)
        goto error;

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (fd >= 0)
        close(fd);

    return rc;
}

size_t data2string_length(const void *data, size_t size)
{
    size_t length;

    if (data == NULL || size == 0)
        return 0;

    length = size * 2 + 1;

    return length;
}

char *data2string(const void *data, size_t size)
{
    char *string;
    size_t length;
    char *p;
    size_t i;

    if (data == NULL || size == 0)
        return NULL;

    length = data2string_length(data, size);
    if (length == 0)
        return NULL;

    string = (char *) calloc(1, length);

    p = string;

    for (i = 0; i < size; i++) {
        sprintf(p, "%02x", *((unsigned char *) data + i));
        p += 2 * sizeof(char);
    }

    return string;
}

size_t string2data_size(const char *string)
{
    size_t length;
    size_t size;

    if (string == NULL)
        return 0;

    length = strlen(string);
    if (length == 0)
        return 0;

    if (length % 2 == 0)
        size = length / 2;
    else
        size = (length - (length % 2)) / 2 + 1;

    return size;
}

void *string2data(const char *string)
{
    void *data;
    size_t size;
    size_t length;
    int shift;
    unsigned char *p;
    unsigned int b;
    size_t i;
    int rc;

    if (string == NULL)
        return NULL;

    length = strlen(string);
    if (length == 0)
        return NULL;

    if (length % 2 == 0)
        shift = 0;
    else
        shift = 1;

    size = string2data_size(string);
    if (size == 0)
        return NULL;

    data = calloc(1, size);

    p = (unsigned char *) data;

    for (i = 0; i < length; i++) {
        rc = sscanf(&string[i], "%01x", &b);
        if (rc < 1)
            b = 0;

        if ((shift % 2) == 0)
            *p |= ((b & 0x0f) << 4);
        else
            *p++ |= b & 0x0f;

        shift++;
    }

    return data;
}

unsigned short crc16_xmodem(unsigned char *ptr, int count)
{
   int  crc;
   char i;
   crc = 0;
   while (--count >= 0)
   {
      crc = crc ^ (int) *ptr++ << 8;
      i = 8;
      do
      {
         if (crc & 0x8000)
            crc = crc << 1 ^ 0x1021;
         else
            crc = crc << 1;
      } while(--i);
   }
   return (crc);
}

// vim:ts=4:sw=4:expandtab
