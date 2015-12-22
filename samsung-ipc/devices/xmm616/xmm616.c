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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <sys/select.h>

#include <samsung-ipc.h>

#include "xmm616.h"

int xmm616_psi_send(struct ipc_client *client, int serial_fd,
    const void *psi_data, unsigned short psi_size)
{
    char at[] = XMM616_AT;
    unsigned char version;
    unsigned char info;
    unsigned char psi_magic;
    unsigned char psi_crc;
    unsigned char psi_ack;
    struct termios termios;
    struct timeval timeout;
    fd_set fds;
    size_t length;
    unsigned char *p;
    int rc;
    int i;

    if (client == NULL || serial_fd < 0 || psi_data == NULL || psi_size == 0)
        return -1;

    tcgetattr(serial_fd, &termios);

    cfmakeraw(&termios);
    cfsetispeed(&termios, B115200);
    cfsetospeed(&termios, B115200);

    tcsetattr(serial_fd, TCSANOW, &termios);

    length = strlen(at);
    for (i = 0; i < XMM616_AT_COUNT; i++) {
        rc = write(serial_fd, at, length);
        if (rc < (int) length) {
            ipc_client_log(client, "Writing AT in ASCII failed");
            goto error;
        }

        usleep(50000);
    }
    ipc_client_log(client, "Wrote AT in ASCII");

    usleep(50000);

    version = 0;

    rc = read(serial_fd, &version, sizeof(version));
    if (rc < (int) sizeof(version)) {
        ipc_client_log(client, "Reading bootcore version failed");
        goto error;
    }

    if (version != XMM616_BOOTCORE_VERSION) {
        ipc_client_log(client, "Read wrong bootcore version (0x%x)", version);
        goto error;
    }

    ipc_client_log(client, "Read bootcore version (0x%x)", version);

    rc = read(serial_fd, &info, sizeof(info));
    if (rc < (int) sizeof(info)) {
        ipc_client_log(client, "Reading info size failed");
        goto error;
    }
    ipc_client_log(client, "Read info size (0x%x)", info);

    psi_magic = XMM616_PSI_MAGIC;

    rc = write(serial_fd, &psi_magic, sizeof(psi_magic));
    if (rc < (int) sizeof(psi_magic)) {
        ipc_client_log(client, "Writing PSI magic failed");
        goto error;
    }
    ipc_client_log(client, "Wrote PSI magic (0x%x)", psi_magic);

    rc = write(serial_fd, &psi_size, sizeof(psi_size));
    if (rc < (int) sizeof(psi_size)) {
        ipc_client_log(client, "Writing PSI size failed");
        goto error;
    }
    ipc_client_log(client, "Wrote PSI size (0x%x)", psi_size);

    FD_ZERO(&fds);
    FD_SET(serial_fd, &fds);

    timeout.tv_sec = 4;
    timeout.tv_usec = 0;

    p = (unsigned char *) psi_data;
    psi_crc = 0;

    for (i = 0; i < psi_size; i++) {
        rc = select(serial_fd + 1, NULL, &fds, NULL, &timeout);
        if (rc <= 0) {
            ipc_client_log(client, "Writing PSI failed");
            goto error;
        }

        rc = write(serial_fd, p, 1);
        if (rc < 1) {
            ipc_client_log(client, "Writing PSI failed");
            goto error;
        }

        psi_crc ^= *p++;
    }
    ipc_client_log(client, "Wrote PSI, CRC is 0x%x", psi_crc);

    rc = select(serial_fd + 1, NULL, &fds, NULL, &timeout);
    if (rc <= 0) {
        ipc_client_log(client, "Writing PSI crc failed");
        goto error;
    }

    rc = write(serial_fd, &psi_crc, sizeof(psi_crc));
    if (rc < (int) sizeof(psi_crc)) {
        ipc_client_log(client, "Writing PSI crc failed");
        goto error;
    }
    ipc_client_log(client, "Wrote PSI CRC (0x%x)", psi_crc);

    timeout.tv_sec = 4;
    timeout.tv_usec = 0;

    i = 0;
    do {
        rc = select(serial_fd + 1, &fds, NULL, NULL, &timeout);
        if (rc <= 0) {
            ipc_client_log(client, "Reading PSI ACK failed");
            goto error;
        }

        rc = read(serial_fd, &psi_ack, sizeof(psi_ack));
        if (rc < (int) sizeof(psi_ack)) {
            ipc_client_log(client, "Reading PSI ACK failed");
            goto error;
        }

        if (i++ > 50) {
            ipc_client_log(client, "Reading PSI ACK failed");
            goto error;
        }
    } while (psi_ack != XMM616_PSI_ACK);
    ipc_client_log(client, "Read PSI ACK (0x%x)", psi_ack);

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    return rc;
}

int xmm616_firmware_send(struct ipc_client *client, int device_fd,
    void *device_address, const void *firmware_data, size_t firmware_size)
{
    size_t wc;
    unsigned char *p;
    int rc;
    int i;

    if (client == NULL || (device_fd < 0 && device_address == NULL) || firmware_data == NULL || firmware_size == 0)
        return -1;

    p = (unsigned char *) firmware_data;

    if (device_address != NULL) {
        memcpy(device_address, (void *) p, firmware_size);
    } else {
        wc = 0;
        while (wc < firmware_size) {
            rc = write(device_fd, (void *) p, firmware_size - wc);
            if (rc <= 0) {
                ipc_client_log(client, "Writing firmware failed");
                goto error;
            }

            p += rc;
            wc += rc;
        }
    }
    ipc_client_log(client, "Wrote firmware");

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    return rc;
}

int xmm616_nv_data_send(struct ipc_client *client, int device_fd,
    void *device_address)
{
    void *nv_data = NULL;
    size_t nv_size;
    size_t wc;
    unsigned char *p;
    int rc;

    if (client == NULL || (device_fd < 0 && device_address == NULL))
        return -1;

    nv_size = ipc_client_nv_data_size(client);
    if (nv_size == 0)
        return -1;

    nv_data = ipc_nv_data_load(client);
    if (nv_data == NULL) {
        ipc_client_log(client, "Loading nv_data failed");
        goto error;
    }
    ipc_client_log(client, "Loaded nv_data");

    p = (unsigned char *) nv_data;

    if (device_address != NULL) {
        memcpy(device_address, p, nv_size);
    } else {
        wc = 0;
        while (wc < nv_size) {
            rc = write(device_fd, p, nv_size - wc);
            if (rc <= 0) {
                ipc_client_log(client, "Writing modem image failed");
                goto error;
            }

            p += rc;
            wc += rc;
        }
    }

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (nv_data != NULL)
        free(nv_data);

    return rc;
}

// vim:ts=4:sw=4:expandtab
