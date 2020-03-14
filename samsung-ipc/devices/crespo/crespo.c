/*
 * This file is part of libsamsung-ipc.
 *
 * Copyright (C) 2011 Joerie de Gram <j.de.gram@gmail.com>
 * Copyright (C) 2011 Simon Busch <morphis@gravedo.de>
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
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <poll.h>

#include <samsung-ipc.h>
#include <ipc.h>

#include "crespo_modem_ctl.h"

#include "xmm626.h"
#include "xmm626_hsic.h"
#include "xmm626_sec_modem.h"
#include "xmm616.h"
#include "ste_m5730.h"
#include "crespo.h"

int crespo_xmm_boot(struct ipc_client *client)
{
    void *modem_image_data = NULL;
    int modem_ctl_fd = -1;
    int serial_fd = -1;
    char *compat;
    char modem_path[100];
    unsigned char *p;
    int rc;

    if (client == NULL)
        return -1;

    ipc_client_log(client, "Starting crespo modem boot");

    /*
     * Try the DT path first, then try the generic modem.bin, then the MTD
     * path as the MTD path may exist even when it's not actually the modem.
     */
    compat = sysfs_string_read("/proc/device-tree/compatible", PATH_MAX);
    if (compat != NULL && strlen(compat) > 0) {
        rc = sprintf(modem_path, "/radio/modem.bin,%s", compat);
        free(compat);

        if (rc <= 0) {
            ipc_client_log(client, "Failed to create modem.bin path");
            return -1;
        }

        modem_image_data = file_data_read(modem_path, CRESPO_XMM_MODEM_IMAGE_SIZE, 0x1000, 0);
    }

    if (modem_image_data == NULL)
        modem_image_data = file_data_read(CRESPO_MODEM_BIN_PATH, CRESPO_XMM_MODEM_IMAGE_SIZE, 0x1000, 0);
    if (modem_image_data == NULL)
        modem_image_data = file_data_read(CRESPO_MODEM_IMAGE_DEVICE, CRESPO_XMM_MODEM_IMAGE_SIZE, 0x1000, 0);

    if (modem_image_data == NULL) {
        ipc_client_log(client, "Reading modem image data failed");
        goto error;
    }
    ipc_client_log(client, "Read modem image data");

    modem_ctl_fd = open(CRESPO_MODEM_CTL_DEVICE, O_RDWR | O_NDELAY);
    if (modem_ctl_fd < 0) {
        ipc_client_log(client, "Opening modem ctl failed");
        goto error;
    }
    ipc_client_log(client, "Opened modem ctl");

    rc = ioctl(modem_ctl_fd, IOCTL_MODEM_RESET);
    if (rc < 0) {
        ipc_client_log(client, "Resetting modem failed");
        goto error;
    }
    ipc_client_log(client, "Reset modem");

    serial_fd = open(CRESPO_MODEM_SERIAL_DEVICE, O_RDWR | O_NDELAY);
    if (serial_fd < 0 && errno == ENOENT)
        serial_fd = open(CRESPO_ALT_MODEM_SERIAL_DEVICE, O_RDWR | O_NDELAY);

    if (serial_fd < 0) {
        ipc_client_log(client, "Opening serial failed");
        goto error;
    }
    ipc_client_log(client, "Opened serial");

    usleep(100000);

    p = (unsigned char *) modem_image_data;

    rc = xmm616_psi_send(client, serial_fd, (void *) p, CRESPO_PSI_SIZE);
    if (rc < 0) {
        ipc_client_log(client, "Sending XMM616 PSI failed");
        goto error;
    }
    ipc_client_log(client, "Sent XMM616 PSI");

    p += CRESPO_PSI_SIZE;

    lseek(modem_ctl_fd, 0, SEEK_SET);

    rc = xmm616_firmware_send(client, modem_ctl_fd, NULL, (void *) p, CRESPO_XMM_MODEM_IMAGE_SIZE - CRESPO_PSI_SIZE);
    if (rc < 0) {
        ipc_client_log(client, "Sending XMM616 firmware failed");
        goto error;
    }
    ipc_client_log(client, "Sent XMM616 firmware");

    lseek(modem_ctl_fd, CRESPO_MODEM_CTL_NV_DATA_OFFSET, SEEK_SET);

    rc = xmm616_nv_data_send(client, modem_ctl_fd, NULL);
    if (rc < 0) {
        ipc_client_log(client, "Sending XMM616 nv_data failed");
        goto error;
    }
    ipc_client_log(client, "Sent XMM616 nv_data");

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (modem_image_data != NULL)
        free(modem_image_data);

    if (serial_fd >= 0)
        close(serial_fd);

    if (modem_ctl_fd >= 0)
        close(modem_ctl_fd);

    return rc;
}

int crespo_boot(struct ipc_client *client)
{
    int rc;

    if (crespo_is_ste()) {
        ipc_client_log(client, "Detected an STE M5730 modem");
        rc = crespo_ste_boot(client);
    } else {
        ipc_client_log(client, "Detected an XMM6160 modem");
        rc = crespo_xmm_boot(client);
    }

    return rc;
}

int crespo_open(void *data, int type)
{
    struct crespo_transport_data *transport_data;
    int fd;

    if (data == NULL)
        return -1;

    transport_data = (struct crespo_transport_data *) data;

    transport_data->fd = xmm626_sec_modem_open(type);
    if (transport_data->fd < 0)
        return -1;

    return 0;
}

int crespo_close(void *data)
{
    struct crespo_transport_data *transport_data;
    int fd;

    if (data == NULL)
        return -1;

    transport_data = (struct crespo_transport_data *) data;

    xmm626_sec_modem_close(transport_data->fd);
    transport_data->fd = -1;

    return 0;
}

int crespo_read(void *data, void *buffer, size_t length)
{
    struct crespo_transport_data *transport_data;
    int rc;

    if (data == NULL)
        return -1;

    transport_data = (struct crespo_transport_data *) data;

    rc = xmm626_sec_modem_read(transport_data->fd, buffer, length);

    return rc;
}

int crespo_write(void *data, const void *buffer, size_t length)
{
    struct crespo_transport_data *transport_data;
    int rc;

    if (data == NULL)
        return -1;

    transport_data = (struct crespo_transport_data *) data;

    rc = xmm626_sec_modem_write(transport_data->fd, buffer, length);

    return rc;
}

int crespo_poll(void *data, struct ipc_poll_fds *fds, struct timeval *timeout)
{
    struct crespo_transport_data *transport_data;
    int rc;
    struct pollfd fd;

    if (data == NULL)
        return -1;

    transport_data = (struct crespo_transport_data *) data;

    fd.fd = transport_data->fd;
    fd.events = POLLRDNORM | POLLIN;

    if (timeout) {
        rc = poll(&fd, 1, timeout->tv_sec * 1000);
    } else {
        rc = poll(&fd, 1, -1);
    }

    return rc - 1;
}

int crespo_xmm_power_on()
{
    int fd;
    int rc;

    fd = open(CRESPO_MODEM_CTL_DEVICE, O_RDWR);
    if (fd < 0)
        return -1;

    rc = ioctl(fd, IOCTL_MODEM_START);

    close(fd);

    if (rc < 0)
        return -1;

    return 0;
}

int crespo_power_on(__attribute__((unused)) void *data)
{
    if (crespo_is_ste())
        return crespo_ste_power_on();

    return crespo_xmm_power_on();
}

int crespo_power_off(__attribute__((unused)) void *data)
{
    int fd;
    int rc;

    fd = open(CRESPO_MODEM_CTL_DEVICE, O_RDWR);
    if (fd < 0)
        return -1;

    rc = ioctl(fd, IOCTL_MODEM_OFF);

    close(fd);

    if (rc < 0)
        return -1;

    return 0;
}

int crespo_data_create(void **transport_data,
		       __attribute__((unused)) void **power_data,
		       __attribute__((unused)) void **gprs_data)
{
    if (transport_data == NULL)
        return -1;

    *transport_data = calloc(1, sizeof(struct crespo_transport_data));

    return 0;
}

int crespo_data_destroy(void *transport_data,
			__attribute__((unused)) void *power_data,
			__attribute__((unused)) void *gprs_data)
{
    if (transport_data == NULL)
        return -1;

    free(transport_data);

    return 0;
}

int crespo_gprs_activate(__attribute__((unused)) void *data,
			 __attribute__((unused)) unsigned int cid)
{
    return 0;
}

int crespo_gprs_deactivate(__attribute__((unused)) void *data,
			   __attribute__((unused)) unsigned int cid)
{
    return 0;
}

char *crespo_gprs_get_iface_single(__attribute__((unused)) unsigned int cid)
{
    char *iface = NULL;

    asprintf(&iface, "%s%d", CRESPO_GPRS_IFACE_PREFIX, 0);

    return iface;
}

int crespo_gprs_get_capabilities_single(struct ipc_client_gprs_capabilities *capabilities)
{
    if (capabilities == NULL)
        return -1;

    capabilities->cid_count = 1;

    return 0;
}

char *crespo_gprs_get_iface(unsigned int cid)
{
    char *iface = NULL;

    if (cid > CRESPO_GPRS_IFACE_COUNT)
        return NULL;

    asprintf(&iface, "%s%d", CRESPO_GPRS_IFACE_PREFIX, cid - 1);

    return iface;
}

int crespo_gprs_get_capabilities(struct ipc_client_gprs_capabilities *capabilities)
{
    if (capabilities == NULL)
        return -1;

    capabilities->cid_count = CRESPO_GPRS_IFACE_COUNT;

    return 0;
}

struct ipc_client_ops crespo_fmt_ops = {
    .boot = crespo_boot,
    .send = xmm626_sec_modem_fmt_send,
    .recv = xmm626_sec_modem_fmt_recv,
};

struct ipc_client_ops crespo_rfs_ops = {
    .boot = NULL,
    .send = xmm626_sec_modem_rfs_send,
    .recv = xmm626_sec_modem_rfs_recv,
};

struct ipc_client_handlers crespo_handlers = {
    .open = crespo_open,
    .close = crespo_close,
    .read = crespo_read,
    .write = crespo_write,
    .poll = crespo_poll,
    .transport_data = NULL,
    .power_on = crespo_power_on,
    .power_off = crespo_power_off,
    .power_data = NULL,
    .gprs_activate = crespo_gprs_activate,
    .gprs_deactivate = crespo_gprs_deactivate,
    .gprs_data = NULL,
    .data_create = crespo_data_create,
    .data_destroy = crespo_data_destroy,
};

struct ipc_client_gprs_specs crespo_gprs_specs_single = {
    .gprs_get_iface = crespo_gprs_get_iface_single,
    .gprs_get_capabilities = crespo_gprs_get_capabilities_single,
};

struct ipc_client_gprs_specs crespo_gprs_specs = {
    .gprs_get_iface = crespo_gprs_get_iface,
    .gprs_get_capabilities = crespo_gprs_get_capabilities,
};

struct ipc_client_nv_data_specs crespo_nv_data_specs = {
    .efs_root = CRESPO_EFS_ROOT,
    .nv_data_path = XMM616_NV_DATA_PATH,
    .nv_data_md5_path = XMM616_NV_DATA_MD5_PATH,
    .nv_data_backup_path = XMM616_NV_DATA_BACKUP_PATH,
    .nv_data_backup_md5_path = XMM616_NV_DATA_BACKUP_MD5_PATH,
    .nv_data_secret = XMM616_NV_DATA_SECRET,
    .nv_data_size = XMM616_NV_DATA_SIZE,
    .nv_data_chunk_size = XMM616_NV_DATA_CHUNK_SIZE,
};

// vim:ts=4:sw=4:expandtab
