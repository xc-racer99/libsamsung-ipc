/*
 * This file is part of libsamsung-ipc.
 *
 * Copyright (C) 2011 Joerie de Gram <j.de.gram@gmail.com>
 * Copyright (C) 2011 Simon Busch <morphis@gravedo.de>
 * Copyright (C) 2011 Igor Almeida <igor.contato@gmail.com>
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
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <net/if.h>

#include <samsung-ipc.h>
#include <ipc.h>

#include "onedram.h"
#include "phonet.h"

#include "xmm616.h"
#include "aries.h"

int aries_boot(struct ipc_client *client)
{
    void *modem_image_data = NULL;
    void *onedram_address = NULL;
    unsigned int onedram_init;
    unsigned int onedram_magic;
    unsigned int onedram_deinit;
    int onedram_fd = -1;
    int serial_fd = -1;
    struct timeval timeout;
    fd_set fds;
    unsigned char *p;
    unsigned char *pp;
    int rc;
    int i;

    if (client == NULL || client->handlers == NULL || client->handlers->power_on == NULL || client->handlers->power_off == NULL)
        return -1;

    ipc_client_log(client, "Starting aries modem boot");

    modem_image_data = file_data_read(ARIES_MODEM_IMAGE_DEVICE, ARIES_MODEM_IMAGE_SIZE, 0x1000, 0);
    if (modem_image_data == NULL) {
        ipc_client_log(client, "Reading modem image data failed");
        goto error;
    }
    ipc_client_log(client, "Read modem image data");

    onedram_fd = open(ARIES_ONEDRAM_DEVICE, O_RDWR);
    if (onedram_fd < 0) {
        ipc_client_log(client, "Opening onedram failed");
        goto error;
    }
    ipc_client_log(client, "Opened onedram");

    rc = network_iface_down(ARIES_MODEM_IFACE, AF_PHONET, SOCK_DGRAM);
    if (rc < 0) {
        ipc_client_log(client, "Turning modem network iface down failed");
        goto error;
    }
    ipc_client_log(client, "Turned modem network iface down");

    rc = client->handlers->power_on(client->handlers->power_data);
    if (rc < 0) {
        ipc_client_log(client, "Powering the modem off failed");
        goto error;
    }
    ipc_client_log(client, "Powered the modem off");

    usleep(1000);

    rc = client->handlers->power_off(client->handlers->power_data);
    if (rc < 0) {
        ipc_client_log(client, "Powering the modem on failed");
        goto error;
    }
    ipc_client_log(client, "Powered the modem on");

    serial_fd = open(ARIES_MODEM_SERIAL_DEVICE, O_RDWR | O_NDELAY);
    if (serial_fd < 0) {
        ipc_client_log(client, "Opening serial failed");
        goto error;
    }
    ipc_client_log(client, "Opened serial");

    usleep(100000);

    p = (unsigned char *) modem_image_data;

    rc = xmm616_psi_send(client, serial_fd, (void *) p, ARIES_PSI_SIZE);
    if (rc < 0) {
        ipc_client_log(client, "Sending XMM616 PSI failed");
        goto error;
    }
    ipc_client_log(client, "Sent XMM616 PSI");

    p += ARIES_PSI_SIZE;

    onedram_init = 0;

    FD_ZERO(&fds);
    FD_SET(onedram_fd, &fds);

    timeout.tv_sec = 4;
    timeout.tv_usec = 0;

    i = 0;
    do {
        rc = select(onedram_fd + 1, &fds, NULL, NULL, &timeout);
        if (rc <= 0) {
            ipc_client_log(client, "Reading onedram init failed");
            goto error;
        }

        rc = read(onedram_fd, &onedram_init, sizeof(onedram_init));
        if (rc < (int) sizeof(onedram_init)) {
            ipc_client_log(client, "Reading onedram init failed");
            goto error;
        }

        if (i++ > 50) {
            ipc_client_log(client, "Reading onedram init failed");
            goto error;
        }
    } while (onedram_init != ARIES_ONEDRAM_INIT);
    ipc_client_log(client, "Read onedram init (0x%x)", onedram_init);

    onedram_address = mmap(NULL, ARIES_ONEDRAM_MEMORY_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, onedram_fd, 0);
    if (onedram_address == NULL || onedram_address == (void *) 0xffffffff) {
            ipc_client_log(client, "Mapping onedram to memory failed");
            goto error;
    }
    ipc_client_log(client, "Mapped onedram to memory");

    pp = (unsigned char *) onedram_address;

    rc = xmm616_firmware_send(client, -1, (void *) pp, (void *) p, ARIES_MODEM_IMAGE_SIZE - ARIES_PSI_SIZE);
    if (rc < 0) {
        ipc_client_log(client, "Sending XMM616 firmware failed");
        goto error;
    }
    ipc_client_log(client, "Sent XMM616 firmware");

    pp = (unsigned char *) onedram_address + ARIES_ONEDRAM_NV_DATA_OFFSET;

    rc = xmm616_nv_data_send(client, -1, pp);
    if (rc < 0) {
        ipc_client_log(client, "Sending XMM616 nv_data failed");
        goto error;
    }
    ipc_client_log(client, "Sent XMM616 nv_data");

    munmap(onedram_address, ARIES_ONEDRAM_MEMORY_SIZE);
    onedram_address = NULL;

    rc = ioctl(onedram_fd, ONEDRAM_REL_SEM);
    if (rc < 0)
        goto error;

    onedram_magic = ARIES_ONEDRAM_MAGIC;
    rc = write(onedram_fd, &onedram_magic, sizeof(onedram_magic));
    if (rc < (int) sizeof(onedram_magic)) {
        ipc_client_log(client, "Writing onedram magic failed");
        goto error;
    }
    ipc_client_log(client, "Wrote onedram magic");

    FD_ZERO(&fds);
    FD_SET(onedram_fd, &fds);

    timeout.tv_sec = 4;
    timeout.tv_usec = 0;

    i = 0;
    do {
        rc = select(onedram_fd + 1, &fds, NULL, NULL, &timeout);
        if (rc <= 0) {
            ipc_client_log(client, "Reading onedram deinit failed");
            goto error;
        }

        rc = read(onedram_fd, &onedram_deinit, sizeof(onedram_deinit));
        if (rc < (int) sizeof(onedram_deinit)) {
            ipc_client_log(client, "Reading onedram deinit failed");
            goto error;
        }

        if (i++ > 50) {
            ipc_client_log(client, "Reading onedram deinit failed");
            goto error;
        }
    } while (onedram_deinit != ARIES_ONEDRAM_DEINIT);
    ipc_client_log(client, "Read onedram deinit (0x%x)", onedram_deinit);

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (modem_image_data != NULL)
        free(modem_image_data);

    if (serial_fd >= 0)
        close(serial_fd);

    if (onedram_address != NULL)
        munmap(onedram_address, ARIES_ONEDRAM_MEMORY_SIZE);

    if (onedram_fd >= 0)
        close(onedram_fd);

    return rc;
}

int aries_fmt_send(struct ipc_client *client, struct ipc_message *message)
{
    struct ipc_fmt_header header;
    void *buffer;
    size_t length;
    size_t count = 0;
    size_t chunk;
    unsigned char *p;
    int rc;

    if (client == NULL || client->handlers == NULL || client->handlers->write == NULL || message == NULL)
        return -1;

    ipc_fmt_header_setup(&header, message);

    length = header.length;
    buffer = calloc(1, length);

    memcpy(buffer, &header, sizeof(struct ipc_fmt_header));

    if (message->data != NULL && message->size > 0) {
        p = (unsigned char *) buffer + sizeof(header);
        memcpy(p, message->data, message->size);
    }

    ipc_client_log_send(client, message, __func__);

    p = (unsigned char *) buffer;

    while (count < length) {
        chunk = length - count < ARIES_BUFFER_LENGTH ? length - count : ARIES_BUFFER_LENGTH;

        rc = client->handlers->write(client->handlers->transport_data, p, chunk);
        if (rc < 0) {
            ipc_client_log(client, "Writing FMT data failed");
            goto error;
        }

        count += rc;
        p += rc;
    }

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (buffer != NULL)
        free(buffer);

    return rc;
}

int aries_fmt_recv(struct ipc_client *client, struct ipc_message *message)
{
    struct ipc_fmt_header *header;
    void *buffer;
    size_t length;
    size_t count = 0;
    size_t chunk;
    unsigned char *p;
    int rc;

    if (client == NULL || client->handlers == NULL || client->handlers->read == NULL || message == NULL)
        return -1;

    length = ARIES_BUFFER_LENGTH;
    buffer = calloc(1, length);

    rc = client->handlers->read(client->handlers->transport_data, buffer, length);
    if (rc < (int) sizeof(struct ipc_fmt_header)) {
        ipc_client_log(client, "Reading FMT header failed");
        goto error;
    }

    header = (struct ipc_fmt_header *) buffer;

    ipc_fmt_message_setup(header, message);

    length = header->length - sizeof(struct ipc_fmt_header);
    if (length > 0) {
        message->size = length;
        message->data = calloc(1, length);

        count = rc - sizeof(struct ipc_fmt_header);
        if (count > 0) {
            p = (unsigned char *) buffer + sizeof(struct ipc_fmt_header);
            memcpy(message->data, p, count);
        }
    }

    p = (unsigned char *) message->data + count;

    while (count < length) {
        chunk = length - count < ARIES_BUFFER_LENGTH ? length - count : ARIES_BUFFER_LENGTH;

        rc = client->handlers->read(client->handlers->transport_data, p, chunk);
        if (rc < 0) {
            ipc_client_log(client, "Reading FMT data failed");
            goto error;
        }

        count += rc;
        p += rc;
    }

    ipc_client_log_recv(client, message, __func__);

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (buffer != NULL)
        free(buffer);

    return rc;
}

int aries_rfs_send(struct ipc_client *client, struct ipc_message *message)
{
    struct ipc_rfs_header header;
    void *buffer;
    size_t length;
    size_t count = 0;
    size_t chunk;
    unsigned char *p;
    int rc;

    if (client == NULL || client->handlers == NULL || client->handlers->write == NULL || message == NULL)
        return -1;

    ipc_rfs_header_setup(&header, message);

    length = header.length;
    buffer = calloc(1, length);

    memcpy(buffer, &header, sizeof(header));
    if (message->data != NULL && message->size > 0) {
        p = (unsigned char *) buffer + sizeof(header);
        memcpy(p, message->data, message->size);
    }

    ipc_client_log_send(client, message, __func__);

    p = (unsigned char *) buffer;

    while (count < length) {
        chunk = length - count < ARIES_BUFFER_LENGTH ? length - count : ARIES_BUFFER_LENGTH;

        rc = client->handlers->write(client->handlers->transport_data, p, chunk);
        if (rc < 0) {
            ipc_client_log(client, "Writing RFS data failed");
            goto error;
        }

        count += rc;
        p += rc;
    }

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (buffer != NULL)
        free(buffer);

    return rc;
}

int aries_rfs_recv(struct ipc_client *client, struct ipc_message *message)
{
    struct ipc_rfs_header *header;
    void *buffer;
    size_t length;
    size_t count = 0;
    size_t chunk;
    unsigned char *p;
    int rc;

    if (client == NULL || client->handlers == NULL || client->handlers->read == NULL || message == NULL)
        return -1;

    length = ARIES_BUFFER_LENGTH;
    buffer = calloc(1, length);

    rc = client->handlers->read(client->handlers->transport_data, buffer, length);
    if (rc < (int) sizeof(struct ipc_rfs_header)) {
        ipc_client_log(client, "Reading RFS header failed");
        goto error;
    }

    header = (struct ipc_rfs_header *) buffer;
    if (header->length > ARIES_DATA_SIZE_LIMIT) {
        ipc_client_log(client, "Invalid RFS header length: %u", header->length);
        goto error;
    }

    ipc_rfs_message_setup(header, message);

    length = header->length - sizeof(struct ipc_rfs_header);
    if (length > 0) {
        message->size = length;
        message->data = calloc(1, length);

        count = rc - sizeof(struct ipc_rfs_header);
        if (count > 0) {
            p = (unsigned char *) buffer + sizeof(struct ipc_rfs_header);
            memcpy(message->data, p, count);
        }
    }

    p = (unsigned char *) message->data + count;

    while (count < length) {
        chunk = length - count < ARIES_BUFFER_LENGTH ? length - count : ARIES_BUFFER_LENGTH;

        rc = client->handlers->read(client->handlers->transport_data, p, chunk);
        if (rc < 0) {
            ipc_client_log(client, "Reading RFS data failed");
            goto error;
        }

        count += rc;
        p += rc;
    }

    ipc_client_log_recv(client, message, __func__);

    rc = 0;
    goto complete;

error:
    rc = -1;

complete:
    if (buffer != NULL)
        free(buffer);

    return rc;
}

int aries_open(void *data, int type)
{
    struct aries_transport_data *transport_data;
    struct sockaddr_pn *spn;
    struct ifreq ifr;
    int reuse;
    int socket_rfs_magic;
    int fd;
    int rc;

    if (data == NULL)
        return -1;

    transport_data = (struct aries_transport_data *) data;
    memset(data, 0, sizeof(struct aries_transport_data));

    spn = &transport_data->spn;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ARIES_MODEM_IFACE, IFNAMSIZ);

    spn->spn_family = AF_PHONET;
    spn->spn_dev = 0;

    switch (type) {
        case IPC_CLIENT_TYPE_FMT:
            spn->spn_resource = ARIES_MODEM_FMT_SPN;
            break;
        case IPC_CLIENT_TYPE_RFS:
            spn->spn_resource = ARIES_MODEM_RFS_SPN;
            break;
        default:
            break;
    }

    fd = socket(AF_PHONET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifr.ifr_name, IFNAMSIZ);
    if (rc < 0)
        return -1;

    rc = ioctl(fd, SIOCGIFINDEX, &ifr);
    if (rc < 0)
        return -1;

    reuse = 1;
    rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (rc < 0)
        return -1;

    rc = bind(fd, (const struct sockaddr *) spn, sizeof(struct sockaddr_pn));
    if (rc < 0)
        return -1;

    transport_data->fd = fd;

    if (type == IPC_CLIENT_TYPE_RFS)
    {
        socket_rfs_magic = ARIES_SOCKET_RFS_MAGIC;
        rc = setsockopt(fd, SOL_SOCKET, SO_IPC_RFS, &socket_rfs_magic, sizeof(socket_rfs_magic));
        if (rc < 0)
            return -1;
    }

    rc = network_iface_up(ARIES_MODEM_IFACE, AF_PHONET, SOCK_DGRAM);
    if (rc < 0)
        return -1;

    return 0;
}

int aries_close(void *data)
{
    struct aries_transport_data *transport_data;
    int fd;

    if (data == NULL)
        return -1;

    transport_data = (struct aries_transport_data *) data;

    fd = transport_data->fd;
    if (fd < 0)
        return -1;

    transport_data->fd = -1;
    close(fd);

    return 0;
}

int aries_read(void *data, void *buffer, size_t length)
{
    struct aries_transport_data *transport_data;
    int spn_size;
    int fd;
    int rc;

    if (data == NULL || buffer == NULL || length == 0)
        return -1;

    transport_data = (struct aries_transport_data *) data;

    fd = transport_data->fd;
    if (fd < 0)
        return -1;

    spn_size = sizeof(struct sockaddr_pn);

    rc = recvfrom(fd, buffer, length, 0, (struct sockaddr *) &transport_data->spn, &spn_size);

    return rc;
}

int aries_write(void *data, const void *buffer, size_t length)
{
    struct aries_transport_data *transport_data;
    int spn_size;
    int fd;
    int rc;

    if (data == NULL || buffer == NULL || length == 0)
        return -1;

    transport_data = (struct aries_transport_data *) data;

    fd = transport_data->fd;
    if (fd < 0)
        return -1;

    spn_size = sizeof(struct sockaddr_pn);

    rc = sendto(fd, buffer, length, 0, (const struct sockaddr *) &transport_data->spn, spn_size);

    return rc;
}

int aries_poll(void *data, struct ipc_poll_fds *fds, struct timeval *timeout)
{
    struct aries_transport_data *transport_data;
    fd_set set;
    int fd;
    int fd_max;
    unsigned int i;
    unsigned int count;
    int rc;

    if (data == NULL)
        return -1;

    transport_data = (struct aries_transport_data *) data;

    fd = transport_data->fd;
    if (fd < 0)
        return -1;

    FD_ZERO(&set);
    FD_SET(fd, &set);

    fd_max = fd;

    if (fds != NULL && fds->fds != NULL && fds->count > 0) {
        for (i = 0; i < fds->count; i++) {
            if (fds->fds[i] >= 0) {
                FD_SET(fds->fds[i], &set);

                if (fds->fds[i] > fd_max)
                    fd_max = fds->fds[i];
            }
        }
    }

    rc = select(fd_max + 1, &set, NULL, NULL, timeout);

    if (fds != NULL && fds->fds != NULL && fds->count > 0) {
        count = fds->count;

        for (i = 0; i < fds->count; i++) {
            if (!FD_ISSET(fds->fds[i], &set)) {
                fds->fds[i] = -1;
                count--;
            }
        }

        fds->count = count;
    }

    return rc;
}

int aries_power_on(void *data)
{
    char buffer[] = "on\n";
    int value;
    int rc;

    value = sysfs_value_read(ARIES_MODEMCTL_STATUS_SYSFS);
    if (value < 0)
        return -1;

    // The modem is already on
    if (value == 1)
        return 0;

    rc = sysfs_string_write(ARIES_MODEMCTL_CONTROL_SYSFS, (char *) &buffer, strlen(buffer));
    if (rc < 0)
        return -1;

    return 0;
}

int aries_power_off(void *data)
{
    char buffer[] = "off\n";
    int value;
    int rc;

    value = sysfs_value_read(ARIES_MODEMCTL_STATUS_SYSFS);
    if (value < 0)
        return -1;

    // The modem is already off
    if (value == 0)
        return 0;

    rc = sysfs_string_write(ARIES_MODEMCTL_CONTROL_SYSFS, (char *) &buffer, strlen(buffer));
    if (rc < 0)
        return -1;

    return 0;
}

int aries_data_create(void **transport_data, void **power_data,
    void **gprs_data)
{
    if (transport_data == NULL)
        return -1;

    *transport_data = calloc(1, sizeof(struct aries_transport_data));

    return 0;
}

int aries_data_destroy(void *transport_data, void *power_data, void *gprs_data)
{
    if (transport_data == NULL)
        return -1;

    free(transport_data);

    return 0;
}

int aries_gprs_activate(void *data, unsigned int cid)
{
    int rc;

    rc = sysfs_value_write(ARIES_MODEM_PDP_ACTIVATE_SYSFS, cid);
    if (rc < 0)
        return -1;

    return 0;
}

int aries_gprs_deactivate(void *data, unsigned int cid)
{
    int rc;

    rc = sysfs_value_write(ARIES_MODEM_PDP_DEACTIVATE_SYSFS, cid);
    if (rc < 0)
        return -1;

    return 0;
}

char *aries_gprs_get_iface(unsigned int cid)
{
    char *iface = NULL;

    if (cid > ARIES_GPRS_IFACE_COUNT)
        return NULL;

    asprintf(&iface, "%s%d", ARIES_GPRS_IFACE_PREFIX, cid - 1);

    return iface;
}

int aries_gprs_get_capabilities(struct ipc_client_gprs_capabilities *capabilities)
{
    if (capabilities == NULL)
        return -1;

    capabilities->cid_count = ARIES_GPRS_IFACE_COUNT;

    return 0;
}

struct ipc_client_ops aries_fmt_ops = {
    .boot = aries_boot,
    .send = aries_fmt_send,
    .recv = aries_fmt_recv,
};

struct ipc_client_ops aries_rfs_ops = {
    .boot = NULL,
    .send = aries_rfs_send,
    .recv = aries_rfs_recv,
};

struct ipc_client_handlers aries_handlers = {
    .open = aries_open,
    .close = aries_close,
    .read = aries_read,
    .write = aries_write,
    .poll = aries_poll,
    .transport_data = NULL,
    .power_on = aries_power_on,
    .power_off = aries_power_off,
    .power_data = NULL,
    .gprs_activate = aries_gprs_activate,
    .gprs_deactivate = aries_gprs_deactivate,
    .gprs_data = NULL,
    .data_create = aries_data_create,
    .data_destroy = aries_data_destroy,
};

struct ipc_client_gprs_specs aries_gprs_specs = {
    .gprs_get_iface = aries_gprs_get_iface,
    .gprs_get_capabilities = aries_gprs_get_capabilities,
};

struct ipc_client_nv_data_specs aries_nv_data_specs = {
    .nv_data_path = XMM616_NV_DATA_PATH,
    .nv_data_md5_path = XMM616_NV_DATA_MD5_PATH,
    .nv_data_backup_path = XMM616_NV_DATA_BACKUP_PATH,
    .nv_data_backup_md5_path = XMM616_NV_DATA_BACKUP_MD5_PATH,
    .nv_data_secret = XMM616_NV_DATA_SECRET,
    .nv_data_size = XMM616_NV_DATA_SIZE,
    .nv_data_chunk_size = XMM616_NV_DATA_CHUNK_SIZE,
};

// vim:ts=4:sw=4:expandtab
