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
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>

#include <samsung-ipc.h>
#include <ipc.h>

#include "crespo_modem_ctl.h"

#include "xmm616.h"
#include "ste_m5730.h"
#include "crespo.h"

const char* const send_protroms[] = {
    "\x64",
    "\x64\x88\x01",
    "\x64\x88\x01\x04",
    "\x04\x00",
};

int crespo_is_ste(void)
{
    char buf[10];
    int fd, rc;

    fd = open(CRESPO_MODEM_TYPE_SYSFS, O_RDONLY);
    if (fd < 0)
        return 0;

    rc = read(fd, buf, 10);
    if (!strncmp(buf, "ste", 3))
        rc = 1;
    else
        rc = 0;

    close(fd);

    return rc;
}

int m5730_write_baud_change(struct ipc_client *client, int serial_fd)
{
    struct timeval time;
    fd_set fds;
    unsigned char buf[8];
    int rc;
    int i;

    usleep(110000);

start_z_protocol:
    /* Flush serial */
    ioctl(serial_fd, TCFLSH, TCIOFLUSH);

    /* Write b */
    rc = write(serial_fd, "b", 1);
    if (rc != 1) {
        ipc_client_log(client, "Failed to write b");
        return -1;
    }
    ipc_client_log(client, "Wrote b");

    usleep(50000);

    FD_ZERO(&fds);
    FD_SET(serial_fd, &fds);

    time.tv_sec = 60;
    time.tv_usec = 0;

    rc = select(serial_fd + 1, &fds, NULL, NULL, &time);
    if (rc < 0) {
        ipc_client_log(client, "Select encountered an error");
        return -1;
    }
    if (!FD_ISSET(serial_fd, &fds)) {
        ipc_client_log(client, "Nothing to read!");
        return -1;
    }

    rc = read(serial_fd, buf, sizeof(buf));
    if (rc == 1) {
        /* If it's a z, resend b */
        if (buf[0] == 'z')
            goto start_z_protocol;

        ipc_client_log(client, "Read unkown byte %c", buf[0]);
        return -1;
    } else if (rc != 8) {
        ipc_client_log(client, "Didn't read 8 bytes, read %d bytes instead", rc);
        return -1;
    }

    /* Just some debugging */
    for (i = 0; i < rc; i++) {
        ipc_client_log(client, "Buf[%d] = 0x%x", i, buf[i]);
    }

    /* Write S4 to change UART speed */
    rc = write(serial_fd, "S4", 2);
    if (rc != 2) {
        ipc_client_log(client, "Failed to write S4 to change speed");
        return -1;
    }

    ioctl(serial_fd, TCFLSH, TCIOFLUSH);

    return 0;
}

int m5730_receive_protrom(int fd)
{
    int rc;
    int i;
    unsigned int ack;
    unsigned char data[32];
    fd_set fds;
    struct timeval time;

    ack = SERIAL_ACK;

    time.tv_sec = 2;
    time.tv_usec = 0;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    rc = select(fd + 1, &fds, NULL, NULL, &time);

    if (rc < 0)
        return rc;

    if (!FD_ISSET(fd, &fds))
        return -1;

    rc = read(fd, data, sizeof(data));
    if (rc <= 0)
        return -1;

    for (i = 0; i < rc; i++) {
        if (memcmp(data + i, &ack, sizeof(ack)) == 0)
            return 0;
    }

    /* Couldn't find ack */
    return -1;
}

int m5730_send_protrom(int fd, int n)
{
    int rc;
    unsigned short xmodem_crc;
    unsigned int ack;
    unsigned short protrom_len = sizeof(send_protroms[n]);
    size_t total_len = sizeof(ack) + 1 + sizeof(protrom_len) + protrom_len + sizeof(xmodem_crc);
    unsigned char *buf;

    buf = calloc(1, total_len);
    if (buf == NULL)
        return -1;

    ack = SERIAL_ACK;

    memcpy(buf, &ack, sizeof(ack));
    memcpy(buf + sizeof(ack) + 1, &protrom_len, sizeof(protrom_len));
    memcpy(buf + sizeof(ack) + 1 + sizeof(protrom_len), send_protroms[n], protrom_len);

    /* Calculate and copy CRC */
    xmodem_crc = crc16_xmodem(buf, total_len - 2);
    memcpy(buf + sizeof(ack) + 1 + sizeof(protrom_len) + protrom_len, &xmodem_crc, sizeof(xmodem_crc));

    rc = write(fd, buf, total_len);

    free(buf);

    return rc < 0 ? -1 : 0;
}

int m5730_connect_ccpu(struct ipc_client *client, int serial_fd)
{
    int i;
    int rc;

    usleep(50000);

    /* Send R to quit z-protocol */
    rc = write(serial_fd, "R", 1);
    if (rc != 1) {
        ipc_client_log(client, "Failed to send R to quit z-protocol");
        return -1;
    }
    ipc_client_log(client, "Sent R to quit z-protocol");

    /* Receive/send protrom */
    for (i = 0; i < 4; i++) {
        rc = m5730_receive_protrom(serial_fd);
        if (rc) {
            ipc_client_log(client, "Failed to receive protrom, %d", rc);
            return -1;
        }

        rc = m5730_send_protrom(serial_fd, i);
        if (rc < 0) {
            ipc_client_log(client, "Failed to send protrom #%d", i);
            return -1;
        }

        usleep(50000);
        ipc_client_log(client, "Sent protrom #%d", i);
    }

    return 0;
}

int ste_load_modem_serial_part(int serial_fd, struct crespo_modem_data_header header, int modem_fd)
{
    int rc;
    unsigned short xmodem_crc;
    unsigned char *buf;

    buf = malloc(sizeof(header) + header.len - 1 + sizeof(xmodem_crc));
    if (buf == NULL)
        return -1;

    memcpy(buf, &header, sizeof(header));
    rc = read(modem_fd, buf + sizeof(header), header.len - 1);
    if (rc != header.len - 1)
        goto error;

    xmodem_crc = crc16_xmodem(buf, sizeof(header) + header.len - 1);
    memcpy(buf + sizeof(header) + header.len - 1, &xmodem_crc, sizeof(xmodem_crc));

    rc = write(serial_fd, buf, sizeof(header) + header.len - 1 + sizeof(xmodem_crc));
    if (rc < 0)
        goto error;

    free(buf);
    return 0;

error:
    if (buf != NULL)
        free(buf);
    return -1;
}

int ste_load_modem_serial(struct ipc_client *client, int serial_fd)
{
    struct crespo_modem_data_header header;
    char *compat;
    char modem_path[100];
    int modem_fd;
    int rc;

    /* First look for a DT version */
    compat = sysfs_string_read("/proc/device-tree/compatible", PATH_MAX);
    if (compat != NULL && strlen(compat) > 0) {
        rc = sprintf(modem_path, "/radio/modem.bin,%s", compat);
        free (compat);

        if (rc <= 0) {
            ipc_client_log(client, "Failed to create modem.bin path");
            return -1;
        }

        modem_fd = open(modem_path, O_RDONLY);
        if (modem_fd < 0) {
            ipc_client_log(client, "Failed to open %s", modem_path);
        } else {
            ipc_client_log(client, "Succesfully opened %s", modem_path);
            goto modem_opened;
        }
    }

    /* Then fall back to generic modem.bin */
    modem_fd = open(CRESPO_MODEM_BIN_PATH, O_RDONLY);
    if (modem_fd < 0) {
        ipc_client_log(client, "Failed to open %s", CRESPO_MODEM_BIN_PATH);
        return -1;
    } else {
        ipc_client_log(client, "Succesfully opened %s", CRESPO_MODEM_BIN_PATH);
    }

modem_opened:
    /* First 12 bytes are a header we don't know what means, but is constant throughout modems */
    lseek(modem_fd, 12, SEEK_SET);

    header.serial_ack = SERIAL_ACK;
    header.padding = 0;
    header.len = 871;
    header.type = 1;

    rc = ste_load_modem_serial_part(serial_fd, header, modem_fd);
    if (rc < 0) {
        ipc_client_log(client, "Failed to send modem.bin part 1 to serial");
        goto error;
    }

    usleep(100000);

    rc = m5730_receive_protrom(serial_fd);
    if (rc) {
        ipc_client_log(client, "Failed to receive ack for modem.bin part 1");
        goto error;
    }

    /* Part 2 - 2 bytes padding */
    lseek(modem_fd, 2, SEEK_CUR);

    /* Another unknown 12 byte header */
    lseek(modem_fd, 12, SEEK_CUR);

    header.len = 10653;
    header.type = 3;

    rc = ste_load_modem_serial_part(serial_fd, header, modem_fd);
    if (rc < 0) {
        ipc_client_log(client, "Failed to send modem.bin part 2 to serial");
        goto error;
    }

    usleep(100000);

    /* Check response */
    rc = m5730_receive_protrom(serial_fd);
    if (rc < 0) {
        ipc_client_log(client, "Failed to receive ack for modem.bin part 2");
        goto error;
    }

    close(modem_fd);
    return 0;

error:
    if (modem_fd >= 0)
        close(modem_fd);

    return -1;
}

int crespo_ste_configure_serial(int serial_fd, speed_t baud_rate)
{
    int ret, ctrl;
    struct termios termios;
    ret = ioctl(serial_fd, TCGETS, &termios);
    if (ret < 0)
        return -1;

    termios.c_cflag = CS8 | CREAD | CLOCAL | baud_rate;
    termios.c_iflag = IGNBRK;
    termios.c_oflag = NL0;
    termios.c_lflag = 0x0;
    termios.c_cc[VMIN] = 0x1;
    termios.c_cc[VTIME] = 0x1;

    ret = ioctl(serial_fd, TCSETS, &termios);
    if (ret < 0)
        return -1;

    ret = ioctl(serial_fd, TIOCMGET, &ctrl);
    if (ret < 0)
        return -1;

    ctrl = TIOCM_DTR | TIOCM_RTS | TIOCM_CAR | TIOCM_DSR;
    ret = ioctl(serial_fd, TIOCMSET, &ctrl);
    if (ret)
        return -1;

    return 0;
}

int crespo_ste_boot(struct ipc_client *client)
{

    int modem_ctl_fd = -1;
    int serial_fd = -1;
    int rc;

    if (client == NULL)
        return -1;

    ipc_client_log(client, "Starting crespo modem boot");

    modem_ctl_fd = open(CRESPO_MODEM_CTL_DEVICE, O_RDWR | O_NDELAY);
    if (modem_ctl_fd < 0) {
        ipc_client_log(client, "Opening modem ctl failed");
        goto error;
    }
    ipc_client_log(client, "Opened modem ctl");

    /* Initialize serial */
    serial_fd = open(CRESPO_MODEM_SERIAL_DEVICE, O_RDWR);
    if (serial_fd < 0 && errno == ENOENT)
        serial_fd = open(CRESPO_ALT_MODEM_SERIAL_DEVICE, O_RDWR);

    if (serial_fd < 0) {
        ipc_client_log(client, "Failed to open serial device");
        rc = -1;
        goto error;
    }

    /* Configure serial */
    rc = crespo_ste_configure_serial(serial_fd, B9600);
    if (rc < 0) {
        ipc_client_log(client, "Failed to configure serial");
        goto error;
    }

    rc = ioctl(modem_ctl_fd, IOCTL_MODEM_OFF);
    if (rc < 0) {
        ipc_client_log(client, "Powering off modem failed");
        goto error;
    }
    ipc_client_log(client, "Powered off modem");

    rc = ioctl(modem_ctl_fd, IOCTL_MODEM_RESET);
    if (rc < 0) {
        ipc_client_log(client, "Resetting modem failed");
        goto error;
    }
    ipc_client_log(client, "Reset modem");

    /* Tell modem to switch to 115200 baud */
    rc = m5730_write_baud_change(client, serial_fd);
    if (rc < 0) {
        ipc_client_log(client, "Failed to change baud rate");
        goto error;
    }

    /* Close and re-open serial, setting to 115200 baud */
    close(serial_fd);
    serial_fd = open(CRESPO_MODEM_SERIAL_DEVICE, O_RDWR);
    if (serial_fd < 0 && errno == ENOENT)
        serial_fd = open(CRESPO_ALT_MODEM_SERIAL_DEVICE, O_RDWR);

    if (serial_fd < 0) {
        ipc_client_log(client, "Failed to open serial device");
        goto error;
    }

    rc = crespo_ste_configure_serial(serial_fd, B115200);
    if (rc < 0) {
        ipc_client_log(client, "Failed to configure serial");
        goto error;
    }

    /* Connect to M5730 */
    rc = m5730_connect_ccpu(client, serial_fd);
    if (rc < 0) {
        ipc_client_log(client, "Failed to connect to CCPU, error %d", serial_fd);
        goto error;
    }

    /* Load modem.bin part to serial */
    rc = ste_load_modem_serial(client, serial_fd);
    if (rc) {
        ipc_client_log(client, "Failed to load modem.bin to serial");
        goto error;
    }

    rc = 0;
    goto complete;

error:
    /* Flush serial */
    if (serial_fd >= 0) {
        rc = ioctl(serial_fd, TCFLSH, TCIOFLUSH);
        if (rc != 0) {
            ipc_client_log(client, "Failed to flush serial, error %d", rc);
        }
        close(serial_fd);
    }

    rc = -1;

complete:
    if (serial_fd >= 0)
        close(serial_fd);

    if (modem_ctl_fd >= 0)
        close(modem_ctl_fd);

    return rc;
}

int crespo_ste_power_on(void)
{
    void *modem_image_data = NULL;
    char *compat;
    char modem_path[100];
    unsigned char *p;
    size_t wc = 0;
    int fd = -1;
    int rc = -1;

    /* First look for a DT version */
    compat = sysfs_string_read("/proc/device-tree/compatible", PATH_MAX);
    if (compat != NULL && strlen(compat) > 0) {
        rc = sprintf(modem_path, "/radio/modem.bin,%s", compat);
        free (compat);

        if (rc <= 0)
            return -1;

        modem_image_data = file_data_read(modem_path, CRESPO_STE_MODEM_IMAGE_SIZE, 0x1000, 0);
    }

    /* Then fall back to generic modem.bin */
    if (modem_image_data == NULL)
        modem_image_data = file_data_read(CRESPO_MODEM_BIN_PATH, CRESPO_STE_MODEM_IMAGE_SIZE, 0x1000, 0);
    if (modem_image_data == NULL)
        return -1;

    fd = open(CRESPO_MODEM_CTL_DEVICE, O_RDWR);
    if (fd < 0)
        goto error;

    rc = ioctl(fd, IOCTL_MODEM_WAIT_FOR_SBL);
    if (rc < 0)
        goto error;

    p = (unsigned char *) modem_image_data;

    p += CRESPO_PSI_SIZE;

    lseek(fd, 0, SEEK_SET);

    while (wc < CRESPO_STE_MODEM_IMAGE_SIZE - CRESPO_PSI_SIZE) {
        rc = write(fd, (void *) p, CRESPO_STE_MODEM_IMAGE_SIZE - CRESPO_PSI_SIZE - wc);
        if (rc <= 0)
            goto error;

        p += rc;
        wc += rc;
    }

    rc = ioctl(fd, IOCTL_MODEM_BINARY_LOAD);
    if (rc < 0)
        goto error;

    rc = 0;

error:
    if (modem_image_data != NULL)
        free(modem_image_data);

    if (fd >= 0)
        close(fd);

    return rc;
}

// vim:ts=4:sw=4:expandtab
