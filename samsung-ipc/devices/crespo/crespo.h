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

#ifndef __CRESPO_H__
#define __CRESPO_H__

#define CRESPO_XMM_MODEM_IMAGE_SIZE                             0xD80000
#define CRESPO_STE_MODEM_IMAGE_SIZE                             0xE05000
#define CRESPO_PSI_SIZE                                         0x5000
#define CRESPO_MODEM_CTL_NV_DATA_OFFSET                         0xD80000
#define CRESPO_BUFFER_LENGTH                                    0x50000

#define CRESPO_MODEM_IMAGE_DEVICE               "/dev/mtd/mtd5ro"
#define CRESPO_MODEM_BIN_PATH                   "/radio/modem.bin"
#define CRESPO_MODEM_SERIAL_DEVICE              "/dev/s3c2410_serial3"
#define CRESPO_ALT_MODEM_SERIAL_DEVICE          "/dev/ttySAC3"
#define CRESPO_MODEM_CTL_DEVICE                 "/dev/modem_ctl"
#define CRESPO_MODEM_FMT_DEVICE                 "/dev/modem_fmt"
#define CRESPO_MODEM_RFS_DEVICE                 "/dev/modem_rfs"

#define CRESPO_GPRS_IFACE_PREFIX                "rmnet"
#define CRESPO_GPRS_IFACE_COUNT                                 3

#define CRESPO_EFS_ROOT                         "/efs/root"

struct crespo_transport_data {
    int fd;
};

extern struct ipc_client_ops crespo_fmt_ops;
extern struct ipc_client_ops crespo_rfs_ops;
extern struct ipc_client_handlers crespo_handlers;
extern struct ipc_client_gprs_specs crespo_gprs_specs_single;
extern struct ipc_client_gprs_specs crespo_gprs_specs;
extern struct ipc_client_nv_data_specs crespo_nv_data_specs;

#endif

// vim:ts=4:sw=4:expandtab
