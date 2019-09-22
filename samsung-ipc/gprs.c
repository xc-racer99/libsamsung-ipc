/*
 * This file is part of libsamsung-ipc.
 *
 * Copyright (C) 2011 Simon Busch <morphis@gravedo.de>
 * Copyright (C) 2014 Paul Kocialkowski <contact@paulk.fr>
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
#include <string.h>

#include <samsung-ipc.h>

int ipc_gprs_define_pdp_context_setup(struct ipc_gprs_define_pdp_context_data *data,
    unsigned char enable, unsigned char cid, const char *apn)
{
    if (data == NULL || apn == NULL)
        return -1;

    memset(data, 0, sizeof(struct ipc_gprs_define_pdp_context_data));
    data->enable = enable;
    data->cid = cid;
    data->magic = 0x02;

    strncpy((char *) data->apn, apn, sizeof(data->apn));

    return 0;
}

int ipc_gprs_pdp_context_request_set_setup(struct ipc_gprs_pdp_context_request_set_data *data,
    unsigned char enable, unsigned char cid, const char *username,
    const char *password)
{
    if (data == NULL)
        return -1;

    memset(data, 0, sizeof(struct ipc_gprs_pdp_context_request_set_data));
    data->enable = enable;
    data->cid = cid;

    if (enable && username != NULL && password != NULL && strlen(username) > 0 && strlen(password) > 0) {
        data->magic1[2] = 0x13;
        data->magic2 = 0x01;

        strncpy((char *) data->username, username, sizeof(data->username));
        strncpy((char *) data->password, password, sizeof(data->password));
    }

    return 0;
}

int ipc_gprs_port_list_setup(struct ipc_gprs_port_list_data *data)
{
    // FIXME: These are only known-to-work values used on most devices
    unsigned char magic[] = { 0x02, 0x04, 0x16, 0x00, 0x17, 0x00, 0x87, 0x00, 0xBD, 0x01 };

    if (data == NULL)
        return -1;

    memset(data, 0, sizeof(struct ipc_gprs_port_list_data));
    memcpy(data->magic, magic, sizeof(magic));

    return 0;
}

// vim:ts=4:sw=4:expandtab
