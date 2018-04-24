/*
 * This file is part of libsamsung-ipc.
 *
 * Copyright (C) 2010-2011 Joerie de Gram <j.de.gram@gmail.com>
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

#include <samsung-ipc.h>

#ifndef __SAMSUNG_IPC_NET_H__
#define __SAMSUNG_IPC_NET_H__

/*
 * Commands
 */

#define IPC_NET_PREF_PLMN                                       0x0801
#define IPC_NET_PLMN_SEL                                        0x0802
#define IPC_NET_SERVING_NETWORK                                 0x0803
#define IPC_NET_PLMN_LIST                                       0x0804
#define IPC_NET_REGIST                                          0x0805
#define IPC_NET_SUBSCRIBER_NUM                                  0x0806
#define IPC_NET_BAND_SEL                                        0x0807
#define IPC_NET_SERVICE_DOMAIN_CONFIG                           0x0808
#define IPC_NET_POWERON_ATTACH                                  0x0809
#define IPC_NET_MODE_SEL                                        0x080A
#define IPC_NET_ACQ_ORDER                                       0x080B
#define IPC_NET_IDENTITY                                        0x080C
#define IPC_NET_PREFERRED_NETWORK_INFO                          0x080D

/*
 * Values
 */

#define IPC_NET_PLMN_SEL_AUTO                                   0x02
#define IPC_NET_PLMN_SEL_MANUAL                                 0x03

#define IPC_NET_MODE_SEL_GSM_UMTS                               0x01
#define IPC_NET_MODE_SEL_GSM_ONLY                               0x02
#define IPC_NET_MODE_SEL_UMTS_ONLY                              0x03

#define IPC_NET_ACCESS_TECHNOLOGY_GSM                           0x00
#define IPC_NET_ACCESS_TECHNOLOGY_GSM2                          0x01
#define IPC_NET_ACCESS_TECHNOLOGY_GPRS                          0x02
#define IPC_NET_ACCESS_TECHNOLOGY_EDGE                          0x03
#define IPC_NET_ACCESS_TECHNOLOGY_UMTS                          0x04
#define IPC_NET_ACCESS_TECHNOLOGY_UNKNOWN                       0xFF

#define IPC_NET_PLMN_STATUS_AVAILABLE                           0x02
#define IPC_NET_PLMN_STATUS_CURRENT                             0x03
#define IPC_NET_PLMN_STATUS_FORBIDDEN                           0x04

#define IPC_NET_PLMN_TYPE_EMERGENCY                             0x01
#define IPC_NET_PLMN_TYPE_NORMAL                                0x04

#define IPC_NET_SERVICE_DOMAIN_GSM                              0x02
#define IPC_NET_SERVICE_DOMAIN_GPRS                             0x03

#define IPC_NET_REGISTRATION_STATUS_NONE                        0x01
#define IPC_NET_REGISTRATION_STATUS_HOME                        0x02
#define IPC_NET_REGISTRATION_STATUS_SEARCHING                   0x03
#define IPC_NET_REGISTRATION_STATUS_EMERGENCY                   0x04
#define IPC_NET_REGISTRATION_STATUS_UNKNOWN                     0x05
#define IPC_NET_REGISTRATION_STATUS_ROAMING                     0x06

/*
 * Structures
 */

struct ipc_net_plmn_sel_response_data {
    unsigned char plmn_sel; // IPC_NET_PLMN_SEL
} __attribute__((__packed__));

struct ipc_net_plmn_sel_request_data {
    unsigned char mode_sel; // IPC_NET_MODE_SEL
    char plmn[6];
    unsigned char act; // IPC_NET_ACCESS_TECHNOLOGY
} __attribute__((__packed__));

struct ipc_net_serving_network_data {
    unsigned char unknown[3];
    char plmn[6];
    unsigned char lac; // This can be either a short or a char
} __attribute__((__packed__));

struct ipc_net_plmn_list_header {
    unsigned char count;
} __attribute__((__packed__));

struct ipc_net_plmn_list_entry {
    unsigned char status; // IPC_NET_PLMN_STATUS
    char plmn[6];
    unsigned char type; // IPC_NET_PLMN_TYPE
    unsigned char unknown[2];
} __attribute__((__packed__));

struct ipc_net_regist_request_data {
    unsigned char act; // IPC_NET_ACCESS_TECHNOLOGY
    unsigned char domain; // IPC_NET_SERVICE_DOMAIN
} __attribute__((__packed__));

struct ipc_net_regist_response_data {
    unsigned char act; // IPC_NET_ACCESS_TECHNOLOGY
    unsigned char domain; // IPC_NET_SERVICE_DOMAIN
    unsigned char status; // IPC_NET_REGISTRATION_STATUS
    unsigned char edge;
    unsigned short lac;
    unsigned int cid;
    unsigned char fail_cause;
} __attribute__((__packed__));

struct ipc_net_mode_sel_data {
    unsigned char mode_sel; // IPC_NET_MODE_SEL
} __attribute__((__packed__));

/*
 * Helpers
 */

int ipc_net_plmn_sel_setup(struct ipc_net_plmn_sel_request_data *data,
    unsigned char mode_sel, const char *plmn, unsigned char act);
int ipc_net_regist_setup(struct ipc_net_regist_request_data *data,
    unsigned char domain);
unsigned char ipc_net_plmn_list_count_extract(const void *data, size_t size);
struct ipc_net_plmn_list_entry *ipc_net_plmn_list_entry_extract(const void *data,
    size_t size, unsigned int index);

#endif

// vim:ts=4:sw=4:expandtab
