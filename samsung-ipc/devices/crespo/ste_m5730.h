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

int crespo_is_ste(void);
int crespo_ste_boot(struct ipc_client *client);
int crespo_ste_power_on(void);

/* This is prepended to each message sent via serial */
#define SERIAL_ACK 4008639402U

struct crespo_modem_data_header {
    unsigned int serial_ack;
    char padding;
    unsigned short len;
    char type;
} __attribute__((__packed__));


