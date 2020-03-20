/*
 * Copyright (C) 2010 Google, Inc.
 * Copyright (C) 2010 Samsung Electronics.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __MODEM_CONTROL_H__
#define __MODEM_CONTROL_H__

#define IOCTL_MODEM_RAMDUMP             _IO('o', 0x19)
#define IOCTL_MODEM_RESET               _IO('o', 0x20)
#define IOCTL_MODEM_START               _IO('o', 0x21)
#define IOCTL_MODEM_OFF                 _IO('o', 0x22)
#define IOCTL_MODEM_WAIT_FOR_SBL	_IO('o', 0x23)
#define IOCTL_MODEM_BINARY_LOAD		_IO('o', 0x24)

#endif
