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

#ifndef __XMM626_H__
#define __XMM626_H__

#define XMM626_AT                               "ATAT"
#define XMM626_PSI_PADDING                                      0xFF
#define XMM626_PSI_MAGIC                                        0x30
#define XMM626_SEC_END_MAGIC                                    0x0000
#define XMM626_HW_RESET_MAGIC                                   0x111001
#define XMM626_DATA_SIZE                                        0x1000
#define XMM626_DATA_SIZE_LIMIT                                  0x80000

#define XMM626_COMMAND_SET_PORT_CONFIG                          0x86
#define XMM626_COMMAND_SEC_START                                0x204
#define XMM626_COMMAND_SEC_END                                  0x205
#define XMM626_COMMAND_HW_RESET                                 0x208
#define XMM626_COMMAND_FLASH_SET_ADDRESS                        0x802
#define XMM626_COMMAND_FLASH_WRITE_BLOCK                        0x804

#define XMM626_FIRMWARE_ADDRESS                                 0x60300000
#define XMM626_NV_DATA_ADDRESS                                  0x60E80000
#define XMM626_MPS_DATA_ADDRESS                                 0x61080000

#define XMM626_NV_DATA_PATH                     "/efs/nv_data.bin"
#define XMM626_NV_DATA_MD5_PATH                 "/efs/nv_data.bin.md5"
#define XMM626_NV_DATA_BACKUP_PATH              "/efs/.nv_data.bak"
#define XMM626_NV_DATA_BACKUP_MD5_PATH          "/efs/.nv_data.bak.md5"
#define XMM626_NV_DATA_SECRET                   "Samsung_Android_RIL"
#define XMM626_NV_DATA_SIZE                                     0x200000
#define XMM626_NV_DATA_CHUNK_SIZE                               0x2000

unsigned char xmm626_crc_calculate(const void *data, size_t size);

#endif

// vim:ts=4:sw=4:expandtab
