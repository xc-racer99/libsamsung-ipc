/*
 * This file is part of libsamsung-ipc.
 *
 * Copyright (C) 2010-2011 Joerie de Gram <j.de.gram@gmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <asm/types.h>

#include <samsung-ipc.h>
#include <ipc.h>

int ipc_seq_valid(unsigned char seq)
{
    if (seq == 0x00 || seq == 0xff)
        return 0;

    return 1;
}

const char *ipc_request_type_string(unsigned char type)
{
    static char type_string[5] = { 0 };

    switch (type) {
        case IPC_TYPE_EXEC:
            return "IPC_TYPE_EXEC";
        case IPC_TYPE_GET:
            return "IPC_TYPE_GET";
        case IPC_TYPE_SET:
            return "IPC_TYPE_SET";
        case IPC_TYPE_CFRM:
            return "IPC_TYPE_CFRM";
        case IPC_TYPE_EVENT:
            return "IPC_TYPE_EVENT";
        default:
            snprintf((char *) &type_string, sizeof(type_string), "0x%02x", type);
            return type_string;
    }
}

const char *ipc_response_type_string(unsigned char type)
{
    static char type_string[5] = { 0 };

    switch (type) {
        case IPC_TYPE_INDI:
            return "IPC_TYPE_INDI";
        case IPC_TYPE_RESP:
            return "IPC_TYPE_RESP";
        case IPC_TYPE_NOTI:
            return "IPC_TYPE_NOTI";
        default:
            snprintf((char *) &type_string, sizeof(type_string), "0x%02x", type);
            return type_string;
    }
}

const char *ipc_command_string(unsigned short command)
{
    static char command_string[7] = { 0 };

    switch (command) {
        case IPC_PWR_PHONE_PWR_UP:
            return "IPC_PWR_PHONE_PWR_UP";
        case IPC_PWR_PHONE_PWR_OFF:
            return "IPC_PWR_PHONE_PWR_OFF";
        case IPC_PWR_PHONE_RESET:
            return "IPC_PWR_PHONE_RESET";
        case IPC_PWR_BATT_STATUS:
            return "IPC_PWR_BATT_STATUS";
        case IPC_PWR_BATT_TYPE:
            return "IPC_PWR_BATT_TYPE";
        case IPC_PWR_BATT_COMP:
            return "IPC_PWR_BATT_COMP";
        case IPC_PWR_PHONE_STATE:
            return "IPC_PWR_PHONE_STATE";
        case IPC_CALL_OUTGOING:
            return "IPC_CALL_OUTGOING";
        case IPC_CALL_INCOMING:
            return "IPC_CALL_INCOMING";
        case IPC_CALL_RELEASE:
            return "IPC_CALL_RELEASE";
        case IPC_CALL_ANSWER:
            return "IPC_CALL_ANSWER";
        case IPC_CALL_STATUS:
            return "IPC_CALL_STATUS";
        case IPC_CALL_LIST:
            return "IPC_CALL_LIST";
        case IPC_CALL_BURST_DTMF:
            return "IPC_CALL_BURST_DTMF";
        case IPC_CALL_CONT_DTMF:
            return "IPC_CALL_CONT_DTMF";
        case IPC_CALL_WAITING:
            return "IPC_CALL_WAITING";
        case IPC_CALL_LINE_ID:
            return "IPC_CALL_LINE_ID";
        case IPC_SMS_SEND_MSG:
            return "IPC_SMS_SEND_MSG";
        case IPC_SMS_INCOMING_MSG:
            return "IPC_SMS_INCOMING_MSG";
        case IPC_SMS_READ_MSG:
            return "IPC_SMS_READ_MSG";
        case IPC_SMS_SAVE_MSG:
            return "IPC_SMS_SAVE_MSG";
        case IPC_SMS_DEL_MSG:
            return "IPC_SMS_DEL_MSG";
        case IPC_SMS_DELIVER_REPORT:
            return "IPC_SMS_DELIVER_REPORT";
        case IPC_SMS_DEVICE_READY:
            return "IPC_SMS_DEVICE_READY";
        case IPC_SMS_SEL_MEM:
            return "IPC_SMS_SEL_MEM";
        case IPC_SMS_STORED_MSG_COUNT:
            return "IPC_SMS_STORED_MSG_COUNT";
        case IPC_SMS_SVC_CENTER_ADDR:
            return "IPC_SMS_SVC_CENTER_ADDR";
        case IPC_SMS_SVC_OPTION:
            return "IPC_SMS_SVC_OPTION";
        case IPC_SMS_MEM_STATUS:
            return "IPC_SMS_MEM_STATUS";
        case IPC_SMS_CBS_MSG:
            return "IPC_SMS_CBS_MSG";
        case IPC_SMS_CBS_CFG:
            return "IPC_SMS_CBS_CFG";
        case IPC_SMS_STORED_MSG_STATUS:
            return "IPC_SMS_STORED_MSG_STATUS";
        case IPC_SMS_PARAM_COUNT:
            return "IPC_SMS_PARAM_COUNT";
        case IPC_SMS_PARAM:
            return "IPC_SMS_PARAM";
        case IPC_SEC_PIN_STATUS:
            return "IPC_SEC_PIN_STATUS";
        case IPC_SEC_PHONE_LOCK:
            return "IPC_SEC_PHONE_LOCK";
        case IPC_SEC_CHANGE_LOCKING_PW:
            return "IPC_SEC_CHANGE_LOCKING_PW";
        case IPC_SEC_SIM_LANG:
            return "IPC_SEC_SIM_LANG";
        case IPC_SEC_RSIM_ACCESS:
            return "IPC_SEC_RSIM_ACCESS";
        case IPC_SEC_GSIM_ACCESS:
            return "IPC_SEC_GSIM_ACCESS";
        case IPC_SEC_SIM_ICC_TYPE:
            return "IPC_SEC_SIM_ICC_TYPE";
        case IPC_SEC_LOCK_INFOMATION:
            return "IPC_SEC_LOCK_INFOMATION";
        case IPC_SEC_IMS_AUTH:
            return "IPC_SEC_IMS_AUTH";
        case IPC_PB_ACCESS:
            return "IPC_PB_ACCESS";
        case IPC_PB_STORAGE:
            return "IPC_PB_STORAGE";
        case IPC_PB_STORAGE_LIST:
            return "IPC_PB_STORAGE_LIST";
        case IPC_PB_ENTRY_INFO:
            return "IPC_PB_ENTRY_INFO";
        case IPC_PB_3GPB_CAPA:
            return "IPC_PB_3GPB_CAPA";
        case IPC_DISP_ICON_INFO:
            return "IPC_DISP_ICON_INFO";
        case IPC_DISP_HOMEZONE_INFO:
            return "IPC_DISP_HOMEZONE_INFO";
        case IPC_DISP_RSSI_INFO:
            return "IPC_DISP_RSSI_INFO";
        case IPC_NET_PREF_PLMN:
            return "IPC_NET_PREF_PLMN";
        case IPC_NET_PLMN_SEL:
            return "IPC_NET_PLMN_SEL";
        case IPC_NET_SERVING_NETWORK:
            return "IPC_NET_SERVING_NETWORK";
        case IPC_NET_PLMN_LIST:
            return "IPC_NET_PLMN_LIST";
        case IPC_NET_REGIST:
            return "IPC_NET_REGIST";
        case IPC_NET_SUBSCRIBER_NUM:
            return "IPC_NET_SUBSCRIBER_NUM";
        case IPC_NET_BAND_SEL:
            return "IPC_NET_BAND_SEL";
        case IPC_NET_SERVICE_DOMAIN_CONFIG:
            return "IPC_NET_SERVICE_DOMAIN_CONFIG";
        case IPC_NET_POWERON_ATTACH:
            return "IPC_NET_POWERON_ATTACH";
        case IPC_NET_MODE_SEL:
            return "IPC_NET_MODE_SEL";
        case IPC_NET_ACQ_ORDER:
            return "IPC_NET_ACQ_ORDER";
        case IPC_NET_IDENTITY:
            return "IPC_NET_IDENTITY";
        case IPC_NET_PREFERRED_NETWORK_INFO:
            return "IPC_NET_PREFERRED_NETWORK_INFO";
        case IPC_SND_SPKR_VOLUME_CTRL:
            return "IPC_SND_SPKR_VOLUME_CTRL";
        case IPC_SND_MIC_MUTE_CTRL:
            return "IPC_SND_MIC_MUTE_CTRL";
        case IPC_SND_AUDIO_PATH_CTRL:
            return "IPC_SND_AUDIO_PATH_CTRL";
        case IPC_SND_AUDIO_SOURCE_CTRL:
            return "IPC_SND_AUDIO_SOURCE_CTRL";
        case IPC_SND_LOOPBACK_CTRL:
            return "IPC_SND_LOOPBACK_CTRL";
        case IPC_SND_VOICE_RECORDING_CTRL:
            return "IPC_SND_VOICE_RECORDING_CTRL";
        case IPC_SND_VIDEO_CALL_CTRL:
            return "IPC_SND_VIDEO_CALL_CTRL";
        case IPC_SND_RINGBACK_TONE_CTRL:
            return "IPC_SND_RINGBACK_TONE_CTRL";
        case IPC_SND_CLOCK_CTRL:
            return "IPC_SND_CLOCK_CTRL";
        case IPC_SND_WB_AMR_STATUS:
            return "IPC_SND_WB_AMR_STATUS";
        case IPC_MISC_ME_VERSION:
            return "IPC_MISC_ME_VERSION";
        case IPC_MISC_ME_IMSI:
            return "IPC_MISC_ME_IMSI";
        case IPC_MISC_ME_SN:
            return "IPC_MISC_ME_SN";
        case IPC_MISC_TIME_INFO:
            return "IPC_MISC_TIME_INFO";
        case IPC_MISC_DEBUG_LEVEL:
            return "IPC_MISC_DEBUG_LEVEL";
        case IPC_SVC_ENTER:
            return "IPC_SVC_ENTER";
        case IPC_SVC_END:
            return "IPC_SVC_END";
        case IPC_SVC_PRO_KEYCODE:
            return "IPC_SVC_PRO_KEYCODE";
        case IPC_SVC_SCREEN_CFG:
            return "IPC_SVC_SCREEN_CFG";
        case IPC_SVC_DISPLAY_SCREEN:
            return "IPC_SVC_DISPLAY_SCREEN";
        case IPC_SVC_CHANGE_SVC_MODE:
            return "IPC_SVC_CHANGE_SVC_MODE";
        case IPC_SVC_DEVICE_TEST:
            return "IPC_SVC_DEVICE_TEST";
        case IPC_SVC_DEBUG_DUMP:
            return "IPC_SVC_DEBUG_DUMP";
        case IPC_SVC_DEBUG_STRING:
            return "IPC_SVC_DEBUG_STRING";
        case IPC_SS_WAITING:
            return "IPC_SS_WAITING";
        case IPC_SS_CLI:
            return "IPC_SS_CLI";
        case IPC_SS_BARRING:
            return "IPC_SS_BARRING";
        case IPC_SS_BARRING_PW:
            return "IPC_SS_BARRING_PW";
        case IPC_SS_FORWARDING:
            return "IPC_SS_FORWARDING";
        case IPC_SS_INFO:
            return "IPC_SS_INFO";
        case IPC_SS_MANAGE_CALL:
            return "IPC_SS_MANAGE_CALL";
        case IPC_SS_USSD:
            return "IPC_SS_USSD";
        case IPC_SS_AOC:
            return "IPC_SS_AOC";
        case IPC_SS_RELEASE_COMPLETE:
            return "IPC_SS_RELEASE_COMPLETE";
        case IPC_GPRS_DEFINE_PDP_CONTEXT:
            return "IPC_GPRS_DEFINE_PDP_CONTEXT";
        case IPC_GPRS_QOS:
            return "IPC_GPRS_QOS";
        case IPC_GPRS_PS:
            return "IPC_GPRS_PS";
        case IPC_GPRS_PDP_CONTEXT:
            return "IPC_GPRS_PDP_CONTEXT";
        case IPC_GPRS_ENTER_DATA:
            return "IPC_GPRS_ENTER_DATA";
        case IPC_GPRS_SHOW_PDP_ADDR:
            return "IPC_GPRS_SHOW_PDP_ADDR";
        case IPC_GPRS_MS_CLASS:
            return "IPC_GPRS_MS_CLASS";
        case IPC_GPRS_3G_QUAL_SRVC_PROFILE:
            return "IPC_GPRS_3G_QUAL_SRVC_PROFILE";
        case IPC_GPRS_IP_CONFIGURATION:
            return "IPC_GPRS_IP_CONFIGURATION";
        case IPC_GPRS_DEFINE_SEC_PDP_CONTEXT:
            return "IPC_GPRS_DEFINE_SEC_PDP_CONTEXT";
        case IPC_GPRS_TFT:
            return "IPC_GPRS_TFT";
        case IPC_GPRS_HSDPA_STATUS:
            return "IPC_GPRS_HSDPA_STATUS";
        case IPC_GPRS_CURRENT_SESSION_DATA_COUNTER:
            return "IPC_GPRS_CURRENT_SESSION_DATA_COUNTER";
        case IPC_GPRS_DATA_DORMANT:
            return "IPC_GPRS_DATA_DORMANT";
        case IPC_GPRS_PIN_CTRL:
            return "IPC_GPRS_PIN_CTRL";
        case IPC_GPRS_CALL_STATUS:
            return "IPC_GPRS_CALL_STATUS";
        case IPC_GPRS_PORT_LIST:
            return "IPC_GPRS_PORT_LIST";
        case IPC_SAT_PROFILE_DOWNLOAD:
            return "IPC_SAT_PROFILE_DOWNLOAD";
        case IPC_SAT_ENVELOPE_CMD:
            return "IPC_SAT_ENVELOPE_CMD";
        case IPC_SAT_PROACTIVE_CMD:
            return "IPC_SAT_PROACTIVE_CMD";
        case IPC_SAT_TERMINATE_USAT_SESSION:
            return "IPC_SAT_TERMINATE_USAT_SESSION";
        case IPC_SAT_EVENT_DOWNLOAD:
            return "IPC_SAT_EVENT_DOWNLOAD";
        case IPC_SAT_PROVIDE_LOCAL_INFO:
            return "IPC_SAT_PROVIDE_LOCAL_INFO";
        case IPC_SAT_POLLING:
            return "IPC_SAT_POLLING";
        case IPC_SAT_REFRESH:
            return "IPC_SAT_REFRESH";
        case IPC_SAT_SETUP_EVENT_LIST:
            return "IPC_SAT_SETUP_EVENT_LIST";
        case IPC_SAT_CALL_CONTROL_RESULT:
            return "IPC_SAT_CALL_CONTROL_RESULT";
        case IPC_SAT_IMAGE_CLUT:
            return "IPC_SAT_IMAGE_CLUT";
        case IPC_SAT_SETUP_CALL_PROCESSING:
            return "IPC_SAT_SETUP_CALL_PROCESSING";
        case IPC_IMEI_START:
            return "IPC_IMEI_START";
        case IPC_IMEI_CHECK_DEVICE_INFO:
            return "IPC_IMEI_CHECK_DEVICE_INFO";
        case IPC_RFS_NV_READ_ITEM:
            return "IPC_RFS_NV_READ_ITEM";
        case IPC_RFS_NV_WRITE_ITEM:
            return "IPC_RFS_NV_WRITE_ITEM";
        case IPC_RFS_READ_FILE:
            return "IPC_RFS_READ_FILE";
        case IPC_RFS_WRITE_FILE:
            return "IPC_RFS_WRITE_FILE";
        case IPC_RFS_LSEEK_FILE:
            return "IPC_RFS_LSEEK_FILE";
        case IPC_RFS_CLOSE_FILE:
            return "IPC_RFS_CLOSE_FILE";
        case IPC_RFS_PUT_FILE:
            return "IPC_RFS_PUT_FILE";
        case IPC_RFS_GET_FILE:
            return "IPC_RFS_GET_FILE";
        case IPC_RFS_RENAME_FILE:
            return "IPC_RFS_RENAME_FILE";
        case IPC_RFS_GET_FILE_INFO:
            return "IPC_RFS_GET_FILE_INFO";
        case IPC_RFS_UNLINK_FILE:
            return "IPC_RFS_UNLINK_FILE";
        case IPC_RFS_MAKE_DIR:
            return "IPC_RFS_MAKE_DIR";
        case IPC_RFS_REMOVE_DIR:
            return "IPC_RFS_REMOVE_DIR";
        case IPC_RFS_OPEN_DIR:
            return "IPC_RFS_OPEN_DIR";
        case IPC_RFS_READ_DIR:
            return "IPC_RFS_READ_DIR";
        case IPC_RFS_CLOSE_DIR:
            return "IPC_RFS_CLOSE_DIR";
        case IPC_RFS_OPEN_FILE:
            return "IPC_RFS_OPEN_FILE";
        case IPC_RFS_FTRUNCATE_FILE:
            return "IPC_RFS_FTRUNCATE_FILE";
        case IPC_RFS_GET_HANDLE_INFO:
            return "IPC_RFS_GET_HANDLE_INFO";
        case IPC_RFS_CREATE_FILE:
            return "IPC_RFS_CREATE_FILE";
        case IPC_RFS_NV_WRITE_ALL_ITEM:
            return "IPC_RFS_NV_WRITE_ALL_ITEM";
        case IPC_GEN_PHONE_RES:
            return "IPC_GEN_PHONE_RES";
        default:
            snprintf((char *) &command_string, sizeof(command_string), "0x%04x", command);
            return command_string;
    }
}

int ipc_data_dump(struct ipc_client *client, const void *data, size_t size)
{
    unsigned int cols = 8;
    unsigned int cols_count = 2;
    int spacer;
    char string[81] = { 0 };
    char final[161] = { 0 };
    size_t length;
    char *print;
    unsigned char *p;
    unsigned int offset;
    unsigned int rollback;
    unsigned int i, j, k;
    int rc;

    if (data == NULL || size == 0)
        return -1;

    // spacer = string length - offset print length - data print length - ascii print length
    spacer = (sizeof(string) - 1) - 6 - (3 * cols * cols_count - 1 + (cols_count - 1)) - (cols * cols_count + cols_count - 1);

    // Need 3 spacers
    spacer /= 3;

    if (spacer <= 0)
        return -1;

    p = (unsigned char *) data;
    offset = 0;

    while (offset < size) {
        rollback = 0;

        print = (char *) &string;
        length = sizeof(string);

        // Offset print

        rc = snprintf(print, length, "[%04x]", offset);
        print += rc;
        length -= rc;

        // Spacer print

        for (i = 0; i < (unsigned int) spacer; i++) {
            *print++ = ' ';
            length--;
        }

        // Data print

        for (i = 0; i < cols_count; i++) {
            for (j = 0; j < cols; j++) {
                if (offset < size) {
                    rc = snprintf(print, length, "%02X", *p);
                    print += rc;
                    length -= rc;

                    p++;
                    offset++;
                    rollback++;
                } else {
                    for (k = 0; k < 2; k++) {
                        *print++ = ' ';
                        length--;
                    }
                }

                if (j != (cols - 1)) {
                    *print++ = ' ';
                    length--;
                }
            }

            if (i != (cols_count - 1)) {
                for (k = 0; k < 2; k++) {
                    *print++ = ' ';
                    length--;
                }
            }
        }

        // Spacer print

        for (i = 0; i < (unsigned int) spacer; i++) {
            *print++ = ' ';
            length--;
        }

        // ASCII print

        p -= rollback;
        offset -= rollback;

        for (i = 0; i < cols_count; i++) {
            for (j = 0; j < cols; j++) {
                if (offset < size) {
                    if (isascii(*p) && isprint(*p))
                        *print = *p;
                    else
                        *print = '.';

                    print++;
                    length--;

                    p++;
                    offset++;
                    rollback++;
                }
            }

            if (i != (cols_count - 1) && offset < size) {
                *print++ = ' ';
                length--;
            }
        }

        *print = '\0';

        // Escape string

        j = 0;

        for (i = 0; i < sizeof(string); i++) {
            if (string[i] == '%')
                final[j++] = string[i];

            final[j++] = string[i];
        }

        ipc_client_log(client, final);
    }

    return 0;
}

void ipc_client_log_send(struct ipc_client *client, struct ipc_message *message,
    const char *prefix)
{
    if (client == NULL || message == NULL || prefix == NULL)
        return;

    switch (client->type) {
        case IPC_CLIENT_TYPE_FMT:
            ipc_client_log(client, "\n");
            ipc_client_log(client, "%s: Sent FMT message", prefix);
            ipc_client_log(client, "%s: Message: mseq=0x%02x, command=%s, type=%s, size=%d", prefix, message->mseq, ipc_command_string(message->command), ipc_request_type_string(message->type), message->size);
#ifdef DEBUG
            if (message->size > 0) {
                ipc_client_log(client, "================================= IPC FMT data =================================");
                ipc_data_dump(client, (void *) message->data, message->size > 0x100 ? 0x100 : message->size);
                ipc_client_log(client, "================================================================================");
            }
#endif
            break;
        case IPC_CLIENT_TYPE_RFS:
            ipc_client_log(client, "\n");
            ipc_client_log(client, "%s: Sent RFS message", prefix);
            ipc_client_log(client, "%s: Message: mseq=0x%02x, command=%s, size=%d", prefix, message->mseq, ipc_command_string(message->command), message->size);
#ifdef DEBUG
            if (message->size > 0) {
                ipc_client_log(client, "================================= IPC RFS data =================================");
                ipc_data_dump(client, (void *) message->data, message->size > 0x100 ? 0x100 : message->size);
                ipc_client_log(client, "================================================================================");
            }
#endif
            break;
    }
}

void ipc_client_log_recv(struct ipc_client *client, struct ipc_message *message,
    const char *prefix)
{
    if (client == NULL || message == NULL || prefix == NULL)
        return;

    switch (client->type) {
        case IPC_CLIENT_TYPE_FMT:
            ipc_client_log(client, "\n");
            ipc_client_log(client, "%s: Received FMT message", prefix);
            ipc_client_log(client, "%s: Message: aseq=0x%02x, command=%s, type=%s, size=%d", prefix, message->aseq, ipc_command_string(message->command), ipc_response_type_string(message->type), message->size);
#ifdef DEBUG
            if (message->size > 0) {
                ipc_client_log(client, "================================= IPC FMT data =================================");
                ipc_data_dump(client, (void *) message->data, message->size > 0x100 ? 0x100 : message->size);
                ipc_client_log(client, "================================================================================");
            }
#endif
            break;
        case IPC_CLIENT_TYPE_RFS:
            ipc_client_log(client, "\n");
            ipc_client_log(client, "%s: Received RFS message", prefix);
            ipc_client_log(client, "%s: Message: aseq=0x%02x, command=%s, size=%d", prefix, message->aseq, ipc_command_string(message->command), message->size);
#ifdef DEBUG
            if (message->size > 0) {
                ipc_client_log(client, "================================= IPC RFS data =================================");
                ipc_data_dump(client, (void *) message->data, message->size > 0x100 ? 0x100 : message->size);
                ipc_client_log(client, "================================================================================");
            }
#endif
            break;
    }
}

int ipc_fmt_header_setup(struct ipc_fmt_header *header,
    const struct ipc_message *message)
{
    if (header == NULL || message == NULL)
        return -1;

    memset(header, 0, sizeof(struct ipc_fmt_header));
    header->length = message->size + sizeof(struct ipc_fmt_header);
    header->mseq = message->mseq;
    header->aseq = message->aseq;
    header->group = IPC_GROUP(message->command);
    header->index = IPC_INDEX(message->command);
    header->type = message->type;

    return 0;
}

int ipc_fmt_message_setup(const struct ipc_fmt_header *header,
    struct ipc_message *message)
{
    if (header == NULL || message == NULL)
        return -1;

    memset(message, 0, sizeof(struct ipc_message));
    message->mseq = header->mseq;
    message->aseq = header->aseq;
    message->command = IPC_COMMAND(header->group, header->index);
    message->type = header->type;
    message->data = NULL;
    message->size = 0;

    return 0;
}

int ipc_rfs_header_setup(struct ipc_rfs_header *header,
    const struct ipc_message *message)
{
    if (header == NULL || message == NULL)
        return -1;

    memset(header, 0, sizeof(struct ipc_rfs_header));
    header->length = message->size + sizeof(struct ipc_rfs_header);
    header->id = message->mseq;
    header->index = IPC_INDEX(message->command);

    return 0;
}

int ipc_rfs_message_setup(const struct ipc_rfs_header *header,
    struct ipc_message *message)
{
    if (header == NULL || message == NULL)
        return -1;

    memset(message, 0, sizeof(struct ipc_message));
    message->aseq = header->id;
    message->command = IPC_COMMAND(IPC_GROUP_RFS, header->index);
    message->data = NULL;
    message->size = 0;

    return 0;
}

// vim:ts=4:sw=4:expandtab
