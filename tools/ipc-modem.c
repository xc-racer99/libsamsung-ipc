/*
 * This file is part of libsamsung-ipc.
 *
 * Copyright (C) 2011 Simon Busch <morphis@gravedo.de>
 * Copyright (C) 2011 Paul Kocialkowsk <contact@paulk.fr>
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
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <termios.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <getopt.h>

#include <samsung-ipc.h>

#include "rfs.h"

#define MODEM_STATE_LPM     0
#define MODEM_STATE_NORMAL  2
#define MODEM_STATE_SIM_OK  4

#define DEF_CALL_NUMBER "950"
#define DEF_SIM_PIN     "1234"

int state = MODEM_STATE_LPM;
int seq = 0;
int in_call = 0;
int out_call = 0;
int call_done = 0;

char sim_pin[8];

int seq_get(void)
{
    if(seq == 0xff)
        seq = 0x00;

    seq++;

    return seq;
}

void modem_snd_no_mic_mute(struct ipc_client *client)
{
    uint8_t data = 0;
    ipc_client_send(client, seq_get(), IPC_SND_MIC_MUTE_CTRL, IPC_TYPE_SET, (void *) &data, 1);
}

void modem_snd_clock_ctrl(struct ipc_client *client)
{
    uint8_t data = 0x01;
    ipc_client_send(client, seq_get(), IPC_SND_CLOCK_CTRL, IPC_TYPE_EXEC, (void *) &data, 1);
}

void modem_snd_spkr_volume_ctrl(struct ipc_client *client)
{
    uint16_t data = 0x0411;
    ipc_client_send(client, seq_get(), IPC_SND_SPKR_VOLUME_CTRL, IPC_TYPE_SET, (void *) &data, 2);
}

void modem_snd_audio_path_ctrl(struct ipc_client *client)
{
    uint8_t data = 0x01;
    ipc_client_send(client, seq_get(), IPC_SND_AUDIO_PATH_CTRL, IPC_TYPE_SET, (void *) &data, 1);
}


void modem_exec_call_out(struct ipc_client *client, char *num)
{
    struct ipc_call_outgoing_data call_out;

    modem_snd_no_mic_mute(client);

    memset(&call_out, 0, sizeof(struct ipc_call_outgoing_data));

    call_out.type = IPC_CALL_TYPE_VOICE;
    call_out.identity = IPC_CALL_IDENTITY_DEFAULT;
    call_out.number_length=strlen(num);
    /* 0x21 = +33 */
    call_out.prefix=IPC_CALL_PREFIX_NONE; //0x21;//IPC_CALL_PREFIX_NONE;
    memcpy(call_out.number, num, call_out.number_length);

    ipc_client_send(client, seq_get(), IPC_CALL_OUTGOING, IPC_TYPE_EXEC, (void *) &call_out, sizeof(struct ipc_call_outgoing_data));

    out_call = 1;

    modem_snd_no_mic_mute(client);
    modem_snd_spkr_volume_ctrl(client);
    modem_snd_audio_path_ctrl(client);
}

void modem_exec_call_answer(struct ipc_client *client)
{
    modem_snd_clock_ctrl(client);

    ipc_client_send(client, seq_get(), IPC_CALL_ANSWER, IPC_TYPE_EXEC, NULL, 0);

    modem_snd_no_mic_mute(client);
}

void modem_get_call_list(struct ipc_client *client)
{
    ipc_client_send(client, seq_get(), IPC_CALL_LIST, IPC_TYPE_GET, NULL, 0);

    modem_snd_no_mic_mute(client);
}

void modem_exec_power_normal(struct ipc_client *client)
{
    uint16_t data = 0x0202;
    ipc_client_send(client, seq_get(), IPC_PWR_PHONE_STATE, IPC_TYPE_EXEC, (void *) &data, sizeof(data));
}

void modem_set_sms_device_ready(struct ipc_client *client)
{
    ipc_client_send(client, seq_get(), IPC_SMS_DEVICE_READY, IPC_TYPE_SET, NULL, 0);
}

void modem_set_sec_pin_status(struct ipc_client *client, char *pin1, char *pin2)
{
    struct ipc_sec_pin_status_request_data pin_status;

    printf("[I] Sending PIN1 unlock request\n");

    ipc_sec_pin_status_setup(&pin_status, IPC_SEC_PIN_TYPE_PIN1, pin1, pin2);
    ipc_client_send(client, seq_get(), IPC_SEC_PIN_STATUS, IPC_TYPE_SET, (void *) &pin_status, sizeof(pin_status));
}

void modem_response_sec(struct ipc_client *client, struct ipc_message *resp)
{
    struct ipc_sec_pin_status_response_data *sim_status;
    unsigned char type;
    int status;
    char *data;

    switch(resp->command)
    {
        case IPC_SEC_PIN_STATUS :
            sim_status = (struct ipc_sec_pin_status_response_data *)resp->data;

            switch(sim_status->status)
            {
                case IPC_SEC_PIN_STATUS_CARD_NOT_PRESENT:
                    printf("[I] SIM card is definitely absent\n");
                break;
                case IPC_SEC_PIN_STATUS_LOCK_SC:
                    switch(sim_status->facility_lock)
                    {
                        case IPC_SEC_FACILITY_LOCK_TYPE_SC_PIN1_REQ:
                            printf("[I] We need the PIN1 to unlock the card!\n");
                            if(strlen(sim_pin) > 0) {
                                modem_set_sec_pin_status(client, sim_pin, NULL);
                            } else {
                                printf("[E] No SIM Pin, use --pin\n");
                            }
                        break;
                        case IPC_SEC_FACILITY_LOCK_TYPE_SC_PUK_REQ:
                            printf("[I] Please provide the SIM card PUK!\n");
                        break;
                        case IPC_SEC_FACILITY_LOCK_TYPE_SC_CARD_BLOCKED:
                            printf("[I] Ouch, the SIM Card is blocked.\n");
                        break;
                    }
                break;
                case IPC_SEC_PIN_STATUS_INIT_COMPLETE:
                    printf("[3] SIM init complete\n");
                    if(state == MODEM_STATE_NORMAL)
                        state = MODEM_STATE_SIM_OK;

                break;
                case IPC_SEC_PIN_STATUS_PB_INIT_COMPLETE:
                    printf("[I] SIM Phone Book init complete\n");
                break;
            }
        break;
        case IPC_SEC_SIM_ICC_TYPE:
            type = *((char *) resp->data);
            switch(type)
            {
                case IPC_SEC_SIM_CARD_TYPE_UNKNOWN:
                    printf("[I] No SIM card type: unknown (absent?)\n");
                break;
                case IPC_SEC_SIM_CARD_TYPE_SIM:
                case IPC_SEC_SIM_CARD_TYPE_USIM:
                    printf("[I] SIM card found\n");
                break;
            }
        break;
    }
}

void modem_response_sms(struct ipc_client *client, struct ipc_message *resp)
{
    switch(resp->command)
    {
        case IPC_SMS_DEVICE_READY:
            if(state ==  MODEM_STATE_LPM)
            {
                printf("[4] Modem is ready, requesting normal power mode\n");
                modem_exec_power_normal(client);
            }
            else if(state == MODEM_STATE_SIM_OK)
            {
                printf("[5] Modem is fully ready\n");
                modem_set_sms_device_ready(client);
            }
        break;
    }
}

void modem_response_call(struct ipc_client *client, struct ipc_message *resp)
{
    struct ipc_call_status_data *stat;

    switch(resp->command)
    {
        case IPC_CALL_LIST:

            if(in_call) {
                modem_exec_call_answer(client);
                modem_snd_clock_ctrl(client);
                modem_snd_spkr_volume_ctrl(client);
                modem_snd_no_mic_mute(client);
                modem_snd_audio_path_ctrl(client);
            }
/*
            if(out_call)
                modem_snd_no_mic_mute(client);
*/
        break;
        case IPC_CALL_INCOMING:
            printf("[I] Got an incoming call!\n");
            in_call = 1;
            modem_get_call_list(client);
        break;
        case IPC_CALL_STATUS:
            stat = (struct ipc_call_status_data *)resp->data;

            if(stat->status == IPC_CALL_STATUS_DIALING)
            {
                printf("[I] Sending clock ctrl and restore alsa\n");
                modem_snd_clock_ctrl(client);
//        system("alsa_ctl -f /data/alsa_state_modem restore");

                printf("[I] CALL STATUS DIALING!!!\n");

                modem_snd_spkr_volume_ctrl(client);
                modem_snd_audio_path_ctrl(client);

                modem_get_call_list(client);
            }
            if(stat->status == IPC_CALL_STATUS_CONNECTED)
            {
                printf("[I] CALL STATUS CONNECTED!!!\n");
                modem_snd_no_mic_mute(client);
            }
            if(stat->status == IPC_CALL_STATUS_RELEASED)
            {
                printf("[I] CALL STATUS RELEASED!!!\n");
                modem_snd_no_mic_mute(client);
            }
        break;
    }
}

void modem_response_pwr(struct ipc_client *client, struct ipc_message *resp)
{
    int state_n;

    switch(resp->command)
    {
        case IPC_PWR_PHONE_PWR_UP:
            printf("[2] Phone is powered up (LPM)!\n");
            state = MODEM_STATE_LPM;
        break;

        case IPC_PWR_PHONE_STATE:
            state_n = *((int *)resp->data);
#if 0
            switch(state_n)
            {
                /* FIXME: Broken */
                case IPC_PWR_PHONE_STATE_NORMAL:
                    printf("Power state is now: NORMAL\n");
                break;
                case IPC_PWR_PHONE_STATE_LPM:
                    printf("Power state is now: LPM (Low Power Mode)?\n");
                break;
            }
#endif
            state = state_n;
        break;

    }
}

void modem_response_net(struct ipc_client *client, struct ipc_message *resp)
{
    struct ipc_net_regist_response_data *regi;
    struct ipc_net_plmn_entry *plmn;
    char mnc[6];

    switch(resp->command)
    {
        case IPC_NET_REGIST:
            regi = (struct ipc_net_regist_response_data *) resp->data;
            if(regi->status == IPC_NET_REGISTRATION_STATUS_HOME)
            {
                printf("[I] Registered with network successfully!\n");

            }
        break;
        case IPC_NET_SERVING_NETWORK:

            memcpy(mnc, (char *)((char *) resp->data + 3), 5);
            mnc[5]=0;
            printf("[6] Registered with network! Got PLMN (Mobile Network Code): '%s'\n", mnc);
/*
            if(call_done == 0)
            {
                printf("Requesting outgoing call to %s!\n", DEF_CALL_NUMBER);
                modem_exec_call_out(client, DEF_CALL_NUMBER);
            }
            call_done = 1;
*/
        break;
    }
}

void modem_response_handle_rfs(struct ipc_client *client, struct ipc_message *resp)
{
    switch(resp->command)
    {
        case IPC_RFS_NV_READ_ITEM:
            ipc_rfs_nv_read_item(client, resp);
            break;
        case IPC_RFS_NV_WRITE_ITEM:
            ipc_rfs_nv_write_item(client, resp);
            break;
        case IPC_RFS_GET_FILE_INFO:
        case IPC_RFS_GET_HANDLE_INFO:
            ipc_rfs_file_info(client, resp);
            break;
        case IPC_RFS_READ_DIR:
            ipc_rfs_read_dir(client, resp);
            break;
        default:
            ipc_rfs_generic_io(client, resp);
            break;
    }
}

void modem_response_handle(struct ipc_client *client, struct ipc_message *resp)
{
    switch(IPC_GROUP(resp->command))
    {
        case IPC_GROUP_NET:
            modem_response_net(client, resp);
        break;
        case IPC_GROUP_PWR:
            modem_response_pwr(client, resp);
        break;
        case IPC_GROUP_SEC:
            modem_response_sec(client, resp);
        break;
        case IPC_GROUP_SMS:
            modem_response_sms(client, resp);
        break;
        case IPC_GROUP_CALL:
            modem_response_call(client, resp);
        break;
        case IPC_GROUP_DISP:
            if(in_call)
                modem_snd_no_mic_mute(client);
        break;
        case IPC_GROUP_RFS:
            modem_response_handle_rfs(client, resp);
        break;
    }
}


int modem_read_loop(struct ipc_client *client)
{
    struct ipc_message resp;
    int rc;

    memset(&resp, 0, sizeof(resp));

    while(1) {
        usleep(3000);

        rc = ipc_client_poll(client, NULL, NULL);
        if (rc < 0) {
            continue;
        }

        rc = ipc_client_recv(client, &resp);
        if(rc < 0) {
            printf("[E] Can't RECV from modem: please run this again\n");
            break;
        }

        modem_response_handle(client, &resp);

        if(resp.data != NULL)
            free(resp.data);
    }

    return 0;
}

int modem_rfs_read_loop(struct ipc_client *client)
{
    struct ipc_message resp;
    int rc;

    memset(&resp, 0, sizeof(resp));

    while(1) {
        usleep(3000);

        rc = ipc_client_poll(client, NULL, NULL);
        if (rc < 0) {
            continue;
        }

        rc = ipc_client_recv(client, &resp);
        if(rc < 0) {
            printf("[E] Can't RECV from modem: please run this again\n");
            break;
        }

        modem_response_handle(client, &resp);

        if(resp.data != NULL)
            free(resp.data);
    }

    return 0;
}

void modem_log_handler(void *user_data, const char *msg)
{
    int i, l;
    char *message;

    message = strdup(msg);
    l = strlen(message);

    if(l > 1) {
        for(i=l ; i > 0 ; i--)
        {
            if(message[i] == '\n') {
                message[i] = 0;
            } else if(message[i] != 0) {
                break;
            }
        }

        printf("[D] %s\n", message);
    }

    free(message);
}

void modem_log_handler_quiet(void *user_data, const char *msg)
{
    return;
}

int modem_start(struct ipc_client *client)
{
    int rc = -1;

    ipc_client_data_create(client);
    rc = ipc_client_boot(client);
    if(rc < 0)
        return -1;

    usleep(300);

    rc = ipc_client_open(client);
    if(rc < 0)
        return -1;

    rc = ipc_client_power_on(client);
    if(rc < 0)
        return -1;

    return 0;
}

int modem_stop(struct ipc_client *client)
{
    ipc_client_power_off(client);
    ipc_client_close(client);

    return 0;
}

void *rfs_thread(void *vargp)
{
    struct ipc_client *client_rfs;
    int rc;

    client_rfs = ipc_client_create(IPC_CLIENT_TYPE_RFS);

    if (client_rfs == 0) {
        printf("[E] Could not create IPC client; aborting ...\n");
        return NULL;
    }

    rc = ipc_client_data_create(client_rfs);
    if (rc) {
        printf("[E] Failed to create RFS client data; aborting ... \n");
        goto err_data_create;
    }

    ipc_client_log_callback_register(client_rfs, modem_log_handler, NULL);

    rc = ipc_client_open(client_rfs);
    if (rc) {
        printf("[E] Failed to open RFS client; aborting ... \n");
        goto err_data_create;
    }

    printf("[1] Starting modem_read_loop on RFS client\n");
    modem_read_loop(client_rfs);

    ipc_client_close(client_rfs);
err_data_create:
    ipc_client_destroy(client_rfs);

    return NULL;
}

void print_help()
{
    printf("usage: ipc-modem <command>\n");
    printf("commands:\n");
    printf("\tstart                 boot modem and start read loop\n");
    printf("\tboot                  boot modem only\n");
    printf("\tpower-on              power on the modem\n");
    printf("\tpower-off             power off the modem\n");
    printf("arguments:\n");
    printf("\t--debug               enable debug messages\n");
    printf("\t--pin=[PIN]           provide SIM card PIN\n");
}

int main(int argc, char *argv[])
{
    struct ipc_client *client_fmt;
    int c = 0;
    int opt_i = 0;
    int rc = -1;
    int debug = 0;
    pthread_t thread_rfs;

    struct option opt_l[] = {
        {"help",    no_argument,        0,  0 },
        {"debug",   no_argument,        0,  0 },
        {"pin",     required_argument,  0,  0 },
        {0,         0,                  0,  0 }
    };

    if (argc < 2) {
        print_help();
        exit(1);
    }

    while(c >= 0) {
        c = getopt_long(argc, argv, "", opt_l, &opt_i);
        if(c < 0)
            break;

        switch(c) {
            case 0:
                if (strncmp(opt_l[opt_i].name, "help", 4) == 0) {
                    print_help();
                    exit(1);
                } else if(strcmp(opt_l[opt_i].name, "debug") == 0) {
                    debug = 1;
                    printf("[I] Debug enabled\n");
                } else if(strcmp(opt_l[opt_i].name, "pin") == 0) {
                    if(optarg) {
                        if(strlen(optarg) < 8) {
                            printf("[I] Got SIM PIN!\n");
                            memcpy(sim_pin, optarg, 8);
                        } else {
                            printf("[E] SIM PIN is too long!\n");
                            return 1;
                        }
                    }
                }
            break;
        }
    }

    client_fmt = ipc_client_create(IPC_CLIENT_TYPE_FMT);

    if (client_fmt == 0) {
        printf("[E] Could not create IPC client; aborting ...\n");
        goto modem_quit;
    }

    if (debug == 0)
        ipc_client_log_callback_register(client_fmt, modem_log_handler_quiet, NULL);
    else ipc_client_log_callback_register(client_fmt, modem_log_handler, NULL);

    while(optind < argc) {
        if(strncmp(argv[optind], "power-on", 8) == 0) {
            if (ipc_client_power_on(client_fmt) < 0)
                printf("[E] Something went wrong while powering modem on\n");
            goto modem_quit;
        } else if(strncmp(argv[optind], "power-off", 9) == 0) {
            if (ipc_client_power_off(client_fmt) < 0)
                printf("[E] Something went wrong while powering modem off\n");
            goto modem_quit;
        } else if (strncmp(argv[optind], "boot", 9) == 0) {
            rc = ipc_client_boot(client_fmt);
            if (rc < 0)
                printf("[E] Something went wrong while bootstrapping modem\n");
        } else if(strncmp(argv[optind], "start", 5) == 0) {
            printf("[0] Starting modem on FMT client\n");
            rc = modem_start(client_fmt);
            if(rc < 0) {
                printf("[E] Something went wrong with FMT client\n");
                modem_stop(client_fmt);
                return 1;
            }

            pthread_create(&thread_rfs, NULL, rfs_thread, NULL);

            printf("[1] Starting modem_read_loop on FMT client\n");
            modem_read_loop(client_fmt);

            modem_stop(client_fmt);

            pthread_kill(thread_rfs, 9);
            pthread_join(thread_rfs, NULL);
        } else {
            printf("[E] Unknown argument: '%s'\n", argv[optind]);
            print_help();
            return 1;
        }

        optind++;
    }

modem_quit:
    if (client_fmt != 0)
        ipc_client_destroy(client_fmt);

    return 0;
}

// vim:ts=4:sw=4:expandtab
