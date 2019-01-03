# This file is part of libsamsung-ipc.
#
# Copyright (C) 2011-2014 Paul Kocialkowski <contact@paulk.fr>
#
# libsamsung-ipc is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# libsamsung-ipc is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with libsamsung-ipc.  If not, see <http://www.gnu.org/licenses/>.

LOCAL_PATH := $(call my-dir)

ifneq (,$(filter crespo fascinate4gmtd fascinate4gubi galaxys4gmtd galaxys4gubi telusgalaxys4gmtd telusgalaxys4gubi,$(TARGET_DEVICE)))
	ipc_device_name := crespo
endif

ifneq (,$(filter galaxysmtd galaxytab,$(TARGET_DEVICE)))
	ipc_device_name := aries
endif

ifneq (,$(filter i9100 galaxys2 n7000,$(TARGET_DEVICE)))
	ipc_device_name := galaxys2
endif

ifneq (,$(filter maguro,$(TARGET_DEVICE)))
	ipc_device_name := maguro
endif

ifneq (,$(filter p5100 p3100 espresso3g,$(TARGET_DEVICE)))
	ipc_device_name := piranha
endif

ifneq (,$(filter i9300,$(TARGET_DEVICE)))
	ipc_device_name := i9300
endif

ifneq (,$(filter n7100,$(TARGET_DEVICE)))
	ipc_device_name := n7100
endif

ifneq (,$(filter n5100,$(TARGET_DEVICE)))
	ipc_device_name := n5100
endif

libsamsung_ipc_local_src_files := \
	samsung-ipc/ipc.c \
	samsung-ipc/ipc_devices.c \
	samsung-ipc/ipc_utils.c \
	samsung-ipc/devices/xmm616/xmm616.c \
	samsung-ipc/devices/xmm626/xmm626.c \
	samsung-ipc/devices/xmm626/xmm626_hsic.c \
	samsung-ipc/devices/xmm626/xmm626_mipi.c \
	samsung-ipc/devices/xmm626/xmm626_sec_modem.c \
	samsung-ipc/devices/crespo/crespo.c \
	samsung-ipc/devices/crespo/crespo_ste_m5730.c \
	samsung-ipc/devices/aries/aries.c \
	samsung-ipc/devices/galaxys2/galaxys2.c \
	samsung-ipc/devices/maguro/maguro.c \
	samsung-ipc/devices/piranha/piranha.c \
	samsung-ipc/devices/i9300/i9300.c \
	samsung-ipc/devices/n7100/n7100.c \
	samsung-ipc/devices/n5100/n5100.c \
	samsung-ipc/utils.c \
	samsung-ipc/call.c \
	samsung-ipc/sms.c \
	samsung-ipc/sec.c \
	samsung-ipc/net.c \
	samsung-ipc/misc.c \
	samsung-ipc/svc.c \
	samsung-ipc/gprs.c \
	samsung-ipc/rfs.c \
	samsung-ipc/gen.c

libsamsung_ipc_local_c_includes := \
	$(LOCAL_PATH)/include \
	$(LOCAL_PATH)/samsung-ipc \
	$(LOCAL_PATH)/samsung-ipc/devices/xmm616/ \
	$(LOCAL_PATH)/samsung-ipc/devices/xmm626/ \
	external/openssl/include

libsamsung_local_cflags := \
	-DIPC_DEVICE_NAME=\"$(ipc_device_name)\" \
	-DDEBUG

libsamsung_ipc_local_shared_libraries := \
	libutils \
	libcrypto

############################################
# Static library version of libsamsung-ipc #
############################################
include $(CLEAR_VARS)

LOCAL_MODULE := libsamsung-ipc
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := $(libsamsung_ipc_local_src_files)

LOCAL_C_INCLUDES := $(libsamsung_ipc_local_c_includes)

LOCAL_CFLAGS := $(libsamsung_local_cflags)
LOCAL_SHARED_LIBRARIES := $(libsamsung_ipc_local_shared_libraries)

include $(BUILD_STATIC_LIBRARY)

############################################
# Shared library version of libsamsung-ipc #
############################################
include $(CLEAR_VARS)

LOCAL_MODULE := libsamsung-ipc
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := $(libsamsung_ipc_local_src_files)

LOCAL_C_INCLUDES := $(libsamsung_ipc_local_c_includes)

LOCAL_CFLAGS := $(libsamsung_local_cflags)
LOCAL_SHARED_LIBRARIES := $(libsamsung_ipc_local_shared_libraries)

include $(BUILD_SHARED_LIBRARY)

##################
# ipc-modem tool #
##################
include $(CLEAR_VARS)

LOCAL_MODULE := ipc-modem
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := tools/ipc-modem.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_STATIC_LIBRARIES := libsamsung-ipc
LOCAL_SHARED_LIBRARIES := libutils

include $(BUILD_EXECUTABLE)

#################
# ipc-test tool #
#################
include $(CLEAR_VARS)

LOCAL_MODULE := ipc-test
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := tools/ipc-test.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_STATIC_LIBRARIES := libsamsung-ipc
LOCAL_SHARED_LIBRARIES := libutils

include $(BUILD_EXECUTABLE)
