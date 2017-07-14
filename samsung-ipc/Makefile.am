NULL =

AM_CFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/samsung-ipc \
	-I$(top_srcdir)/samsung-ipc/devices/xmm616 \
	-I$(top_srcdir)/samsung-ipc/devices/xmm626 \
	$(OPENSSL_CFLAGS) \
	$(NULL)

if WANT_DEBUG
AM_CFLAGS += -ggdb -O0 -DDEBUG
endif

lib_LTLIBRARIES = \
	libsamsung-ipc.la \
	$(NULL)

libsamsung_ipc_la_SOURCES = \
	ipc.c \
	ipc.h \
	ipc_devices.c \
	ipc_devices.h \
	ipc_utils.c \
	devices/xmm616/xmm616.c \
	devices/xmm616/xmm616.h \
	devices/xmm626/xmm626.c \
	devices/xmm626/xmm626.h \
	devices/xmm626/xmm626_hsic.c \
	devices/xmm626/xmm626_hsic.h \
	devices/xmm626/xmm626_mipi.c \
	devices/xmm626/xmm626_mipi.h \
	devices/xmm626/xmm626_sec_modem.c \
	devices/xmm626/xmm626_sec_modem.h \
	devices/xmm626/modem.h \
	devices/xmm626/modem_link_device_hsic.h \
	devices/xmm626/modem_prj.h \
	devices/crespo/crespo.c \
	devices/crespo/crespo.h \
	devices/crespo/crespo_modem_ctl.h \
	devices/aries/aries.c \
	devices/aries/aries.h \
	devices/aries/onedram.h \
	devices/aries/phonet.h \
	devices/galaxys2/galaxys2.c \
	devices/galaxys2/galaxys2.h \
	devices/maguro/maguro.c \
	devices/maguro/maguro.h \
	devices/piranha/piranha.c \
	devices/piranha/piranha.h \
	devices/i9300/i9300.c \
	devices/i9300/i9300.h \
	devices/n7100/n7100.c \
	devices/n7100/n7100.h \
	devices/n5100/n5100.c \
	devices/n5100/n5100.h \
	utils.c \
	call.c \
	sms.c \
	sec.c \
	net.c \
	misc.c \
	svc.c \
	gprs.c \
	rfs.c \
	gen.c \
	$(NULL)

libsamsung_ipc_la_LIBADD = \
	$(OPENSSL_LIBS) \
	$(NULL)
