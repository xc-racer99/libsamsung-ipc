NULL =

AM_CFLAGS = \
	-I$(top_srcdir)/include \
	$(NULL)

bin_PROGRAMS = \
	ipc-modem \
	ipc-test \
	nv_data-md5 \
	$(NULL)

ipc_modem_SOURCES = ipc-modem.c
ipc_modem_LDADD = $(top_builddir)/samsung-ipc/libsamsung-ipc.la
ipc_modem_LDFLAGS =

ipc_test_SOURCES = ipc-test.c
ipc_test_LDADD = $(top_builddir)/samsung-ipc/libsamsung-ipc.la
ipc_test_LDFLAGS =

nv_data_md5_SOURCES = nv_data-md5.c
nv_data_md5_LDADD = $(top_builddir)/samsung-ipc/libsamsung-ipc.la
nv_data_md5_LDFLAGS =
