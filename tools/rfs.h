#include <samsung-ipc.h>

int ipc_rfs_nv_read_item(struct ipc_client *client, struct ipc_message *message);
int ipc_rfs_nv_write_item(struct ipc_client *client, struct ipc_message *message);
int ipc_rfs_file_info(struct ipc_client *client, struct ipc_message *message);
int ipc_rfs_generic_io(struct ipc_client *client, struct ipc_message *message);
int ipc_rfs_read_dir(struct ipc_client *client, struct ipc_message *message);
