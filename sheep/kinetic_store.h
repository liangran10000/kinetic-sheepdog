#ifndef __KINETIC_STORE_H__
#define __KINETIC_STORE_H__
bool is_kinetic_store(char *store);
int kinetic_init_global_pathnames(const char *d, char *argp);
int kinetic_init_config_file(const char *d, char *);
int kinetic_write_config(const char *buf, size_t len, bool force_create);
int kinetic_update_epoch_log(uint32_t epoch, struct sd_node *nodes, size_t nr_nodes);
int kinetic_do_epoch_log_read(uint32_t epoch, struct sd_node *nodes, int len,
			     int *nr_nodes, time_t *timestamp);
uint32_t kinetic_get_latest_epoch(void);
int kinetic_lock_base_dir(const char *d);
int kinetic_init_base_path(const char *d);
int kinetic_init_obj_path( char *argp);
int kinetic_init_epoch_path(const char *base_path, char *addr);
int kinetic_init_config_path(const char *base_path, char *addr);
int kinetic_get_store_path(uint64_t oid, uint8_t ec_index, char *path);
size_t kinetic_get_store_objsize(uint64_t oid);
bool kinetic_exist(uint64_t oid, uint8_t ec_index);
int kinetic_write(uint64_t oid, const struct siocb *iocb);
int kinetic_cleanup(void);
int kinetic_init(void);
int kinetic_read(uint64_t oid, const struct siocb *iocb);
int kinetic_create_and_write(uint64_t oid, const struct siocb *iocb);
int kinetic_link(uint64_t oid, uint32_t tgt_epoch);
int kinetic_update_epoch(uint32_t epoch);
int kinetic_format(void);
int kinetic_remove_object(uint64_t oid, uint8_t ec_index);
int kinetic_get_hash(uint64_t oid, uint32_t epoch, uint8_t *sha1);
int kinetic_purge_obj(void);
int kinetic_check_path_len(const char *path);
uint64_t kinetic_init_path_space(const char *path, bool purge);
int kinetic_remove_epoch(uint32_t epoch);
uint64_t kinetic_init_path_space(const char *path, bool purge);
int kinetic_init_global_pathnames(const char *d, char *argp);
void  *kinetic_update_node(struct sd_node *node, void *ref);
int send_kinetic_req(const struct node_id *node, struct sd_req *hdr, void *data,  uint32_t epoch, uint32_t retries);
#endif
