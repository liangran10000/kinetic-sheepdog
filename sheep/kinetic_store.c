/*
 * kinetic_store.c
 *
 *  Created on: Sep 16, 2014
 *      Author: mshafiq
 */
#include <libgen.h>
#include <linux/falloc.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "sheep_priv.h"
#include "kinetic_store.h"
#include <kinetic_client.h>
#include <string.h>
/* KINETIC KEY STORE Design */
#define CONFIG_OID 					"KINETIC_CONFIG"
#define EPOCH_OID_PREFIX 			"EPOCH:" 
#define STALE_OID_PREFIX 			"STALE:"
#define OBJECT_OID_PREFIX 			"OBJECT:"
#define DB_VERSION 					"0.0"
#define KINETIC_TAG 				"KINETIC:SHEEPDOG"
#define KINETIC_HMAC				"asdfasdf"
#define KINETIC_CLUSTER_VERSION 	1
#define KINETIC_IDENTITY 			1

#define KINETIC_SD_FORMAT_VERSION 	0x0005
#define KINETIC_SD_CONFIG_SIZE 		40
#define KINETIC_TAG_SIZE 			16
struct kinetic_req {
        KineticPDU reqPDU;
        KineticPDU respPDU;
        KineticOperation op;
        KineticKeyValue metaData;
        uint8_t oid[PATH_MAX];
		uint8_t buf[KINETIC_TAG_SIZE];
};

struct kinetic_drive {
#define DEFAULT_DRIVE 0x0001
	uint32_t		flags;
	uint32_t		capacity; /* in GB */
	char			host[16];
	uint32_t		port;
	KineticConnection 	conn;
	char			ver[16];
	char			tag[16];
	char			base_path[PATH_MAX];
	char			epoch_path[PATH_MAX];
	char			obj_path[PATH_MAX];
	char			stale_path[PATH_MAX];
	char			config_path[PATH_MAX];
	struct list_node	list;
	bool			nonBlocking;
	int64_t			clusterVersion;
	int64_t			identity;
	char			hmacBuf[PATH_MAX];
	ByteArray		hmacKey;
	};

typedef struct kinetic_drive kinetic_drive_t;
LIST_HEAD(drives);
 
/*FIXME consolidate with config.c */
static struct sheepdog_config {
	uint64_t ctime;
	uint16_t flags;
	uint8_t copies;
	uint8_t store[STORE_LEN];
	uint8_t shutdown;
	uint8_t copy_policy;
	uint8_t __pad;
	uint16_t version;
	uint64_t space;
} config;
#define CONFIG_PATH "/config"

#define sector_algined(x) ({ ((x) & (SECTOR_SIZE - 1)) == 0; })

static void epoch2oid(struct kinetic_req *req, uint32_t epoch)
{
	snprintf((char *)(req->oid), sizeof(req->oid), "%s%"PRIx32, EPOCH_OID_PREFIX,
		epoch);
}


static void stale_object2oid(struct kinetic_req *req, uint64_t oid, uint32_t epoch)
{
	snprintf((char *)(req->oid), sizeof(req->oid), "%s:%"PRIx32":%"PRIx64, STALE_OID_PREFIX,
		epoch, oid);
}

static void object2oid(struct kinetic_req *req, uint64_t oid)
{
	snprintf((char *)(req->oid), sizeof(req->oid), "%s%" PRIx64,
			OBJECT_OID_PREFIX, oid);
}


static void config2oid(struct kinetic_req *req)
{
	snprintf((char *)&(req->oid), sizeof(req->oid), "%s", CONFIG_OID);
}

static kinetic_drive_t  *addr2drv(const char *addr)
{
	kinetic_drive_t *drv;
	list_for_each_entry(drv, &drives, list) {
		if (addr == NULL && drv->flags & DEFAULT_DRIVE) 
				return drv;
		else
			if (!strncmp(drv->base_path, addr, sizeof(drv->base_path)))
				return drv;
	}
	return NULL;
}

static inline bool iocb_is_aligned(const struct siocb *iocb)
{
	return  sector_algined(iocb->offset) && sector_algined(iocb->length);
}

static int prepare_iocb(uint64_t oid, const struct siocb *iocb, bool create)
{
	int flags = O_DSYNC | O_RDWR;

	if (uatomic_is_true(&sys->use_journal) || sys->nosync == true)
		flags &= ~O_DSYNC;

	if (sys->backend_dio && iocb_is_aligned(iocb)) {
		if (!is_aligned_to_pagesize(iocb->buf))
			panic("Memory isn't aligned to pagesize %p", iocb->buf);
		flags |= O_DIRECT;
	}

	if (create)
		flags |= O_CREAT | O_EXCL;

	return flags;
}

static struct kinetic_drive *oid2drv(uint64_t oid)
{
	/* FIXME */
	return NULL;

}

int kinetic_get_store_path(uint64_t oid, uint8_t ec_index, char *path)
{
		/* FIXME we need to return drive IP Address*/

	struct kinetic_req req;
	struct kinetic_drive *drv = oid2drv(oid);
	object2oid(&req, oid);
	if (drv)
			return snprintf(path, PATH_MAX, "%s:%s", drv->base_path, req.oid);
	*path = '\0';
	return 0;
	/*
		if (is_erasure_oid(oid)) {
		if (unlikely(ec_index >= SD_MAX_COPIES))
			panic("invalid ec_index %d", ec_index);
		return snprintf(path, PATH_MAX, "%s/%016"PRIx64"_%d",
				md_get_object_dir(oid), oid, ec_index);
		}

	return snprintf(path, PATH_MAX, "%s/%016" PRIx64,
			md_get_object_dir(oid), oid);
	*/
}

static int get_store_stale_path(uint64_t oid, uint32_t epoch, uint8_t ec_index,
				char *path)
{
	return md_get_stale_path(oid, epoch, ec_index, path);
}

/*
 * Check if oid is in this nodes (if oid is in the wrong place, it will be moved
 * to the correct one after this call in a MD setup.
 */
bool kinetic_exist(uint64_t oid, uint8_t ec_index)
{
	return md_exist(oid, ec_index);
}

/*FIXME re-write to map to KINETIC status code */
static int err_to_sderr(const char *path, uint64_t oid, int err)
{
	struct stat s;
	char p[PATH_MAX], *dir;

	/* Use a temporary buffer since dirname() may modify its argument. */
	pstrcpy(p, sizeof(p), path);
	dir = dirname(p);

	sd_debug("%s", path);
	switch (err) {
	case ENOENT:
		if (stat(dir, &s) < 0) {
			sd_err("%s corrupted", dir);
			return md_handle_eio(dir);
		}
		sd_debug("object %016" PRIx64 " not found locally", oid);
		return SD_RES_NO_OBJ;
	case ENOSPC:
		/* TODO: stop automatic recovery */
		sd_err("diskfull, oid=%"PRIx64, oid);
		return SD_RES_NO_SPACE;
	case EMFILE:
	case ENFILE:
	case EINTR:
	case EAGAIN:
	case EEXIST:
		sd_err("%m, oid=%"PRIx64, oid);
		/* make gateway try again */
		return SD_RES_NETWORK_ERROR;
	default:
		sd_err("oid=%"PRIx64", %m", oid);
		return md_handle_eio(dir);
	}
}
static uint32_t req2size(struct kinetic_req *req)
{
		return ( *(uint32_t *)(req->metaData.tag.data));
}
static void make_kinetic_req(struct kinetic_drive *drv, struct kinetic_req *req,
		uint32_t len, uint8_t *buf)
{
	req->op = KineticClient_CreateOperation(&drv->conn, &req->reqPDU,
			&req->respPDU);
   	req->metaData.algorithm = KINETIC_PROTO_ALGORITHM_SHA1;
   	req->metaData.newVersion = BYTE_ARRAY_INIT_FROM_CSTRING(DB_VERSION);
   	req->metaData.dbVersion = BYTE_ARRAY_NONE;
   	req->metaData.tag.len  = sizeof(req->buf); 
   	req->metaData.tag.data  = (unsigned char *)&req->buf;
	//*(uint32_t *)req->buf = len;	 
   	req->metaData.tag = BYTE_ARRAY_INIT_FROM_CSTRING(KINETIC_TAG);
   	req->metaData.metadataOnly = false;
	req->metaData.key = BYTE_ARRAY_INIT_FROM_CSTRING((const char *)req->oid);
	req->metaData.value.data = buf;
	req->metaData.value.len = len; 
	req->metaData.force = true;
}

int kinetic_write(uint64_t oid, const struct siocb *iocb)
{
	int flags = prepare_iocb(oid, iocb, false), ret = SD_RES_SUCCESS;
	uint32_t len = iocb->length;
	struct kinetic_req req;
	struct kinetic_drive *drv = NULL;
	KineticStatus status;

	if (iocb->epoch < sys_epoch()) {
		sd_debug("%"PRIu32" sys %"PRIu32, iocb->epoch, sys_epoch());
		return SD_RES_OLD_NODE_VER;
	}

	if (uatomic_is_true(&sys->use_journal) &&
	    unlikely(journal_write_store(oid, iocb->buf, iocb->length, iocb->offset, false))
	    != SD_RES_SUCCESS) {
		sd_err("turn off journaling");
		uatomic_set_false(&sys->use_journal);
		flags |= O_DSYNC;
		sync();
	}
	/*
	 * Make sure oid is in the right place because oid might be misplaced
	 * in a wrong place, due to 'shutdown/restart with less/more disks' or
	 * any bugs. We need call err_to_sderr() to return EIO if disk is broken
	 */
	if (!kinetic_exist(oid, iocb->ec_index))
		return SD_RES_NO_OBJ;
	memset(&req, 0x00, sizeof(req));
	object2oid(&req, oid);
	make_kinetic_req(drv, &req, len, iocb->buf);
	if ((status = KineticClient_Put(&(req.op), &(req.metaData)))
		 != KINETIC_STATUS_SUCCESS){
		sd_err("failed to write object %"PRIx64, oid);
		return SD_RES_NETWORK_ERROR;                                                                                              
	}
	return ret;
}

static int make_stale_dir(const char *path)
{
	/*FIXME create stale key */
	return SD_RES_SUCCESS;
}

static int purge_dir(const char *path)
{
	/*FIXME add flush API */	
	return SD_RES_SUCCESS;
}

static int purge_stale_dir(const char *path)
{
	/*FIXME add flush API */	
	return SD_RES_SUCCESS;
}
static void kinetic_disconnect(struct kinetic_drive *drv)
{

	sd_info("disconnecting kinetic drive %s", drv->base_path);
	KineticClient_Disconnect(&drv->conn);


}
int kinetic_cleanup(void)
{
	int ret;
	struct kinetic_drive *drv;

	ret = for_each_obj_path(purge_stale_dir);
	if (ret != SD_RES_SUCCESS)
		return ret;
	/* disconnect kinetic drives */
	list_for_each_entry(drv, &drives, list) {
		kinetic_disconnect(drv);
		list_del(&drv->list);
		free(drv);
	}
	return SD_RES_SUCCESS;
}

static int init_vdi_state(uint64_t oid, const char *wd, uint32_t epoch)
{
	int ret;
	struct sd_inode *inode = xzalloc(SD_INODE_HEADER_SIZE);
	struct siocb iocb = {
		.epoch = epoch,
		.buf = inode,
		.length = SD_INODE_HEADER_SIZE,
	};

	ret = kinetic_read(oid, &iocb);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read inode header %" PRIx64 " %" PRId32
		       "wat %s", oid, epoch, wd);
		goto out;
	}

	add_vdi_state(oid_to_vid(oid), inode->nr_copies,
		      vdi_is_snapshot(inode), inode->copy_policy);
	atomic_set_bit(oid_to_vid(oid), sys->vdi_inuse);

	ret = SD_RES_SUCCESS;
out:
	free(inode);
	return ret;
}

static int init_objlist_and_vdi_bitmap(uint64_t oid, const char *wd,
				       uint32_t epoch, uint8_t ec_index,
				       struct vnode_info *vinfo,
				       void *arg)
{
	int ret;
	objlist_cache_insert(oid);

	if (is_vdi_obj(oid)) {
		sd_debug("found the VDI object %" PRIx64" epoch %"PRIu32
			 " at %s", oid, epoch, wd);
		ret = init_vdi_state(oid, wd, epoch);
		if (ret != SD_RES_SUCCESS)
			return ret;
	}
	return SD_RES_SUCCESS;
}

int kinetic_init(void)
{
	int ret;
	sd_debug("use kinetic store driver");
	ret = for_each_obj_path(make_stale_dir);
	if (ret != SD_RES_SUCCESS)
		return ret;
	for_each_object_in_stale(init_objlist_and_vdi_bitmap, NULL);

	return for_each_object_in_wd(init_objlist_and_vdi_bitmap, true, NULL);
}

static int kinetic_read_from_path(uint64_t oid, const char *path,
				  const struct siocb *iocb)
{
	int ret = SD_RES_SUCCESS;
	struct kinetic_req req;
	struct kinetic_drive *drv = NULL;
	KineticStatus status;

	/*
	 * Make sure oid is in the right place because oid might be misplaced
	 * in a wrong place, due to 'shutdown/restart with less disks' or any
	 * bugs. We need call err_to_sderr() to return EIO if disk is broken.
	 *
	 * For stale path, get_store_stale_path already does kinetic_exist job.
	 */
	if (!is_stale_path(path) && !kinetic_exist(oid, iocb->ec_index))
		return err_to_sderr(path, oid, ENOENT);
 
	memset(&req, 0x00, sizeof(req));
	object2oid(&req, oid);
	make_kinetic_req(drv, &req,  iocb->length, iocb->buf);
	status = KineticClient_Get(&(req.op), &(req.metaData));
	if (unlikely(status != KINETIC_STATUS_SUCCESS)) {
		sd_err("failed to read object %"PRIx64 , oid);
		return SD_RES_NETWORK_ERROR;                                                                                              
	}
	return ret;
}



int kinetic_read(uint64_t oid, const struct siocb *iocb)
{
	int ret;
	char path[PATH_MAX];

	kinetic_get_store_path(oid, iocb->ec_index, path);
	ret = kinetic_read_from_path(oid, path, iocb);

	/*
	 * If the request is against the older epoch, try to read from
	 * the stale directory
	 */
	if (ret == SD_RES_NO_OBJ && iocb->epoch > 0 &&
	    iocb->epoch < sys_epoch()) {
		get_store_stale_path(oid, iocb->epoch, iocb->ec_index, path);
		ret = kinetic_read_from_path(oid, path, iocb);
	}

	return ret;
}


static size_t  req_obj_size(struct kinetic_req *req)
{
  /* FIXME */
  return (size_t)0;

}
size_t kinetic_get_store_objsize(uint64_t oid)
{
	struct kinetic_req req;
	struct kinetic_drive *drv =  addr2drv(NULL);
	KineticStatus status;
	if (is_erasure_oid(oid)) {
		uint8_t policy = get_vdi_copy_policy(oid_to_vid(oid));
		int d;
		ec_policy_to_dp(policy, &d, NULL);
		return SD_DATA_OBJ_SIZE / d;
	}
 
	memset(&req, 0x00, sizeof(req));
	object2oid(&req, oid);
	make_kinetic_req(drv, &req,  0, NULL);
	status = KineticClient_Get(&(req.op), &(req.metaData));
	req.metaData.metadataOnly = true;
	if (unlikely(status != KINETIC_STATUS_SUCCESS)) {
		sd_err("failed to read object %"PRIx64 , oid);
		return 0;                                                                                              
	}
	return  req_obj_size(&req);
}

int kinetic_create_and_write(uint64_t oid, const struct siocb *iocb)
{
	return kinetic_write(oid, iocb);
}
/*
 * To link an object another key is generated with the name
 * containing the object. This will allow to exract the actual
 * object from the new key.
 */

int kinetic_link(uint64_t oid, uint32_t tgt_epoch)
{
	struct kinetic_req req;
	struct kinetic_drive *drv = addr2drv(NULL);
	KineticStatus status;

	sd_debug("try link %"PRIx64" from snapshot with epoch %d", oid,
		 tgt_epoch);
	memset(&req, 0x00, sizeof(req));
	stale_object2oid(&req, oid, tgt_epoch);
	make_kinetic_req(drv, &req, 0, NULL);
	req.metaData.metadataOnly = true;
	if ((status = KineticClient_Put(&(req.op), &(req.metaData)))
		 != KINETIC_STATUS_SUCCESS){
		sd_err("failed to write object %"PRIx64, oid);
		return SD_RES_NETWORK_ERROR;                                                                                              
	}
	return SD_RES_SUCCESS;
}

/*
 * For replicated object, if any of the replica belongs to this node, we
 * consider it not stale.
 *
 * For erasure coded object, since every copy is unique and if it migrates to
 * other node(index gets changed even it has some other copy belongs to it)
 * because of hash ring changes, we consider it stale.
 */
static bool oid_stale(uint64_t oid, int ec_index, struct vnode_info *vinfo)
{
	uint32_t i, nr_copies;
	const struct sd_vnode *v;
	bool ret = true;
	const struct sd_vnode *obj_vnodes[SD_MAX_COPIES];

	nr_copies = get_obj_copy_number(oid, vinfo->nr_zones);
	oid_to_vnodes(oid, &vinfo->vroot, nr_copies, obj_vnodes);
	for (i = 0; i < nr_copies; i++) {
		v = obj_vnodes[i];
		if (vnode_is_local(v)) {
			if (ec_index < SD_MAX_COPIES) {
				if (i == ec_index)
					ret = false;
			} else {
				ret = false;
			}
			break;
		}
	}

	return ret;
}

static int move_object_to_stale_dir(uint64_t oid, const char *wd,
				    uint32_t epoch, uint8_t ec_index,
				    struct vnode_info *vinfo, void *arg)
{
	char path[PATH_MAX], stale_path[PATH_MAX];
	uint32_t tgt_epoch = *(uint32_t *)arg;

	/* ec_index from md.c is reliable so we can directly use it */
	if (ec_index < SD_MAX_COPIES) {
		snprintf(path, PATH_MAX, "%s/%016"PRIx64"_%d",
			 md_get_object_dir(oid), oid, ec_index);
		snprintf(stale_path, PATH_MAX,
			 "%s/.stale/%016"PRIx64"_%d.%"PRIu32,
			 md_get_object_dir(oid), oid, ec_index, tgt_epoch);
	} else {
		snprintf(path, PATH_MAX, "%s/%016" PRIx64,
			 md_get_object_dir(oid), oid);
		snprintf(stale_path, PATH_MAX, "%s/.stale/%016"PRIx64".%"PRIu32,
			 md_get_object_dir(oid), oid, tgt_epoch);
	}

	/* FIXME rename key with stale */

	sd_debug("moved object %"PRIx64, oid);
	return SD_RES_SUCCESS;
}

static int check_stale_objects(uint64_t oid, const char *wd, uint32_t epoch,
			       uint8_t ec_index, struct vnode_info *vinfo,
			       void *arg)
{
	if (oid_stale(oid, ec_index, vinfo))
		return move_object_to_stale_dir(oid, wd, 0, ec_index,
						NULL, arg);

	return SD_RES_SUCCESS;
}

int kinetic_update_epoch(uint32_t epoch)
{
	assert(epoch);
	return for_each_object_in_wd(check_stale_objects, false, &epoch);
}

int kinetic_format(void)
{
	unsigned ret;

	sd_debug("try get a clean store");
	ret = for_each_obj_path(purge_dir);
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (sys->enable_object_cache)
		object_cache_format();

	return SD_RES_SUCCESS;
}

int kinetic_remove_object(uint64_t oid, uint8_t ec_index)
{
	struct kinetic_req req;
	struct kinetic_drive *drv = NULL;
	KineticStatus status;
	if (uatomic_is_true(&sys->use_journal))
		journal_remove_object(oid);

	memset(&req, 0x00, sizeof(req));
	object2oid(&req, oid);
	make_kinetic_req(drv, &req,   0, NULL);
	if ((status = KineticClient_Delete(&(req.op), &(req.metaData)))
		 != KINETIC_STATUS_SUCCESS){
		sd_err("failed to delete  object %"PRIx64, oid);
		return SD_RES_NETWORK_ERROR;                                                                                              
	}
	return SD_RES_SUCCESS;
}


static int get_object_path(uint64_t oid, uint32_t epoch, char *path,
			   size_t size)
{
	if (kinetic_exist(oid, 0)) {
		snprintf(path, PATH_MAX, "%s/%016"PRIx64,
			 md_get_object_dir(oid), oid);
	} else {
		get_store_stale_path(oid, epoch, 0, path);
		if (access(path, F_OK) < 0) {
			if (errno == ENOENT)
				return SD_RES_NO_OBJ;
			return SD_RES_EIO;
		}

	}

	return SD_RES_SUCCESS;
}

int kinetic_get_hash(uint64_t oid, uint32_t epoch, uint8_t *sha1)
{
	int ret = SD_RES_SUCCESS;
	struct kinetic_req req;
	struct kinetic_drive *drv = NULL;
	KineticStatus status;
	uint32_t length;
	uint8_t *buf;
	bool is_readonly_obj = oid_is_readonly(oid);

	memset(&req, 0x00, sizeof(req));
	object2oid(&req, oid);
	make_kinetic_req(drv, &req,  0, NULL);
   	req.metaData.metadataOnly = true;
	status = KineticClient_Get(&(req.op), &(req.metaData));
	if (unlikely(status != KINETIC_STATUS_SUCCESS)) {
		sd_debug("not found object %"PRIx64 , oid);
		memset(&req, 0x00, sizeof(req));
		stale_object2oid(&req, oid, epoch);
		make_kinetic_req(drv, &req,  0, NULL);
		status = KineticClient_Get(&(req.op), &(req.metaData));
		if (unlikely(status != KINETIC_STATUS_SUCCESS)) {
			sd_err("failed to read object %"PRIx64 , oid);
				return SD_RES_NETWORK_ERROR;
		}
	}
	length = req2size(&req);
	buf = valloc(length);
	if (buf == NULL)
		return SD_RES_NO_MEM;
	make_kinetic_req(drv, &req,  length, buf);
	status = KineticClient_Get(&(req.op), &(req.metaData));
	if (unlikely(status != KINETIC_STATUS_SUCCESS)) {
		sd_err("failed to read object %"PRIx64 , oid);
		free(buf);
		return SD_RES_NETWORK_ERROR;
	}
	get_buffer_sha1(buf, length, sha1);
	/*FIXME we shoud set and get SHA1 from metadata */
	if (is_readonly_obj){
	}
	sd_debug("the message digest of %"PRIx64" at epoch %d is %s", oid,
		 epoch, sha1_to_hex(sha1));
	return ret;

}

int kinetic_purge_obj(void)
{
	/*
	uint32_t tgt_epoch = get_latest_epoch();

	return for_each_object_in_wd(move_object_to_stale_dir, true,
				     &tgt_epoch);
    */
	return SD_RES_SUCCESS;
}

#define KINETIC_DRIVER "kinetic"

bool is_kinetic_store(char *store)
{
	return (strncmp(store, KINETIC_DRIVER, strlen(KINETIC_DRIVER)) == 0 ? true: false);
}
static struct store_driver kinetic_store = {
	.name = KINETIC_DRIVER,
	.init = kinetic_init,
	.exist = kinetic_exist,
	.create_and_write = kinetic_create_and_write,
	.write = kinetic_write,
	.read = kinetic_read,
	.link = kinetic_link,
	.update_epoch = kinetic_update_epoch,
	.cleanup = kinetic_cleanup,
	.format = kinetic_format,
	.remove_object = kinetic_remove_object,
	.get_hash = kinetic_get_hash,
	.purge_obj = kinetic_purge_obj,
};

add_store_driver(kinetic_store);

/*
 * FIXME The following functions should be added in each store driver
 */
int kinetic_init_base_path(const char *d)
{
	/* We will create Kinetic drive later
	struct kinetic_drive *drv = NULL;
	strncpy(drv->base_path, d, sizeof(drv->base_path));
	if (xmkdir(d, sd_def_dmode) < 0) {
		sd_err("cannot create the directory %s (%m)", d);
		return -1;
	}
   */
	return 0;
}

/*FIXME consolidate with config.c */
static int kinetic_get_cluster_config(struct cluster_info *cinfo)
{
	cinfo->ctime = config.ctime;
	cinfo->nr_copies = config.copies;
	cinfo->flags = config.flags;
	cinfo->copy_policy = config.copy_policy;
	memcpy(cinfo->store, config.store, sizeof(config.store));

	return SD_RES_SUCCESS;
}

int kinetic_init_config_file(const char *d, char *argp)
{

	int ret = 0;
	struct kinetic_req req;
	struct kinetic_drive *drv = NULL;
	KineticStatus status;
	char buf[PATH_MAX], *drive, *ptrs;
	strncpy(buf, argp, sizeof(buf));
	if ( ((drive = strtok_r(buf, ",", &ptrs)) == NULL) ||
			((drive = strtok_r(NULL, ",", &ptrs)) == NULL) ) {
			sd_err("invalid drive");
			return 1;
	}
	/* FIXME */
	return ret;	
	memset(&req, 0x00, sizeof(req));
	config2oid(&req);
	make_kinetic_req(drv, &req,  sizeof(config), (uint8_t *)&config);
	status = KineticClient_Get(&(req.op), &(req.metaData));
	if (unlikely(status != KINETIC_STATUS_SUCCESS)) {
		sd_err("failed to read object %s", config_path);
		return -1;                                                                                              
	}
	kinetic_get_cluster_config(&sys->cinfo);
	if ((config.flags & SD_CLUSTER_FLAG_DISKMODE) !=
	    (sys->cinfo.flags & SD_CLUSTER_FLAG_DISKMODE)) {
		sd_err("This sheep can't run because "
		       "exists data format mismatch");
		return -1;
	}
	config.version = KINETIC_SD_FORMAT_VERSION;
	if (kinetic_write_config((const char *)&config, sizeof(config), true) != SD_RES_SUCCESS)
		return -1;
	return ret;

}

int kinetic_write_config(const char *buf, size_t len, bool force_create)
{
	struct kinetic_req req;
	struct kinetic_drive *drv = addr2drv(NULL); /* FIXME find drv from config */
	KineticStatus status;
    if (unlikely(drv == NULL)) {
		sd_err(" no valid drive found");
		return -1;
	}
	memset(&req, 0x00, sizeof(req));
	config2oid(&req);
	make_kinetic_req(drv, &req, len, (uint8_t *)buf);
	status = KineticClient_Put(&(req.op), &(req.metaData));
	if (unlikely(status != KINETIC_STATUS_SUCCESS)) {
		sd_err("failed to write config");
		return -1;                                                                                              
	}
	return 0;
}

int kinetic_update_epoch_log(uint32_t epoch, struct sd_node *nodes, size_t nr_nodes)
{
	int ret, len, nodes_len;
	time_t t;
	char *buf;
	struct kinetic_req req;
	struct kinetic_drive *drv = NULL;
	KineticStatus status;

	/* Piggyback the epoch creation time for 'dog cluster info' */
	time(&t);
	nodes_len = nr_nodes * sizeof(struct sd_node);
	len = nodes_len + sizeof(time_t);
	buf = xmalloc(len);
	memcpy(buf, nodes, nodes_len);
	memcpy(buf + nodes_len, &t, sizeof(time_t));

	/*
	 * rb field is unused in epoch file, zero-filling it
	 * is good for epoch file recovery because it is unified
	 */
	for (int i = 0; i < nr_nodes; i++)
		memset(buf + i * sizeof(struct sd_node)
				+ offsetof(struct sd_node, rb),
				0, sizeof(struct rb_node));

	memset(&req, 0x00, sizeof(req));
	epoch2oid(&req, epoch);
	make_kinetic_req(drv, &req,  len, (uint8_t *)buf);
	if ((status = KineticClient_Put(&(req.op), &(req.metaData)))
		 != KINETIC_STATUS_SUCCESS){
		sd_err("failed to write epoch  path=%s ", req.oid);
		ret =  SD_RES_NETWORK_ERROR;                                                                                              
	}

	free(buf);
	return ret;
}

int kinetic_do_epoch_log_read(uint32_t epoch, struct sd_node *nodes, int len,
			     int *nr_nodes, time_t *timestamp)
{
	int  ret, buf_len;
	struct kinetic_req req;
	struct kinetic_drive *drv = NULL;
	KineticStatus status;
	buf_len = len + sizeof(*timestamp);
	char *buf = malloc(buf_len);
	memset(&req, 0x00, sizeof(req));
	epoch2oid(&req, epoch);
	make_kinetic_req(drv, &req,  len, (uint8_t *)buf);
	if ((status = KineticClient_Get(&(req.op), &(req.metaData)))
		 != KINETIC_STATUS_SUCCESS){
		sd_err("failed to write epoch  path=%s ", req.oid);
		ret =  SD_RES_NETWORK_ERROR;                                                                                              
	}

	/* FIXME we should first check actual length of the key
 	* instead of the user supplied length
 	*/
 	memcpy(nodes, buf, len);	
	*nr_nodes = len / sizeof(struct sd_node);
	if (timestamp)
		memcpy(timestamp, buf + len, sizeof(*timestamp));
	return SD_RES_SUCCESS;
}

uint32_t kinetic_get_latest_epoch(void)
{
#define EPOCH_START 0x00000000
#define EPOCH_END	0xFFFFFFFF
	/* FIXME complete when key rannge API is supported */
	struct kinetic_req req;
	struct kinetic_drive *drv =  addr2drv(NULL);
	KineticStatus status;
	memset(&req, 0x00, sizeof(req));
	epoch2oid(&req, EPOCH_START);
	make_kinetic_req(drv, &req,  0, NULL);
	//status = KineticClient_(&(req.op), &(req.metaData));
	req.metaData.metadataOnly = true;
	if (unlikely(status != KINETIC_STATUS_SUCCESS)) {
		sd_err("failed to read epoch ");
		return -1;                                                                                              
	}

	return 0;
}

int kinetic_lock_base_dir(const char *d)
{
#define LOCK_PATH "lock"
	/* FIXME create a lock key and keep on retrying until 
	 * success.
	 */
	int ret = 0;
	return ret;
}

int kinetic_check_path_len(const char *path)
{
	int len = strlen(path);
	if (len > PATH_MAX) {
		sd_err("insanely long object directory %s", path);
		return -1;
	}
	return 0;
}
static bool kinetic_add_disk(char *path, bool flag)
{
	char *host, *port, *ptrs, buf[PATH_MAX];
	KineticStatus status;

	struct kinetic_drive *drv = malloc(sizeof(*drv));
	if(drv == NULL) {
		sd_err("allocation of disk memory  failed");
		return false;
	}
	memset(drv, 0x00, sizeof(*drv));
	if (flag)
			drv->flags |= DEFAULT_DRIVE;
	INIT_LIST_NODE(&drv->list);
	strncpy(buf, path, sizeof(buf));
	host = strtok_r(buf, ":", &ptrs);
	if (host == NULL) {
		sd_err("invalid drive ip address");
		return false;
	}
	port = strtok_r(NULL, ":", &ptrs);
	if (port == NULL) {
		sd_err("invalid drive ip address");
		return false;
	}
	strncpy(drv->host, host, sizeof(drv->host));
	strncpy(drv->base_path, path, sizeof(drv->base_path));
	drv->port = atoi(port);
	drv->nonBlocking = false;
	drv->clusterVersion = KINETIC_CLUSTER_VERSION;
	strncpy(drv->hmacBuf, KINETIC_HMAC, sizeof(drv->hmacBuf));
	drv->hmacKey = BYTE_ARRAY_INIT_FROM_CSTRING(drv->hmacBuf);
	drv->identity = KINETIC_IDENTITY;
	
	/* FIXME wrong error code is returned upon success */
	if((status = KineticClient_Connect(&drv->conn, (const char *)&drv->host,
			drv->port, drv->nonBlocking, drv->clusterVersion,
			drv->identity, drv->hmacKey)) == 0) {
			sd_err("kinetic client connetion operation failed for"
			"IP:%s Port:%d status:%d\n", drv->host, drv->port, status);
		return SD_RES_NETWORK_ERROR;                                                                                              
	}                                                          

	list_add_tail(&drv->list, &drives);
	return SD_RES_SUCCESS;
}

static int is_kinetic_meta_store(const char *path)
{
	char conf[PATH_MAX];
	char epoch[PATH_MAX];

	snprintf(conf, PATH_MAX, "%s/config", path);
	snprintf(epoch, PATH_MAX, "%s/epoch", path);
	if (!access(conf, R_OK) && !access(epoch, R_OK))
		return true;

	return false;
}
int kinetic_init_obj_path(const char *base_path, char *drive)
{
	char *p;
	int len;
	char buf[PATH_MAX];

	if (kinetic_check_path_len(base_path) < 0)
		return -1;

#define OBJ_PATH "/obj"
	len = strlen(base_path) + strlen(OBJ_PATH) + 1;
	obj_path = xzalloc(len);
	snprintf(obj_path, len, "%s" OBJ_PATH, base_path);
    strncpy(buf, drive, sizeof(buf));
	/* Eat up the first component */
	strtok(buf, ",");
	p = strtok(NULL, ",");
	if (!p) {
		/*
		 * If We have only one path, meta-store and object-store share
		 * it. This is helpful to upgrade old sheep cluster to
		 * the MD-enabled.
		 */
		if (kinetic_add_disk(drive, true) != SD_RES_SUCCESS)
			return -1;
		md_add_disk(drive, false);
	} else {
		do {
			if (is_kinetic_meta_store(p)) {
				sd_err("%s is meta-store, abort", p);
				return -1;
			}
			if(kinetic_add_disk(p, true) != SD_RES_SUCCESS)
				return -1;
			md_add_disk(p, false);
		} while ((p = strtok(NULL, ",")));
	}

	if (md_nr_disks() <= 0) {
		sd_err("There isn't any available disk!");
		return -1;
	}

	return 0;
}


int kinetic_init_config_path(const char *path, char *addr)
{
	/* FIXME */
	return 0;
}

int kinetic_init_epoch_path(const char *path, char *addr)
{
	/* FIXME */
	return 0;
}
 uint64_t kinetic_init_path_space(const char *path, bool purge)
{
	 /* FIXME
	  *
	  *use admin API to get the disk size
	*/

	 uint64_t space = 1024  * 1024;
	 space *= space;
	 sd_debug("returning disk space of %" PRIx64, space);
	 return space;
}

int kinetic_remove_epoch(uint32_t epoch)
{
	struct kinetic_req req;
	struct kinetic_drive *drv = NULL; /* FIXME find drv from epoch */
	KineticStatus status;
	sd_debug("remove epoch %"PRIu32, epoch);
	memset(&req, 0x00, sizeof(req));
	epoch2oid(&req, epoch);
	make_kinetic_req(drv, &req, 0, NULL);
	if ((status = KineticClient_Delete(&(req.op), &(req.metaData)))
		 != KINETIC_STATUS_SUCCESS){
		sd_err("failed to remove epoch %"PRIx32, epoch);
		return SD_RES_NETWORK_ERROR;                                                                                              
	}
	return SD_RES_SUCCESS;
}

int kinetic_init_global_pathnames(const char *d, char *argp)
{

#define KINETIC_LOG_FILE 		"kinetic.log"
	char buf[PATH_MAX], *drive, *ptrs;
	strncpy(buf, argp, sizeof(buf));
	if ( ((drive = strtok_r(buf, ",", &ptrs)) == NULL) ||
			((drive = strtok_r(NULL, ",", &ptrs)) == NULL) ) {
			sd_err("invalid drive");
			return 1;
	}
	/* initialize kinetic */
	KineticClient_Init(KINETIC_LOG_FILE);

	if (kinetic_init_obj_path(d, drive) || kinetic_init_epoch_path(d, drive) ||
		kinetic_init_config_path(d, drive))
			return -1;
	return 0;
}
