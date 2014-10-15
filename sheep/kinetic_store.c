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
#define INVALID_OID					0x0000000000000000
#define STALE_OID_PREFIX			0x1
#define OBJECT_OID_PREFIX 			0x2
#define EPOCH_OID_PREFIX			0x1
#define DB_VERSION 					"0.0"
#define KINETIC_TAG 				"KINETIC:SHEEPDOG"
#define KINETIC_HMAC				"asdfasdf"
#define KINETIC_CLUSTER_VERSION 	0
#define KINETIC_IDENTITY 			1

#define KINETIC_SD_FORMAT_VERSION 	0x0005
#define KINETIC_SD_CONFIG_SIZE 		(40)
#define KINETIC_TAG_SIZE 			(16)
#define KINETIC_OBJECT_LIMIT		(0x100000)
#define	KINETIC_OBJECT_NAME_LENGTH	13
uint8_t epoch_oid_prefix[]	= {0,0,0,0,0,0,0,0,1};
uint8_t config_oid[]		= {0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0};
uint8_t obj_start[]			= {OBJECT_OID_PREFIX,0,0,0,0,0,0,0,0,0,0,0,0};
uint8_t obj_end[]			= {OBJECT_OID_PREFIX,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF};

uint8_t stale_start[]  		= {STALE_OID_PREFIX,0,0,0,0,0,0,0,0,0,0,0,0};
uint8_t stale_end[] 		= {STALE_OID_PREFIX,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF};

uint8_t epoch_start[] = {EPOCH_OID_PREFIX,0,0,0,0};
uint8_t epoch_end[] = {EPOCH_OID_PREFIX,0xF,0xF,0xF,0xF};
struct kinetic_tag {
#define SHA1_PRESENT 	0x001
#define STALE_OBJECT	0x002
		uint32_t	flags;
		uint32_t	segs;			/* number of segments where each segment is 1M */
		uint64_t	size;			/* size of the object */
		uint64_t 	sha1;			/* SHA1 computed by the sheepdog */
		uint32_t	seg_size;
		uint64_t	linked_oid;
};

struct kinetic_req {
		struct	list_node	list;
        KineticEntry metaData;
        uint8_t oid[KINETIC_OBJECT_NAME_LENGTH];
		struct kinetic_tag tag;
};

typedef struct kinetic_req kinetic_req_t;

struct kinetic_drive {
#define DEFAULT_DRIVE 0x0001
	uint32_t		flags;
	uint32_t		capacity; /* in GB */
	/* FIXME create multiple session per drive */
	KineticSession 	conn;
	KineticSessionHandle 	handle;
	char			ver[16];
	char			tag[16];
	char			base_path[PATH_MAX];
	char			epoch_path[PATH_MAX];
	char			obj_path[PATH_MAX];
	char			stale_path[PATH_MAX];
	char			config_path[PATH_MAX];
	char			hmacBuf[PATH_MAX];
	uint32_t		zone;
	struct list_node	list;
	struct list_head	req_list;
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
static void make_kinetic_req(struct kinetic_drive *drv, struct kinetic_req *req,
						uint32_t len, uint8_t *buf);

int kinetic_write_config(const char *buf, size_t len, bool force_create);


static uint32_t object2epoch(uint8_t *buf)
{
	buf += sizeof(epoch_oid_prefix);
    return (*(uint32_t *)buf);		
}
static void epoch2object(struct kinetic_req *req, uint32_t epoch)
{
	memcpy(req->oid, epoch_oid_prefix, sizeof(epoch_oid_prefix));
	memcpy(&req->oid[sizeof(epoch_oid_prefix)], &epoch, sizeof(epoch));
}


static void stale_oid2object(struct kinetic_req *req, uint64_t oid, uint32_t epoch)
{
	epoch2object(req, epoch);
	req->tag.linked_oid = oid;
}

static void oid2object(struct kinetic_req *req, uint64_t oid, uint32_t seg)
{
	req->oid[0] = OBJECT_OID_PREFIX;
	memcpy(&req->oid[1], &oid, sizeof(oid));
	memcpy(&req->oid[(sizeof(oid)+1)], &seg, sizeof(seg));
}

static void config2oid(struct kinetic_req *req)
{
	memcpy(req->oid, config_oid, sizeof(config_oid));
}

static  kinetic_req_t *alloc_req(void)
{
	struct kinetic_req *req = malloc(sizeof(*req));
	if (req == NULL) 
			sd_err("failed to allocate kinetic_req");
	
	memset(&req->metaData, 0x00, sizeof(req->metaData));
	memset(&req->tag, 0x00, sizeof(req->tag));
	return req;
}

static 	void	free_req(struct kinetic_req *req)
{
	free(req);
}

static KineticStatus kinetic_put(struct kinetic_drive *drv, 
		struct kinetic_req *req, uint64_t oid, uint32_t len, uint8_t *buf)
{  
	KineticStatus status;
	uint32_t i, segs = len/KINETIC_OBJECT_LIMIT;
	if (len % KINETIC_OBJECT_LIMIT) segs++;
	req->tag.size = len;
	req->tag.segs = segs;
	for (i = 0; i < segs; i ++) {
		oid2object(req, oid, i);
		req->tag.seg_size =  MIN(len, KINETIC_OBJECT_LIMIT);
		make_kinetic_req(drv, req, req->tag.seg_size, buf);
		if ((status = KineticClient_Put(drv->handle, &(req->metaData)))
			 != KINETIC_STATUS_SUCCESS){
			sd_err("failed to write object %"PRIx64, oid);
			return SD_RES_NETWORK_ERROR;                                                                                              
		}
		len -= req->tag.seg_size;
		buf += req->tag.seg_size;
	}
	return SD_RES_SUCCESS;
}


static int kinetic_get(struct kinetic_drive *drv,
		struct kinetic_req *req, uint64_t oid, uint32_t len, uint8_t *buf, uint32_t offset)
{  
	KineticStatus status;
	uint32_t i = 0, segs = 0, read_size = 0, req_len;
	assert(offset == 0);
	req_len = MIN(len, KINETIC_OBJECT_LIMIT);
	oid2object(req, oid, i++);
	make_kinetic_req(drv, req, req_len,  buf);
	if (len == 0)
		req->metaData.metadataOnly = true;
	status = KineticClient_Get(drv->handle, &(req->metaData));
	if ( (status != KINETIC_STATUS_SUCCESS) &&
			(status != KINETIC_STATUS_BUFFER_OVERRUN)) {
		sd_err("failed to write %d object %"PRIx64, read_size, oid);
		return SD_RES_NETWORK_ERROR;                                                                                              
	}
	read_size += req_len;
    segs = req->tag.segs;
	while (read_size < len) {
		req_len = MIN((len - read_size), KINETIC_OBJECT_LIMIT);
		buf += req_len;
		assert(i <= segs);
		oid2object(req, oid, i++);
		make_kinetic_req(drv, req, req_len,  buf);
		status = KineticClient_Get(drv->handle, &(req->metaData));
		if ( (status != KINETIC_STATUS_SUCCESS) &&
					(status != KINETIC_STATUS_BUFFER_OVERRUN)){
			sd_err("failed to write object %"PRIx64, oid);
			return SD_RES_NETWORK_ERROR;                                                                                              
		}
		read_size += req_len;
	}
	return SD_RES_SUCCESS;
}

static KineticStatus kinetic_delete(struct kinetic_drive *drv, 
		struct kinetic_req *req, uint64_t oid)
{  
	KineticStatus status;
	uint32_t i, segs;
	oid2object(req, oid, 0);
	make_kinetic_req(drv, req, 0, NULL);
   	req->metaData.metadataOnly = true;
	if ((status = KineticClient_Get(drv->handle, &(req->metaData)))
			 != KINETIC_STATUS_SUCCESS){
			sd_err("failed to get metadata for  object %"PRIx64, oid);
			return SD_RES_NETWORK_ERROR;                                                                                              
	}
    segs = req->tag.segs;
	assert(segs);
	for (i = 0; i < segs; i++) {
		oid2object(req, oid, i);
		make_kinetic_req(drv, req,   0, NULL);
		if ((status = KineticClient_Delete(drv->handle, &(req->metaData)))
		 	!= KINETIC_STATUS_SUCCESS){
			sd_err("failed to delete object ignoring error %"PRIx64 "%"PRIx32,
				 oid, i);
		}
	}
	return SD_RES_SUCCESS;                                                                                              
}


static kinetic_drive_t  *addr2drv(const char *addr)
{
	kinetic_drive_t *drv;
	list_for_each_entry(drv, &drives, list) {
		if (addr == NULL && (drv->flags & DEFAULT_DRIVE))
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

	struct kinetic_drive *drv = oid2drv(oid);
	if (drv)
			return snprintf(path, PATH_MAX, "%s", drv->base_path);
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
	//return md_exist(oid, ec_index);
	struct kinetic_drive *drv = addr2drv(NULL);
	struct kinetic_req *req = alloc_req();
	KineticStatus status;
	bool ret;
	/*FIXME replace with proper error code */
	assert(req != NULL);
	oid2object(req, oid, 0);
	make_kinetic_req(drv, req, 0, NULL);
	req->metaData.force = false;
   	req->metaData.metadataOnly = true;
	status = KineticClient_Get(drv->handle, &(req->metaData));
	if ( (status == KINETIC_STATUS_SUCCESS) || (status == KINETIC_STATUS_BUFFER_OVERRUN))
		ret = true;
	else 
		ret = false;
	free(req);
	return ret;
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
		return ( (uint32_t )(req->metaData.tag.bytesUsed));
}
static void make_kinetic_req(struct kinetic_drive *drv, struct kinetic_req *req,
		uint32_t len, uint8_t *buf)
{
	//req->op = KineticClient_CreateOperation(&drv->conn, &req->reqPDU,
	//		&req->respPDU);
   	req->metaData.algorithm = KINETIC_ALGORITHM_SHA1;
   	req->metaData.newVersion.array = BYTE_ARRAY_NONE;
   	req->metaData.dbVersion.array = BYTE_ARRAY_NONE;
   	req->metaData.tag.array.len  = sizeof(req->tag); 
   	req->metaData.tag.array.data  = (unsigned char *)&req->tag;
   	//req->metaData.tag = BYTE_ARRAY_INIT_FROM_CSTRING(KINETIC_TAG);
   	req->metaData.metadataOnly = false;
	req->metaData.key.array.len = sizeof(req->oid);
	req->metaData.key.array.data = req->oid;
	req->metaData.value.array.data = buf;
	req->metaData.value.array.len = len; 
	req->metaData.force = true;
}

int kinetic_write(uint64_t oid, const struct siocb *iocb)
{
	int ret, flags = prepare_iocb(oid, iocb, false);
	uint32_t len = iocb->length;
	struct kinetic_req *req = alloc_req();
	struct kinetic_drive *drv = addr2drv(NULL);
	if (req == NULL) 
			return SD_RES_NO_MEM;
	if (iocb->epoch < sys_epoch()) {
		sd_debug("%"PRIu32" sys %"PRIu32, iocb->epoch, sys_epoch());
		free_req(req);
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
	if (!kinetic_exist(oid, iocb->ec_index)) {
		free_req(req);
		return SD_RES_NO_OBJ;
	}
	assert(iocb->offset == 0);
	ret =  kinetic_put(drv, req, oid, len, iocb->buf);
	free_req(req);
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
	KineticStatus status;
	sd_info("disconnecting kinetic drive %s", drv->base_path);
	status = KineticClient_Disconnect(&drv->handle);
	if (status != KINETIC_STATUS_SUCCESS){
			sd_err("error in disconnecting the client for %s", drv->conn.host);
	}


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
	struct kinetic_req *req = alloc_req();
	struct kinetic_drive *drv = addr2drv(NULL);
	int ret;

	/*
	 * Make sure oid is in the right place because oid might be misplaced
	 * in a wrong place, due to 'shutdown/restart with less disks' or any
	 * bugs. We need call err_to_sderr() to return EIO if disk is broken.
	 *
	 * For stale path, get_store_stale_path already does kinetic_exist job.
	 */
	if (!is_stale_path(path) && !kinetic_exist(oid, iocb->ec_index)) {
		free_req(req);
		return err_to_sderr(path, oid, ENOENT);
	}
 
	ret =  kinetic_get(drv, req, oid, iocb->length, iocb->buf, iocb->offset);
	free_req(req);
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
	return req->tag.size;
}
size_t kinetic_get_store_objsize(uint64_t oid)
{
	struct kinetic_req *req = malloc(sizeof(*req));
	struct kinetic_drive *drv =  addr2drv(NULL);
	KineticStatus status;
	if (is_erasure_oid(oid)) {
		uint8_t policy = get_vdi_copy_policy(oid_to_vid(oid));
		int d;
		ec_policy_to_dp(policy, &d, NULL);
		return SD_DATA_OBJ_SIZE / d;
	}
 
	oid2object(req, oid, 0);
	make_kinetic_req(drv, req,  0, NULL);
	req->metaData.metadataOnly = true;
	status = KineticClient_Get(drv->handle, &(req->metaData));
	if (unlikely(status != KINETIC_STATUS_SUCCESS)) {
		sd_err("failed to read object %"PRIx64 , oid);
		return 0;                                                                                              
	}
	return  req_obj_size(req);
}

int kinetic_create_and_write(uint64_t oid, const struct siocb *iocb)
{
	int flags = prepare_iocb(oid, iocb, true);
	int ret;
	uint32_t len = iocb->length;
	struct kinetic_drive *drv = addr2drv(NULL);
	struct kinetic_req *req = alloc_req();

	sd_debug("%"PRIx64, oid);

	if (uatomic_is_true(&sys->use_journal) &&
	    journal_write_store(oid, iocb->buf, iocb->length,
				iocb->offset, true)
	    != SD_RES_SUCCESS) {
		sd_err("turn off journaling");
		uatomic_set_false(&sys->use_journal);
		flags |= O_DSYNC;
		sync();
	}

/* FIXME  trimming support required
	obj_size = get_store_objsize(oid);

	trim_zero_blocks(iocb->buf, &offset, &len);

	if (offset != 0 || len != get_objsize(oid)) {
		if (is_sparse_object(oid))
			ret = xftruncate(fd, obj_size);
		else
			ret = prealloc(fd, obj_size);
		if (ret < 0) {
			ret = err_to_sderr(path, oid, errno);
			goto out;
		}
	}
	ret = xpwrite(fd, iocb->buf, len, offset);
*/
	if (req == NULL) 
			return SD_RES_NO_MEM;
	
	assert(iocb->offset == 0);
	if ((ret = kinetic_put(drv, req, oid, len, iocb->buf)) != SD_RES_SUCCESS) {
		sd_err("failed to write object. %m");
		goto out;
	}
	objlist_cache_insert(oid);
out:
	free_req(req);
	return ret;
}
/*
 * To link an object another key is generated with the name
 * containing the object. This will allow to exract the actual
 * object from the new key.
 */

int kinetic_link(uint64_t oid, uint32_t tgt_epoch)
{
	struct kinetic_req *req = malloc(sizeof(*req));
	struct kinetic_drive *drv = addr2drv(NULL);
	KineticStatus status;
	int ret;

	sd_debug("try link %"PRIx64" from snapshot with epoch %d", oid,
		 tgt_epoch);
	memset(req, 0x00, sizeof(*req));
	req->tag.segs = 1;
	stale_oid2object(req, oid, tgt_epoch);
	make_kinetic_req(drv, req, 0, NULL);
	req->metaData.metadataOnly = true;
	if ((status = KineticClient_Put(drv->handle, &(req->metaData)))
		 != KINETIC_STATUS_SUCCESS){
		sd_err("failed to write object %"PRIx64, oid);
		ret = SD_RES_NETWORK_ERROR;                                                                                              
	}
	ret = SD_RES_SUCCESS;
	free_req(req);
	return ret;
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
	struct kinetic_req *req = alloc_req();
	struct kinetic_drive *drv = NULL;
	int ret;
	if (uatomic_is_true(&sys->use_journal))
		journal_remove_object(oid);

	ret =  kinetic_delete(drv, req, oid);
	free_req(req);
	return ret;
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
	struct kinetic_req *req = alloc_req();
	struct kinetic_drive *drv = NULL;
	KineticStatus status;
	uint32_t length;
	uint8_t *buf;
	bool is_readonly_obj = oid_is_readonly(oid);

	oid2object(req, oid, 0);
	make_kinetic_req(drv, req,  0, NULL);
   	req->metaData.metadataOnly = true;
	status = KineticClient_Get(drv->handle, &(req->metaData));
	if (unlikely(status != KINETIC_STATUS_SUCCESS)) {
		sd_debug("not found object %"PRIx64 , oid);
		stale_oid2object(req, oid, epoch);
		make_kinetic_req(drv, req,  0, NULL);
		status = KineticClient_Get(drv->handle, &(req->metaData));
		if (unlikely(status != KINETIC_STATUS_SUCCESS)) {
			sd_err("failed to read object %"PRIx64 , oid);
			free_req(req);
			return SD_RES_NETWORK_ERROR;
		}
	}
	length = req2size(req);
	buf = valloc(length);
	if (buf == NULL) {
		free_req(req);
		return SD_RES_NO_MEM;
	}
	make_kinetic_req(drv, req,  length, buf);
	status = KineticClient_Get(drv->handle, &(req->metaData));
	if (unlikely(status != KINETIC_STATUS_SUCCESS)) {
		sd_err("failed to read object %"PRIx64 , oid);
		free_req(req);
		free(buf);
		return SD_RES_NETWORK_ERROR;
	}
	get_buffer_sha1(buf, length, sha1);
	/*FIXME we shoud set and get SHA1 from metadata */
	if (is_readonly_obj){
	}
	sd_debug("the message digest of %"PRIx64" at epoch %d is %s", oid,
		 epoch, sha1_to_hex(sha1));
	free(buf);
	free_req(req);
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

	int ret = -1;
	struct kinetic_req *req = alloc_req();
	struct kinetic_drive *drv = addr2drv(NULL);
	KineticStatus status;
	if (req == NULL)
		return -1;

	config2oid(req);
	make_kinetic_req(drv, req,
			sizeof(config), (uint8_t *)&config);
	status = KineticClient_Get(drv->handle, &(req->metaData));
	if (unlikely(status != KINETIC_STATUS_SUCCESS)) {
		sd_err("failed to read object %s", config_path);
		//goto exit_init_config_file;
	}
	kinetic_get_cluster_config(&sys->cinfo);
	if ((config.flags & SD_CLUSTER_FLAG_DISKMODE) !=
	    (sys->cinfo.flags & SD_CLUSTER_FLAG_DISKMODE)) {
		sd_err("This sheep can't run because "
		       "exists data format mismatch");
		goto exit_init_config_file;
	}

	config.version = KINETIC_SD_FORMAT_VERSION;
	ret = kinetic_write_config((const char *)&config, sizeof(config), true);
exit_init_config_file:
	free_req(req);
	return ret;

}

int kinetic_write_config(const char *buf, size_t len, bool force_create)
{
	struct kinetic_req *req = alloc_req();
	struct kinetic_drive *drv = addr2drv(NULL); /* FIXME find drv from config */
	KineticStatus status;
    if (req == NULL) 
    		return -1;
    
    if (unlikely(drv == NULL)) {
		sd_err(" no valid drive found");
		free_req(req);
		return -1;
	}
	memset(req, 0x00, sizeof(*req));
	req->tag.segs = 1;
	config2oid(req);
	make_kinetic_req(drv, req, len, (uint8_t *)buf);
	status = KineticClient_Put(drv->handle, &(req->metaData));
	if (unlikely(status != KINETIC_STATUS_SUCCESS)) {
		sd_err("failed to write config");
		free_req(req);
		return -1;                                                                                              
	}
	free_req(req);
	return 0;
}

int kinetic_update_epoch_log(uint32_t epoch, struct sd_node *nodes, size_t nr_nodes)
{
	int ret = SD_RES_SUCCESS, len, nodes_len;
	time_t t;
	char *buf;
	struct kinetic_req *req = alloc_req();
	struct kinetic_drive *drv = addr2drv(NULL);
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

	memset(req, 0x00, sizeof(*req));
	req->tag.segs = 1;
	epoch2object(req, epoch);
	make_kinetic_req(drv, req,  len, (uint8_t *)buf);
	if ((status = KineticClient_Put(drv->handle, &(req->metaData)))
		 != KINETIC_STATUS_SUCCESS){
		sd_err("failed to write epoch  path=%s ", req->oid);
		ret =  SD_RES_NETWORK_ERROR;                                                                                              
	}
	free_req(req);
	free(buf);
	return ret;
}

int kinetic_do_epoch_log_read(uint32_t epoch, struct sd_node *nodes, int len,
			     int *nr_nodes, time_t *timestamp)
{
	int   buf_len, ret;
	struct kinetic_req *req = alloc_req();
	struct kinetic_drive *drv = NULL;
	KineticStatus status;
	buf_len = len + sizeof(*timestamp);
	char *buf = malloc(buf_len);
	if (req == NULL || buf == NULL || drv == NULL) {
			sd_err("no more memory or no drive");
			ret = SD_RES_NO_MEM;
			goto log_read_exit;
	}
	epoch2object(req, epoch);
	make_kinetic_req(drv, req,  len, (uint8_t *)buf);
	if ((status = KineticClient_Get(drv->handle, &(req->metaData)))
		 != KINETIC_STATUS_SUCCESS){
		sd_err("failed to write epoch  path=%s ", req->oid);
		ret = SD_RES_NO_TAG;
		goto log_read_exit;
	}

	if (req->tag.size !=  buf_len) {
		sd_err("epoch %d length mismatch expected:%d found:%" PRIu64, epoch, buf_len,
		 	req->tag.size);
		if (req->tag.size > buf_len)
				ret = SD_RES_BUFFER_SMALL;
		else
				ret = SD_RES_NO_TAG;
		goto log_read_exit;
	}
 	memcpy(nodes, buf, len);	
	*nr_nodes = len / sizeof(struct sd_node);
	if (timestamp)
		memcpy(timestamp, buf + len, sizeof(*timestamp));
	ret = SD_RES_SUCCESS;
log_read_exit:
	if (req) free_req(req);
	if (buf) free(buf);	
	return ret;
}

uint32_t kinetic_get_latest_epoch(void)
{
	KineticRange range;
	ByteBuffer	 key;
	uint8_t		buf[sizeof(epoch_end)];
	/* FIXME complete when key rannge API is supported */
	struct kinetic_req *req = alloc_req();
	struct kinetic_drive *drv =  addr2drv(NULL);
	KineticStatus status;
	if (req == NULL) {
			sd_err("no more memory");
			return 0;
	}
	memset(&range, 0x00, sizeof(range));
	key.array.len = sizeof(buf);
 	key.array.data = buf;
	range.startKey.array.data = epoch_start;
	range.startKey.array.len = sizeof(epoch_start);
	range.endKey.array.data = epoch_end;
	range.endKey.array.len = sizeof(epoch_end);
	range.startKeyInclusive = true;
	range.endKeyInclusive = true;
	range.reverse = true;
	range.maxRequested = 1;
	range.keys = &key;
	free(req);
	status = KineticClient_GetRange(drv->handle, &range);
	if (status == KINETIC_STATUS_SUCCESS && range.returned)
				return object2epoch(buf);
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
	strncpy(drv->conn.host, host, sizeof(drv->conn.host));
	strncpy(drv->base_path, path, sizeof(drv->base_path));
	drv->conn.port = atoi(port);
	drv->conn.nonBlocking = false;
	drv->conn.clusterVersion = KINETIC_CLUSTER_VERSION;
	strncpy(drv->hmacBuf, KINETIC_HMAC, sizeof(drv->hmacBuf));
	drv->conn.hmacKey.len  = strlen(drv->hmacBuf);
	drv->conn.hmacKey.data  = (uint8_t *)drv->hmacBuf;
	drv->conn.identity = KINETIC_IDENTITY;
	
	if((KineticClient_Connect((const KineticSession *)&drv->conn,
			&drv->handle)) != KINETIC_STATUS_SUCCESS) {
			sd_err("kinetic client connetion operation failed for"
			"IP:%s Port:%d ", drv->conn.host, drv->conn.port);
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
int kinetic_init_obj_path(char *drive)
{
	char *p;
	char buf[PATH_MAX];

KineticStatus KineticClient_Init(const char *logFile, int logLevel);
	if (kinetic_check_path_len(drive) < 0)
		return -1;
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
	struct kinetic_req *req = alloc_req();
	struct kinetic_drive *drv = addr2drv(NULL); /* FIXME find drv from epoch */
	KineticStatus status;
	int ret;
	sd_debug("remove epoch %"PRIu32, epoch);
	if (req == NULL) 
			return SD_RES_NO_MEM;
	
	epoch2object(req, epoch);
	make_kinetic_req(drv, req, 0, NULL);
	if ((status = KineticClient_Delete(drv->handle, &(req->metaData)))
		 != KINETIC_STATUS_SUCCESS){
		sd_err("failed to remove epoch %"PRIx32, epoch);
		ret =  SD_RES_NETWORK_ERROR;                                                                                              
	}
	ret = SD_RES_SUCCESS;
	free_req(req);
	return ret;
}

int kinetic_init_global_pathnames(const char *d, char *argp)
{
#define KINETIC_LOG_FILE 		"kinetic.log"

	/* initialize kinetic */
	KineticClient_Init(KINETIC_LOG_FILE, 0);

	if (kinetic_init_obj_path(argp) || kinetic_init_epoch_path(d, argp) ||
		kinetic_init_config_path(d, argp)) {
		KineticClient_DeInit();
		return -1;
	}
	return 0;
}

void  *kinetic_update_node(struct sd_node *node, void *ref)
{
	kinetic_drive_t *drv;
	list_for_each_entry(drv, &drives, list) {
		if ( (ref == NULL && drv) || (drv == ref)){
			node->space = drv->capacity;
			node->zone   = drv->zone;
			memcpy(node->nid.kinetic_addr, drv->conn.host,
					sizeof(node->nid.kinetic_addr));
			node->nid.port = drv->conn.port;

		}
	}
	return NULL;
}

/*===================== STORING Large Objects ====================
 *Object in sheepdog may be over 1MB limit iposed by Kinetic. Additional keys are generated as follows:
 * First Key for a Large Object: Derived form OID such as "OBJ":{OID}
 * Subsequent Keys: "SEG":{OID}:{SEG ID}
 * The first segment is zero and is the main key
 * Subsequent segmenst are numbered as 1,2,3...n
 * Tag filed in the ,etadata is used to store additional information
 */

