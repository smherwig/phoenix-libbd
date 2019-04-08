#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ext4_config.h>
#include <ext4_blockdev.h>
#include <ext4_errno.h>

#include <rho/rho.h>

#include "bd.h"
#include "mt.h"

#define BDVERITY_BLOCK_SIZE  1024
#define BDVERITY_HASH_SIZE   32

static const char *bdverity_imagepath = NULL;
static FILE *bdverity_devfile = NULL;

static const char *bdverity_mtpath = NULL;
static struct mt *bdverity_mt = NULL;
static uint8_t bdverity_roothash[32] = { 0 };
static struct rho_hmac *bdverity_hmac = NULL;

static int bdverity_open(struct ext4_blockdev *bdev);
static int bdverity_bread(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id,
			 uint32_t blk_cnt);
static int bdverity_bwrite(struct ext4_blockdev *bdev, const void *buf,
			  uint64_t blk_id, uint32_t blk_cnt);
static int bdverity_close(struct ext4_blockdev *bdev);

EXT4_BLOCKDEV_STATIC_INSTANCE(bdverity, BDVERITY_BLOCK_SIZE, 0,
        bdverity_open, bdverity_bread, bdverity_bwrite, bdverity_close,
	    NULL, NULL);

/**************************************
 * HASH FUNCTION FOR MERKLE TREE
 **************************************/

static void
bdverity_hashfn(const void *data, size_t datalen, void *out)
{
    RHO_TRACE_ENTER();

    rho_hmac_update(bdverity_hmac, data, datalen);
    rho_hmac_finish(bdverity_hmac, out);
    rho_hmac_reset(bdverity_hmac, NULL, 0);

    RHO_TRACE_EXIT();
}

/**************************************
 * BLOCK DEVICE INTERFACE
 **************************************/

static int
bdverity_open(struct ext4_blockdev *bdev)
{
    int error = EOK;

    RHO_TRACE_ENTER();

    (void)bdev;

    bdverity_devfile = fopen(bdverity_imagepath, "r+b");
    if (bdverity_devfile == NULL) {
        rho_errno_warn(errno, "fopen(\"%s\", \"r+b\")", bdverity_imagepath);
        error = EIO;
        goto fail;
    }
    setbuf(bdverity_devfile, NULL);

	bdverity.part_offset = 0;
	bdverity.part_size = rho_path_getsize(bdverity_imagepath);
	bdverity.bdif->ph_bcnt = bdverity.part_size / bdverity.bdif->ph_bsize;

    bdverity_mt = mt_open(bdverity_mtpath, bdverity_hashfn, BDVERITY_HASH_SIZE,
            bdverity_roothash);

    goto succeed;

fail:
    if (bdverity_devfile != NULL)
        fclose(bdverity_devfile);

succeed:
    RHO_TRACE_EXIT("error=%d", error);
	return (error);
}

static int
bdverity_bread(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id,
			 uint32_t blk_cnt)
{
	int error = EOK;
    bool valid = 0;
    off_t off = 0;
    uint32_t i = 0;

    RHO_TRACE_ENTER("blk_id=%"PRIu64", blk_cnt=%"PRIu32", ph_bsize=%"PRIu32,
            blk_id, blk_cnt, bdev->bdif->ph_bsize);

	if (!blk_cnt)
        goto done;

    off = blk_id * bdev->bdif->ph_bsize;
	if (fseeko(bdverity_devfile, off, SEEK_SET) == -1) {
        rho_errno_warn(errno, "fseeko(bdverity_devfile, %lld, SEEK_SET)",
                (long long)off);
        error = EIO;
        goto done;
    }

	if (fread(buf, bdev->bdif->ph_bsize * blk_cnt, 1, bdverity_devfile) == 0) {
        rho_warn("fread(buf, %lu, 1, bdverity_devfile)",
                (unsigned long) bdev->bdif->ph_bsize * blk_cnt);
        error = EIO;
        goto done;
    }

    for (i = 0; i < blk_cnt; i++) {
        valid = mt_verify(bdverity_mt, buf + (i * bdev->bdif->ph_bsize),
                bdev->bdif->ph_bsize, blk_id + i);
        if (!valid) {
            rho_warn("blk_id %"PRIu64" did not pass integrity check", blk_id + i);
            error = EIO;
            goto done;
        }
    }

done:
    RHO_TRACE_EXIT("error=%d", error);
	return (error);
}

static int
bdverity_bwrite(struct ext4_blockdev *bdev, const void *buf,
			  uint64_t blk_id, uint32_t blk_cnt)
{
    int error = EOK;
    off_t off = 0;
    uint32_t i = 0;

    RHO_TRACE_ENTER("blk_id=%"PRIu64", blk_cnt=%"PRIu32, blk_id, blk_cnt);

	if (!blk_cnt)
        goto done;

    off = blk_id * bdev->bdif->ph_bsize;
	if (fseeko(bdverity_devfile, off, SEEK_SET)) {
        rho_errno_warn(errno, "fseeko(bdverity_devfile, %lld, SEEK_SET)",
                (long long)off);
        error = EIO;
        goto done;
    }

    for (i = 0; i < blk_cnt; i++) {
	    if (!fwrite(buf + (i * bdev->bdif->ph_bsize), bdev->bdif->ph_bsize, 
                    1, bdverity_devfile)) {
            error = EIO;
            goto done;
        }

        mt_update(bdverity_mt, buf + (i * bdev->bdif->ph_bsize), bdev->bdif->ph_bsize,
                blk_id + i);
    }

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
bdverity_close(struct ext4_blockdev *bdev)
{
    RHO_TRACE_ENTER();
    (void)bdev;

    fclose(bdverity_devfile);
    mt_close(bdverity_mt);

    RHO_TRACE_EXIT();
	return (0);
}

/**************************************
 * INITIALIZATION
 **************************************/
struct ext4_blockdev *
bdverity_init(const char *fspath, const char *mtpath,
        const char *mac_password, uint8_t *roothash)
{
    RHO_TRACE_ENTER("fspath=%s, mtpath=%s, mac_password=%s",
            fspath, mtpath, mac_password);

    bdverity_imagepath = rhoL_strdup(fspath);
    bdverity_mtpath = rhoL_strdup(mtpath);
    memcpy(bdverity_roothash, roothash, 32); /* TODO: don't hardcode */

    /* 
     * For now, we just use the mac_password as is; we need to update 
     * makemerkel.py to use the kdf
     */
#if 0
    /* TODO: let user specify salt, number of iterations, md_type */
    rho_kdf_pbkdf2hmac_oneshot(mac_password, NULL, 0, 1000, RHO_MD_SHA256,
            bdverity_mackey, 32);
#endif
    bdverity_hmac = rho_hmac_create(RHO_MD_SHA256, mac_password,
            strlen(mac_password));

    RHO_TRACE_EXIT();
    return (&bdverity);
}
