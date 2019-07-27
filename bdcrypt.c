#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ext4_config.h>
#include <ext4_blockdev.h>
#include <ext4_errno.h>

#include <rho/rho.h>

#include "bd.h"
#include "bd_util.h"

/*
 * TODO: client (the fs) needs to be able to set:
 *  - bdcrypt_imagepath
 *  - bdcrypt_key
 *  - assert that imagepath and key are set before any bd operations.
 *  - let user specify salt, number of iterations, md_type for KDF
 *
 * Also, we need to check what the block size should be.
 * This interface makes it appear as if block size is static,
 * but lwext_mkfs makes it look configurable.
 *
 * THINGS I DON'T UNDERSANTD:
 *  - What is the purpose of th bdcrypt_ph_bbuf static variable?
 *  - what is ext4 partition mode?
 *  - what is the diffference betweent the physical and logical
 *    block sizes?
 */

#define BDCRYPT_BLOCK_SIZE 1024

static const char *bdcrypt_imagepath = NULL;
static uint8_t bdcrypt_key[64] = { 0 };
static FILE *bdcrypt_devfile = NULL;
static struct rho_cipher *bdcrypt_cipher = NULL;

static int bdcrypt_open(struct ext4_blockdev *bdev);
static int bdcrypt_bread(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id,
			 uint32_t blk_cnt);
static int bdcrypt_bwrite(struct ext4_blockdev *bdev, const void *buf,
			  uint64_t blk_id, uint32_t blk_cnt);
static int bdcrypt_close(struct ext4_blockdev *bdev);

/* static uint8_t bdcrypt_ph_bbuf[BDCRYPT_BLOCK_SIZE];
 *
 * static struct ext4_blockdev_iface bdcrypt_iface = {
 *  .open = bdcrypt_open,
 *  .bread = bdcrypt_bread,
 *  .bwrite = bdcrypt_bwrite,
 *  .close = bdcrypt_close,
 *  .lock= NULL,
 *  .unlock = NULL
 *  .ph_bsize = BDCRYPT_BLOCK_SIZE,
 *  .ph_bcnt = 0,
 *  .ph_bbuf = bdcrypt_ph_bbuf
 * };
 *
 * static struct ext4_blockdev bdcrypt = {
 *  .bdif = &bdcrypt_iface,
 *  .part_offset = 0,
 *  .part_size = BDCRYPT_BLOCK_SIZE * 0
 * };
 */
EXT4_BLOCKDEV_STATIC_INSTANCE(bdcrypt, BDCRYPT_BLOCK_SIZE, 0,
        bdcrypt_open, bdcrypt_bread, bdcrypt_bwrite, bdcrypt_close,
	    NULL, NULL);

/**************************************
 * BLOCK DEVICE INTERFACE
 **************************************/

static int
bdcrypt_open(struct ext4_blockdev *bdev)
{
    int error = EOK;

    RHO_TRACE_ENTER();

    (void)bdev;

    bdcrypt_devfile = fopen(bdcrypt_imagepath, "r+b");
    if (bdcrypt_devfile == NULL) {
        rho_errno_warn(errno, "fopen(\"%s\", \"r+b\")", bdcrypt_imagepath);
        error = EIO;
        goto done;
    }

    /* No buffering at file. */
    setbuf(bdcrypt_devfile, NULL);

	bdcrypt.part_offset = 0;
	bdcrypt.part_size = rho_path_getsize(bdcrypt_imagepath);
	bdcrypt.bdif->ph_bcnt = bdcrypt.part_size / bdcrypt.bdif->ph_bsize;


done:
    RHO_TRACE_EXIT("error=%d", error);
	return (error);
}

static int
bdcrypt_bread(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id,
			 uint32_t blk_cnt)
{
	int error = EOK;
    off_t off = 0;
    size_t n = 0;
    uint8_t iv[16] = { 0 };
    size_t outlen = 0;
    size_t extralen = 0;
    uint32_t i = 0;
    uint8_t tmpblk[BDCRYPT_BLOCK_SIZE] = { 0 };

    RHO_TRACE_ENTER("blk_id=%"PRIu64", blk_cnt=%"PRIu32", ph_bsize=%"PRIu32,
            blk_id, blk_cnt, bdev->bdif->ph_bsize);

	if (!blk_cnt)
        goto done;

    /* read in all blocks at once */
    off = blk_id * bdev->bdif->ph_bsize;
    //fprintf(stderr, "bdcrypt_bread: file offset=%ld\n", off);
	if (-1 == fseeko(bdcrypt_devfile, off, SEEK_SET)) {
        rho_errno_warn(errno, "fseek(bdcrypt_devfile, %ld)", off);
        error = EIO;
        goto done;
    }

    n = bdev->bdif->ph_bsize * blk_cnt;
    //fprintf(stderr, "reading %zu bytes\n", n);
	if (!fread(buf, n, 1, bdcrypt_devfile)) {
        rho_warn("fread(bdcrypt_devfile) %zu bytes failed", n);
        error = EIO;
        goto done;
    }

    /* decrypt each block individually */
    for (i = 0; i < blk_cnt; i++) { 
        bd_iv_from_blk_id(blk_id + i, iv, 16);
        //rho_hexdump(iv, 16, "iv");  
        rho_cipher_reset(bdcrypt_cipher, RHO_CIPHER_MODE_DECRYPT, false, NULL, iv);
        rho_cipher_update(bdcrypt_cipher, buf + (i * bdev->bdif->ph_bsize), 
                bdev->bdif->ph_bsize, tmpblk, &outlen);

        //rho_hexdump(tmpblk, BDCRYPT_BLOCK_SIZE, "after rho_cipher_update");
        //fprintf(stderr, "outlen=%zu\n", outlen);
        /* XXX: is 'finish' even needed? */
        rho_cipher_finish(bdcrypt_cipher, tmpblk + outlen, &extralen);
        memcpy(buf + (i * bdev->bdif->ph_bsize), tmpblk, BDCRYPT_BLOCK_SIZE);
    }

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
bdcrypt_bwrite(struct ext4_blockdev *bdev, const void *buf,
			  uint64_t blk_id, uint32_t blk_cnt)
{
	int error = EOK;
    off_t off = 0;
    uint8_t iv[16] = { 0 };
    size_t outlen = 0;
    size_t extralen = 0;
    uint32_t i = 0;
    uint8_t tmpblk[BDCRYPT_BLOCK_SIZE] = { 0 };

    RHO_TRACE_ENTER("blk_id=%"PRIu64", blk_cnt=%"PRIu32, blk_id, blk_cnt);

	if (!blk_cnt)
        goto done;

    off = blk_id * bdev->bdif->ph_bsize;
	if (fseeko(bdcrypt_devfile, off, SEEK_SET)) {
        error = EIO;
        goto done;
    }

    /* encrypt and write each block individually */
    for (i = 0; i < blk_cnt; i++) {
        bd_iv_from_blk_id(blk_id + i, iv, 16);
        rho_cipher_reset(bdcrypt_cipher, RHO_CIPHER_MODE_ENCRYPT, false, NULL, iv);
        rho_cipher_update(bdcrypt_cipher, buf + (i * bdev->bdif->ph_bsize), 
                bdev->bdif->ph_bsize, tmpblk, &outlen);
        /* XXX is 'finish needed? */
        rho_cipher_finish(bdcrypt_cipher, tmpblk + outlen, &extralen);
	    if (!fwrite(tmpblk, bdev->bdif->ph_bsize, 1, bdcrypt_devfile)) {
            error = EIO;
            goto done;
        }
    }

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
bdcrypt_close(struct ext4_blockdev *bdev)
{
    RHO_TRACE_ENTER();

    (void)bdev;
    fclose(bdcrypt_devfile);

    RHO_TRACE_EXIT();
	return (0);
}

/**************************************
 * INITIALIZATION
 **************************************/
struct ext4_blockdev *
bdcrypt_init(const char *path, const char *password, 
        enum rho_cipher_type cipher)
{
    size_t keylen =0;

    RHO_TRACE_ENTER("path=%s, password=%s", path, password);

    bdcrypt_imagepath = rhoL_strdup(path);

    if (cipher == RHO_CIPHER_AES_256_XTS)
        keylen = 64;
    else if (cipher == RHO_CIPHER_AES_256_CBC)
        keylen = 32;
    else
        rho_die("invalid cipher (%ld)\n", (long)cipher);

    rho_kdf_pbkdf2hmac_oneshot(password, NULL, 0, 1000, RHO_MD_SHA256,
        bdcrypt_key, keylen);

    //rho_hexdump(bdcrypt_key, keylen, "bdcrypt_key");

    bdcrypt_cipher = rho_cipher_create(cipher,
            RHO_CIPHER_MODE_ENCRYPT, false, bdcrypt_key, NULL);

    RHO_TRACE_EXIT();
    return (&bdcrypt);
}
