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
#include "mt.h"

/*
 * TODO: 
 *  - apply a KDF to the macpassword
 *  - let user specify salt, number of iterations, md_type for KDF
 */

#define BDVERICRYPT_BLOCK_SIZE  4096
#define BDVERICRYPT_HASH_SIZE   32

static const char *bdvericrypt_imagepath = NULL;
static FILE *bdvericrypt_devfile = NULL;
static uint8_t bdvericrypt_enckey[64] = { 0 };
static struct rho_cipher *bdvericrypt_cipher = NULL;

static const char *bdvericrypt_mtpath = NULL;
static uint8_t bdvericrypt_roothash[BDVERICRYPT_HASH_SIZE] = { 0 };
static struct mt *bdvericrypt_mt = NULL;
static struct rho_hmac *bdvericrypt_hmac = NULL;

static int bdvericrypt_open(struct ext4_blockdev *bdev);
static int bdvericrypt_bread(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id,
			 uint32_t blk_cnt);
static int bdvericrypt_bwrite(struct ext4_blockdev *bdev, const void *buf,
			  uint64_t blk_id, uint32_t blk_cnt);
static int bdvericrypt_close(struct ext4_blockdev *bdev);

EXT4_BLOCKDEV_STATIC_INSTANCE(bdvericrypt, BDVERICRYPT_BLOCK_SIZE, 0,
        bdvericrypt_open, bdvericrypt_bread, bdvericrypt_bwrite, bdvericrypt_close,
	    NULL, NULL);

/**************************************
 * HASH FUNCTION FOR MERKLE TREE
 **************************************/

static void
bdvericrypt_hashfn(const void *data, size_t datalen, void *out)
{
    RHO_TRACE_ENTER();

    rho_hmac_update(bdvericrypt_hmac, data, datalen);
    rho_hmac_finish(bdvericrypt_hmac, out);
    rho_hmac_reset(bdvericrypt_hmac, NULL, 0);

    RHO_TRACE_EXIT();
}

/**************************************
 * BLOCK DEVICE INTERFACE
 **************************************/

static int
bdvericrypt_open(struct ext4_blockdev *bdev)
{
    int error = EOK;

    RHO_TRACE_ENTER();

    (void)bdev;

    bdvericrypt_devfile = fopen(bdvericrypt_imagepath, "r+b");
    if (bdvericrypt_devfile == NULL) {
        rho_errno_warn(errno, "fopen(\"%s\", \"r+b\")", bdvericrypt_imagepath);
        error = EIO;
        goto fail;
    }
    setbuf(bdvericrypt_devfile, NULL);

	bdvericrypt.part_offset = 0;
	bdvericrypt.part_size = rho_path_getsize(bdvericrypt_imagepath);
	bdvericrypt.bdif->ph_bcnt = bdvericrypt.part_size / bdvericrypt.bdif->ph_bsize;

    bdvericrypt_mt = mt_open(bdvericrypt_mtpath, bdvericrypt_hashfn, BDVERICRYPT_HASH_SIZE,
            bdvericrypt_roothash);

    goto succeed;

fail:
    if (bdvericrypt_devfile != NULL)
        fclose(bdvericrypt_devfile);

succeed:
    RHO_TRACE_EXIT("error=%d", error);
	return (error);
}

static int
bdvericrypt_bread(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id,
			 uint32_t blk_cnt)
{
	int error = EOK;
    bool valid = 0;
    off_t off = 0;
    uint8_t iv[16] = { 0 };
    size_t outlen = 0;
    size_t extralen = 0;
    uint32_t i = 0;
    uint8_t tmpblk[BDVERICRYPT_BLOCK_SIZE] = { 0 };

    RHO_TRACE_ENTER("blk_id=%"PRIu64", blk_cnt=%"PRIu32", ph_bsize=%"PRIu32,
            blk_id, blk_cnt, bdev->bdif->ph_bsize);

	if (!blk_cnt)
        goto done;

    /* read in all encrypted blocks at once */
    off = blk_id * bdev->bdif->ph_bsize;
	if (fseeko(bdvericrypt_devfile, off, SEEK_SET) == -1) {
        rho_errno_warn(errno, "fseeko(bdvericrypt_devfile, %lld, SEEK_SET)",
                (long long)off);
        error = EIO;
        goto done;
    }

	if (fread(buf, bdev->bdif->ph_bsize * blk_cnt, 1, bdvericrypt_devfile) == 0) {
        rho_warn("fread(buf, %lu, 1, bdvericrypt_devfile)",
                (unsigned long) bdev->bdif->ph_bsize * blk_cnt);
        error = EIO;
        goto done;
    }

    /* 
     * the merkletree is over the encrypted blocks -- verify each encrypted
     * block
     */
    for (i = 0; i < blk_cnt; i++) {
        valid = mt_verify(bdvericrypt_mt, buf + (i * bdev->bdif->ph_bsize), bdev->bdif->ph_bsize, blk_id + i);
        if (!valid) {
            rho_warn("blk_id %"PRIu64" did not pass integrity check", blk_id + i);
            error = EIO;
            goto done;
        }
    }

    /* decrypt each block individually */
    for (i = 0; i < blk_cnt; i++) { 
        bd_iv_from_blk_id(blk_id + i, iv, 16);
        //rho_hexdump(iv, 16, "iv");  
        rho_cipher_reset(bdvericrypt_cipher, RHO_CIPHER_MODE_DECRYPT, false,
                NULL, iv);
        rho_cipher_update(bdvericrypt_cipher, buf + (i * bdev->bdif->ph_bsize),
                bdev->bdif->ph_bsize, tmpblk, &outlen);

        //rho_hexdump(tmpblk, BDVERICRYPT_BLOCK_SIZE, "after rho_cipher_update");
        //fprintf(stderr, "outlen=%zu\n", outlen);
        /* XXX: is 'finish' even needed? */
        rho_cipher_finish(bdvericrypt_cipher, tmpblk + outlen, &extralen);
        memcpy(buf + (i * bdev->bdif->ph_bsize), tmpblk,
                BDVERICRYPT_BLOCK_SIZE);
    }

done:
    RHO_TRACE_EXIT("error=%d", error);
	return (error);
}

static int
bdvericrypt_bwrite(struct ext4_blockdev *bdev, const void *buf,
			  uint64_t blk_id, uint32_t blk_cnt)
{
    int error = EOK;
    off_t off = 0;
    uint8_t iv[16] = { 0 };
    size_t outlen = 0;
    size_t extralen = 0;
    uint32_t i = 0;
    uint8_t tmpblk[BDVERICRYPT_BLOCK_SIZE] = { 0 };

    RHO_TRACE_ENTER("blk_id=%"PRIu64", blk_cnt=%"PRIu32, blk_id, blk_cnt);

	if (!blk_cnt)
        goto done;

    off = blk_id * bdev->bdif->ph_bsize;
	if (fseeko(bdvericrypt_devfile, off, SEEK_SET)) {
        rho_errno_warn(errno, "fseeko(bdvericrypt_devfile, %lld, SEEK_SET)",
                (long long)off);
        error = EIO;
        goto done;
    }

    /* encrypt and write each block individually */
    for (i = 0; i < blk_cnt; i++) {
        bd_iv_from_blk_id(blk_id + i, iv, 16);
        rho_cipher_reset(bdvericrypt_cipher, RHO_CIPHER_MODE_ENCRYPT, false, NULL, iv);
        rho_cipher_update(bdvericrypt_cipher, buf + (i * bdev->bdif->ph_bsize), 
                bdev->bdif->ph_bsize, tmpblk, &outlen);
        /* XXX is 'finish needed? */
        rho_cipher_finish(bdvericrypt_cipher, tmpblk + outlen, &extralen);
	    if (!fwrite(tmpblk, bdev->bdif->ph_bsize, 1, bdvericrypt_devfile)) {
            error = EIO;
            goto done;
        }

        /* update merkle tree based on new encrypted block */
        mt_update(bdvericrypt_mt, tmpblk, bdev->bdif->ph_bsize,
                blk_id + i);
    }


done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
bdvericrypt_close(struct ext4_blockdev *bdev)
{
    RHO_TRACE_ENTER();
    (void)bdev;

    fclose(bdvericrypt_devfile);
    mt_close(bdvericrypt_mt);

    RHO_TRACE_EXIT();
	return (0);
}

/**************************************
 * INITIALIZATION
 **************************************/
struct ext4_blockdev *
bdvericrypt_init(const char *fspath, const char *mtpath, const char *macpassword,
        uint8_t *roothash, const char *encpassword, enum rho_cipher_type cipher)
{
    size_t keylen = 0;

    RHO_TRACE_ENTER("fspath=%s, fspassword=%s, mtpath=%s, macpassword=%s",
            fspath, encpassword, mtpath, macpassword);

    bdvericrypt_imagepath = rhoL_strdup(fspath);
    bdvericrypt_mtpath = rhoL_strdup(mtpath);

    memcpy(bdvericrypt_roothash, roothash, BDVERICRYPT_HASH_SIZE);

    bdvericrypt_hmac = rho_hmac_create(RHO_MD_SHA256, macpassword,
            strlen(macpassword));

    if (cipher == RHO_CIPHER_AES_256_XTS)
        keylen = 64;
    else if (cipher == RHO_CIPHER_AES_256_CBC)
        keylen = 32;
    else
        rho_die("invalid cipher (%ld)\n", (long)cipher);

    rho_kdf_pbkdf2hmac_oneshot(encpassword, NULL, 0, 1000, RHO_MD_SHA256,
            bdvericrypt_enckey, keylen);

    rho_hexdump(bdvericrypt_enckey, keylen, "bdvericrypt_enckey");

    bdvericrypt_cipher = rho_cipher_create(cipher,
            RHO_CIPHER_MODE_ENCRYPT, false, bdvericrypt_enckey, NULL);

    RHO_TRACE_EXIT();
    return (&bdvericrypt);
}
