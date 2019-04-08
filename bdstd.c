/*
 * Bassed on lwext4's blockdev/linux/filedev.c:
 *
 * Copyright (c) 2013 Grzegorz Kostka (kostka.grzegorz@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * - The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Modifications by anonymous.
 */

#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <ext4_config.h>
#include <ext4_blockdev.h>
#include <ext4_errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <rho/rho.h>

#include "bd.h"

/**@brief   Image block size.*/
#define EXT4_FILEDEV_BSIZE 512

static const char *bdstd_imagepath = NULL;
static FILE *bdstd_devfile = NULL;

static int bdstd_open(struct ext4_blockdev *bdev);
static int bdstd_bread(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id,
			 uint32_t blk_cnt);
static int bdstd_bwrite(struct ext4_blockdev *bdev, const void *buf,
			  uint64_t blk_id, uint32_t blk_cnt);
static int bdstd_close(struct ext4_blockdev *bdev);

EXT4_BLOCKDEV_STATIC_INSTANCE(bd, EXT4_FILEDEV_BSIZE, 0, bdstd_open,
		bdstd_bread, bdstd_bwrite, bdstd_close, 0, 0);

/**************************************
 * BLOCK DEVICE INTERFACE
 **************************************/

static int
bdstd_open(struct ext4_blockdev *bdev)
{
    (void)bdev;

	bdstd_devfile = fopen(bdstd_imagepath, "r+b");
	if (bdstd_devfile == NULL) {
        rho_errno_warn(errno, "fopen(\"%s\", \"r+b\")", bdstd_imagepath);
		return (EIO);
    }

	/*No buffering at file.*/
	setbuf(bdstd_devfile, 0);

	bd.part_offset = 0;
	bd.part_size = rho_path_getsize(bdstd_imagepath);
	bd.bdif->ph_bcnt = bd.part_size / bd.bdif->ph_bsize;

	return (EOK);
}

static int
bdstd_bread(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id,
			 uint32_t blk_cnt)
{
	if (!blk_cnt)
		return (EOK);
	if (fseeko(bdstd_devfile, blk_id * bdev->bdif->ph_bsize, SEEK_SET))
		return (EIO);
	if (!fread(buf, bdev->bdif->ph_bsize * blk_cnt, 1, bdstd_devfile))
		return (EIO);

	return (EOK);
}

static int 
bdstd_bwrite(struct ext4_blockdev *bdev, const void *buf,
			  uint64_t blk_id, uint32_t blk_cnt)
{
	if (fseeko(bdstd_devfile, blk_id * bdev->bdif->ph_bsize, SEEK_SET))
		return (EIO);
	if (!blk_cnt)
		return EOK;
	if (!fwrite(buf, bdev->bdif->ph_bsize * blk_cnt, 1, bdstd_devfile))
		return (EIO);

	return (EOK);
}

static int
bdstd_close(struct ext4_blockdev *bdev)
{
    (void)bdev;

	fclose(bdstd_devfile);
	return (EOK);
}

/**************************************
 * INITIALIZATION
 **************************************/
struct ext4_blockdev *
bdstd_init(const char *path)
{
    RHO_TRACE_ENTER("path=\"%s\"", path);

    bdstd_imagepath = rhoL_strdup(path);

    RHO_TRACE_EXIT();
	return (&bd);
}
