#ifndef _MT_H_
#define _MT_H_

/* disk-based merkle tree */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <rho/rho_decls.h>

RHO_DECLS_BEGIN

typedef void (*mt_hashfn)(const void *data, size_t datalen, void *out);

/* opaque */
struct mt;

struct mt * mt_open(const char *mtpath,
       mt_hashfn hashfn, size_t hashsize, const uint8_t *root_hash);

void mt_close(struct mt *mt);

bool mt_verify(struct mt *mt, const void *blk, size_t blk_size,
        uint64_t blk_id);

void mt_update(struct mt *mt, const void *blk, size_t blk_size,
        uint64_t blk_id);

RHO_DECLS_END

#endif /* _MT_H_ */
