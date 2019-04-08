#ifndef _BD_UTIL_H_
#define _BD_UTIL_H_

#include <stddef.h>
#include <stdint.h>

#include <ext4_config.h>
#include <ext4_blockdev.h>

#include <rho/rho_decls.h>

RHO_DECLS_BEGIN

void bd_iv_from_blk_id(uint64_t blk_id, void *iv, size_t ivlen);

RHO_DECLS_END

#endif /* _BD_H_ */
