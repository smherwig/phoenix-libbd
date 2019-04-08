#include <stddef.h>
#include <stdint.h>

#include <rho/rho.h>

#include "bd_util.h"

void
bd_iv_from_blk_id(uint64_t blk_id, void *iv, size_t ivlen)
{
    rho_memzero(iv, ivlen);
    memcpy(iv, &blk_id, sizeof(blk_id));
}

#if 0
void
bd_encrypt_block(struct rho_cipher *cipher, uint64_t blk_id)
{
    uint8_t iv[16] = { 0 };
    
    bd_iv_from_blk_id(blk_id, iv, 16);
   
    rho_cipher_reset(cipher, RHO_CIPHER_MODE_ENCRYPT, false, NULL, iv);
    rho_cipher_update(cipher, buf + (i * bdev->bdif->ph_bsize), 
                bdev->bdif->ph_bsize, tmpblk, &outlen);
    rho_cipher_finish(cipher, tmpblk + outlen, &extralen);
}

void
bd_decrypt_block(struct rho_cipher *cipher, uint64_t blk_id)
{

}
#endif
