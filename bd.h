#ifndef _BD_H_
#define _BD_H_

#include <stdint.h>

#include <ext4_config.h>
#include <ext4_blockdev.h>

#include <rho/rho_decls.h>

RHO_DECLS_BEGIN

#define BDSTD_NAME          "bdstd"
#define BDCRYPT_NAME        "bdcrypt"
#define BDVERITY_NAME       "bdverity"
#define BDVERICRYPT_NAME    "bdvericrypt"

/*
 * TODO: perhaps have parameteter to the init functions
 * be a void *
 */

struct ext4_blockdev * bdstd_init(const char *path);

struct ext4_blockdev * bdverity_init(const char *fspath, const char *mtpath,
        const char *macpassword, uint8_t *roothash);

struct ext4_blockdev * bdcrypt_init(const char *path, const char *encpassword);

struct ext4_blockdev * bdvericrypt_init(const char *fspath,
        const char *mtpath, const char *macpassword, uint8_t *roothash,
        const char *encpassword);

RHO_DECLS_END

#endif /* _BD_H_ */
