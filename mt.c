#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <rho/rho.h>

#include "mt.h"

/************************************************************ 
 * DEFINES
 ************************************************************/
/* XXX: we're assuming SHA-256, though smaller-sizes hashes will also work */ 
#define MT_MAX_HASH_SIZE    32
#define MT_CACHE_DEFAULT_MAX_ENTRIES    1024

/************************************************************ 
 * TYPES
 ************************************************************/
struct mt_cache_entry {
    uint64_t    ai;                 /* array index */
    uint32_t    usecnt;            /* for lru accounting */
    bool        on_dirty_list;      /* whether or not on dirty list */
    uint8_t     hashval[MT_MAX_HASH_SIZE];
    int         refcnt;
    RHO_RB_ENTRY(mt_cache_entry)   ai_entry;    /* array index entry */ 
    RHO_RB_ENTRY(mt_cache_entry)   lru_entry;
    RHO_LIST_ENTRY(mt_cache_entry) dirty_entry;
};

RHO_RB_HEAD(mt_cache_ai_tree, mt_cache_entry);
RHO_RB_HEAD(mt_cache_lru_tree, mt_cache_entry);

struct mt_cache {
    struct mt_cache_ai_tree ai_root;
    struct mt_cache_lru_tree lru_root;
    RHO_LIST_HEAD(mt_cache_dirty, mt_cache_entry) dirty_list;
    size_t      num_entries;
    size_t      max_entries;
    struct mt   *mt;    /* weak pointer */
};

struct mt {
    mt_hashfn       hashfn;
    size_t          hashsize;
    uint8_t         root_hash[MT_MAX_HASH_SIZE];
    char            *mtpath;
    int             fd;
    size_t          num_nodes;
    size_t          num_leafs;
    struct mt_cache cache;
};


#define MT_BLKID_TO_FILE_OFFSET(mt, blkid) \
    ( (((mt)->num_nodes - (mt)->num_leafs) * (mt)->hashsize) + ((blkid) * (mt)->hashsize) )

#define MT_FILE_OFFSET_TO_INDEX(mt, off) \
    ((off) / (mt)->hashsize)

#define MT_INDEX_TO_FILE_OFFSET(mt, ai) \
    ((mt)->hashsize * (ai))

#define MT_LEFT_CHILD_INDEX(ai)     (((ai) * 2) + 1)
#define MT_RIGHT_CHILD_INDEX(ai)    (((ai) * 2) + 2)
#define MT_PARENT_INDEX(ai)         (((ai) - 1) / 2)
#define MT_SIBLING_INDEX(ai)        ((ai % 2) ? (ai) + 1 : (ai) - 1)
#define MT_WHICH_SIBLING(ai)        (((ai) + 1) % 2)    /* 0 means left sibling, 1 means right */

/************************************************************ 
 * FUNCTION PROTOTYPES
 ************************************************************/
static int mt_cache_entry_ai_cmp(struct mt_cache_entry *a,
        struct mt_cache_entry *b);

RHO_RB_PROTOTYPE_STATIC(mt_cache_ai_tree, mt_cache_entry, ai_entry,
        mt_cache_entry_ai_cmp);

static int mt_cache_entry_usecnt_cmp(struct mt_cache_entry *a,
        struct mt_cache_entry *b);

RHO_RB_PROTOTYPE_STATIC(mt_cache_lru_tree, mt_cache_entry, lru_entry,
        mt_cache_entry_usecnt_cmp);

static void mt_cache_entry_init(struct mt_cache_entry *entry, uint64_t ai,
        const void *hashval, size_t hashsize, bool on_dirty_list);

#if 0
static void mt_cache_entry_reset(struct mt_cache_entry *entry);
#endif

static struct mt_cache_entry * mt_cache_entry_create(uint64_t ai,
        const uint8_t *hashval, size_t hashsize, bool on_dirty_list);

static void mt_cache_entry_destroy(struct mt_cache_entry *entry);

static void mt_cache_init(struct mt_cache *cache, uint32_t max_entries,
        struct mt *mt);

static void mt_cache_cleanup(struct mt_cache *cache);
static bool mt_cache_is_full(const struct mt_cache *cache);
static void mt_cache_flush(struct mt_cache *cache);

static struct mt_cache_entry * mt_cache_remove_lru_entry(
        struct mt_cache *cache);

static void mt_cache_add_entry(struct mt_cache *cache,
        struct mt_cache_entry *entry, bool dirty);

static void mt_cache_update_entry(struct mt_cache *cache,
        struct mt_cache_entry *entry, const uint8_t *hashval);

static struct mt_cache_entry * mt_cache_find(struct mt_cache *cache,
        uint64_t ai);

static void mt_read_file(struct mt *mt, uint64_t ai, uint8_t *hashval);
static void mt_write_file(struct mt *mt, uint64_t ai, const uint8_t *hashval);
static void mt_read_index(struct mt *mt, uint64_t ai, uint8_t *hashval);
static void mt_write_index(struct mt *mt, uint64_t ai, const uint8_t *hashval);

static void mt_num_nodes_and_leafs(struct mt *mt, size_t *num_nodes,
        size_t *num_leafs);

/************************************************************ 
 * RED-BLACK TREE FOR CACHE
 *
 * ai = array index, which is how cache entries are
 * identified
 ************************************************************/
static int
mt_cache_entry_ai_cmp(struct mt_cache_entry *a, struct mt_cache_entry *b)
{
    if      (a->ai < b->ai)     return (-1);
    else if (a->ai == b->ai)    return (0);
    else                        return (1);
}

RHO_RB_GENERATE_STATIC(mt_cache_ai_tree, mt_cache_entry, ai_entry,
        mt_cache_entry_ai_cmp);

/************************************************************ 
 * RED-BLACK TREE FOR CACHE'S LRU 
 ************************************************************/
static int
mt_cache_entry_usecnt_cmp(struct mt_cache_entry *a, struct mt_cache_entry *b)
{
    if (a->usecnt < b->usecnt)          return (-1);
    else if (a->usecnt == b->usecnt)    return (0);
    else                                return (1);
}

RHO_RB_GENERATE_STATIC(mt_cache_lru_tree, mt_cache_entry, lru_entry,
        mt_cache_entry_usecnt_cmp);

/************************************************************ 
 * CACHE ENTRY
 ************************************************************/
static void
mt_cache_entry_init(struct mt_cache_entry *entry, uint64_t ai,
        const void *hashval, size_t hashsize, bool on_dirty_list)
{
    RHO_TRACE_ENTER();

    entry->ai = ai;
    entry->usecnt = 0;
    entry->on_dirty_list = on_dirty_list;
    memcpy(entry->hashval, hashval, hashsize);

    RHO_TRACE_EXIT();
}

#if 0
static void
mt_cache_entry_reset(struct mt_cache_entry *entry)
{
    RHO_TRACE_ENTER();

    entry->ai = 0;
    entry->usecnt = 0;
    entry->on_dirty_list = false;
    rho_memzero(entry->hashval, MT_MAX_HASH_SIZE);

    RHO_TRACE_EXIT();
}
#endif

static struct mt_cache_entry *
mt_cache_entry_create(uint64_t ai, const uint8_t *hashval, size_t hashsize,
        bool on_dirty_list)
{
    struct mt_cache_entry *entry = NULL;

    RHO_TRACE_ENTER();

    entry = rhoL_zalloc(sizeof(*entry));
    entry->ai = ai;
    entry->on_dirty_list = on_dirty_list;
    memcpy(entry->hashval, hashval, hashsize);

    RHO_TRACE_EXIT();
    return (entry);
}

static void
mt_cache_entry_destroy(struct mt_cache_entry *entry)
{
    RHO_TRACE_ENTER();

    entry->refcnt--;
    if (entry->refcnt == 0)
        rhoL_free(entry);

    RHO_TRACE_EXIT();
}

/************************************************************ 
 * CACHE LAYER
 ************************************************************/

static void
mt_cache_init(struct mt_cache *cache, uint32_t max_entries, struct mt *mt)
{
    RHO_TRACE_ENTER();

    RHO_RB_INIT(&cache->ai_root);
    RHO_RB_INIT(&cache->lru_root);
    RHO_LIST_INIT(&cache->dirty_list);

    cache->num_entries = 0;
    cache->max_entries = max_entries;
    cache->mt = mt;

    RHO_TRACE_EXIT();
}

static void
mt_cache_cleanup(struct mt_cache *cache)
{
    struct mt_cache_entry *entry = NULL;
    struct mt_cache_entry *next = NULL;

    RHO_TRACE_ENTER();

    for (entry = RHO_RB_MIN(mt_cache_ai_tree, &cache->ai_root); entry != NULL;
            entry = next) 
    {
        next = RHO_RB_NEXT(mt_cache_ai_tree, &cache->ai_root, entry);
        RHO_RB_REMOVE(mt_cache_ai_tree, &cache->ai_root, entry);
        mt_cache_entry_destroy(entry);
    }

    for (entry = RHO_RB_MIN(mt_cache_lru_tree, &cache->lru_root); entry != NULL;
            entry = next) 
    {
        next = RHO_RB_NEXT(mt_cache_lru_tree, &cache->lru_root, entry);
        RHO_RB_REMOVE(mt_cache_lru_tree, &cache->lru_root, entry);
        mt_cache_entry_destroy(entry);
    }

    while (!RHO_LIST_EMPTY(&cache->dirty_list)) {
        entry = RHO_LIST_FIRST(&cache->dirty_list);
        RHO_LIST_REMOVE(entry, dirty_entry);
        mt_cache_entry_destroy(entry);
    }

    RHO_TRACE_EXIT();
}

static bool
mt_cache_is_full(const struct mt_cache *cache)
{
    bool ret = 0;

    RHO_TRACE_ENTER();

    ret = cache->num_entries == cache->max_entries;

    RHO_TRACE_EXIT("num_entries=%zu, max_entries=%zu, full=%d",
            cache->num_entries, cache->max_entries, ret);

    return (ret);
}

static void
mt_cache_flush(struct mt_cache *cache)
{
    int i = 0;
    struct mt *mt = mt = cache->mt;
    struct mt_cache_entry *entry = NULL;
    struct mt_cache_entry *tmp = NULL;

    RHO_TRACE_ENTER();

    RHO_LIST_FOREACH_SAFE(entry, &cache->dirty_list, dirty_entry, tmp) {
        mt_write_file(mt, entry->ai, entry->hashval);
        RHO_LIST_REMOVE(entry, dirty_entry);
        entry->on_dirty_list = false;
        entry->refcnt--;
        rho_debug("flushing entry # %d (ai=%"PRIu64")", i, entry->ai);
        i++;
    }

    RHO_TRACE_EXIT();
}
        
static struct mt_cache_entry *
mt_cache_remove_lru_entry(struct mt_cache *cache)
{
    struct mt_cache_entry *entry = NULL;

    RHO_TRACE_ENTER();

    entry = RHO_RB_MIN(mt_cache_lru_tree, &cache->lru_root);
    rho_debug("removing entry ai=%"PRIu64" from cache (usecnt=%"PRIu32")",
            entry->ai, entry->usecnt);

    RHO_RB_REMOVE(mt_cache_lru_tree, &cache->lru_root, entry);
    RHO_RB_REMOVE(mt_cache_ai_tree, &cache->ai_root, entry);
    entry->refcnt -= 2;

#if 0
    if (entry->on_dirty_list)
        mt_cache_flush(cache);
#endif
    if (entry->on_dirty_list) {
        mt_write_file(cache->mt, entry->ai, entry->hashval);
        RHO_LIST_REMOVE(entry, dirty_entry);
        entry->on_dirty_list = false;
        entry->refcnt--;
        rho_debug("removing entry ai=%"PRIu64" from dirty list (flushing to disk)", 
                entry->ai);
    }

    cache->num_entries--;

    RHO_TRACE_EXIT();
    return (entry);
}

static void
mt_cache_add_entry(struct mt_cache *cache,
        struct mt_cache_entry *entry, bool dirty)
{
    RHO_TRACE_ENTER();

    rho_debug("adding entry ai=%"PRIu64" to cache", entry->ai);
    RHO_RB_INSERT(mt_cache_ai_tree, &cache->ai_root, entry);
    RHO_RB_INSERT(mt_cache_lru_tree, &cache->lru_root, entry);
    entry->refcnt += 2;

    if (dirty) {
        rho_debug("adding entry ai=%"PRIu64" to dirty list", entry->ai);
        RHO_LIST_INSERT_HEAD(&cache->dirty_list, entry, dirty_entry);
        entry->refcnt++;
    }

    cache->num_entries++;

    RHO_TRACE_EXIT();
}

static void
mt_cache_update_entry(struct mt_cache *cache,
        struct mt_cache_entry *entry, const uint8_t *hashval)
{
    RHO_TRACE_ENTER();

    memcpy(entry->hashval, hashval, cache->mt->hashsize);
    if (!entry->on_dirty_list) {
        rho_debug("adding entry ai=%"PRIu64" to dirty list", entry->ai);
        RHO_LIST_INSERT_HEAD(&cache->dirty_list, entry, dirty_entry);
        entry->on_dirty_list = true;
        entry->refcnt++;
    }
    entry->usecnt++;

    RHO_TRACE_EXIT();
}

static struct mt_cache_entry *
mt_cache_find(struct mt_cache *cache, uint64_t ai)
{
    struct mt_cache_entry key;
    struct mt_cache_entry *entry = NULL;

    RHO_TRACE_ENTER("ai=%"PRIu64, ai);

    key.ai = ai;
    entry = RHO_RB_FIND(mt_cache_ai_tree, &cache->ai_root, &key);

    RHO_TRACE_EXIT("entry=%p", entry);
    return (entry);
}

/************************************************************ 
 * DISK OPERATIONS
 ************************************************************/
static void
mt_read_file(struct mt *mt, uint64_t ai, uint8_t *hashval)
{
    off_t off = 0;
    ssize_t n = 0;

    RHO_TRACE_ENTER();

    off = MT_INDEX_TO_FILE_OFFSET(mt, ai);
    (void)rhoL_lseek(mt->fd, off, SEEK_SET);
    n = rho_fd_readn(mt->fd, hashval, mt->hashsize);
    if (n == -1)
        rho_errno_die(errno, "read");
    if (((size_t)n) != mt->hashsize)
        rho_die("unexpected EOF");

    RHO_TRACE_EXIT();
}

static void
mt_write_file(struct mt *mt, uint64_t ai, const uint8_t *hashval)
{
    off_t off = 0;
    ssize_t n = 0;

    RHO_TRACE_ENTER();

    off = MT_INDEX_TO_FILE_OFFSET(mt, ai);
    (void)rhoL_lseek(mt->fd, off, SEEK_SET);
    n = rho_fd_writen(mt->fd, hashval, mt->hashsize);
    if (n == -1)
        rho_errno_die(errno, "write");

    RHO_TRACE_EXIT();
}

/************************************************************ 
 * MIDDLE LAYER THAT FACADES BETWEEN DISK AND CACHE
 ************************************************************/

/* 
 * if ai is in the cache
 *      goto done;
 *
 * read the hash from the file
 * if the cache is full
 *      drop the lru entry
 *      add the hash to the cache
 *
 * done:
 *      return the hash value
 */
static void
mt_read_index(struct mt *mt, uint64_t ai, uint8_t *hashval)
{
    struct mt_cache *cache = &mt->cache;
    struct mt_cache_entry *entry = NULL;
    size_t hashsize = mt->hashsize;

    RHO_TRACE_ENTER();

    entry = mt_cache_find(cache, ai);

    /* cache hit */
    if (entry != NULL) {
        rho_debug("cache hit");
        entry->usecnt++;
        memcpy(hashval, entry->hashval, hashsize);
        goto done;
    }

    /* cache miss */
    rho_debug("cache miss");
    mt_read_file(mt, ai, hashval);
    if (mt_cache_is_full(cache)) {
        entry = mt_cache_remove_lru_entry(cache);
        mt_cache_entry_init(entry, ai, hashval, hashsize, false);
    } else {
        entry = mt_cache_entry_create(ai, hashval, hashsize, false); 
    }
    mt_cache_add_entry(cache, entry, false);

done:
    RHO_TRACE_EXIT();
    return;
} 

static void
mt_write_index(struct mt *mt, uint64_t ai, const uint8_t *hashval)
{
    struct mt_cache *cache = &mt->cache;
    struct mt_cache_entry *entry = NULL;
    size_t hashsize = mt->hashsize;

    RHO_TRACE_ENTER();

    entry = mt_cache_find(cache, ai);

    /* cache hit */
    if (entry != NULL) {
        mt_cache_update_entry(cache, entry, hashval);
        goto done;
    } 
    
    /* cache miss */
    if (mt_cache_is_full(cache)) {
        entry = mt_cache_remove_lru_entry(cache);
        mt_cache_entry_init(entry, ai, hashval, hashsize, true);
    } else {
        entry = mt_cache_entry_create(ai, hashval, hashsize, true);
    }
    mt_cache_add_entry(cache, entry, true);

done:
    RHO_TRACE_EXIT();
    return;
}

/************************************************************ 
 * HELPERS FOR MOVING AROUND THE ARRAY-BASED BINARY-TREE
 ************************************************************/
static void
mt_num_nodes_and_leafs(struct mt *mt, size_t *num_nodes,
        size_t *num_leafs)
{
    size_t fsize = 0;
    size_t num_hashes = 0;

    RHO_TRACE_ENTER();

    fsize = rho_path_getsize(mt->mtpath);
    num_hashes = fsize / mt->hashsize;

    *num_nodes = num_hashes;
    *num_leafs = (num_hashes + 1) / 2;

    RHO_TRACE_EXIT("num_hashes=%zu, num_nodes=%zu, num_leafs=%zu",
            num_hashes, *num_nodes, *num_leafs);
}

/************************************************************ 
 * PUBLIC API
 ************************************************************/
struct mt *
mt_open(const char *mtpath, mt_hashfn hashfn, size_t hashsize,
        const uint8_t *root_hash)
{
    int fd = 0;
    struct mt *mt = NULL;

    RHO_TRACE_ENTER();

    mt = rhoL_zalloc(sizeof(*mt));
    mt->hashfn = hashfn;
    mt->hashsize = hashsize;
    memcpy(mt->root_hash, root_hash, hashsize);
    mt->mtpath = rhoL_strdup(mtpath);

    fd = open(mtpath, O_RDWR);
    if (fd == -1)
        rho_errno_die(errno, "open(\"%s\", O_RDWR)", mtpath);
    mt->fd =fd;

    /* TODO: check that root_hash matches */

    mt_num_nodes_and_leafs(mt, &mt->num_nodes, &mt->num_leafs);

    mt_cache_init(&mt->cache, MT_CACHE_DEFAULT_MAX_ENTRIES, mt);

    RHO_TRACE_EXIT();
    return (mt);
}

void
mt_close(struct mt *mt)
{
    RHO_TRACE_ENTER();

    mt_cache_flush(&mt->cache);
    mt_cache_cleanup(&mt->cache);
    rhoL_close(mt->fd);
    rhoL_free(mt->mtpath);
    rhoL_free(mt);
    
    RHO_TRACE_EXIT();
}

bool
mt_verify(struct mt *mt, const void *blk, size_t blk_size, uint64_t blk_id)
{
    bool ret = false;
    uint8_t expected_hash[MT_MAX_HASH_SIZE] = { 0 };
    int si = 0; /* sibling; 0 means left, 1 means right */
    uint8_t sibling_hashes[2][MT_MAX_HASH_SIZE] = { 0 };
    uint8_t parent_hash[MT_MAX_HASH_SIZE] = { 0 };
    uint64_t cur_ai = 0;
    uint64_t sibling_ai = 0;
    uint64_t parent_ai = 0;
    size_t off = 0;
    size_t hashsize = mt->hashsize;

    RHO_TRACE_ENTER("blk_id=%"PRIu64, blk_id);

    /* 
     * verify leaf hash (we just use the first part of sibling hashes here)
     * The left child is always in sibling_hashes[0], and the right child
     * in sibling_hashes[1].
     */
    off = MT_BLKID_TO_FILE_OFFSET(mt, blk_id);
    cur_ai = MT_FILE_OFFSET_TO_INDEX(mt, off);
    mt_read_index(mt, cur_ai, expected_hash);
    si = MT_WHICH_SIBLING(cur_ai);
    mt->hashfn(blk, blk_size, sibling_hashes[si]);

    rho_debug("initial cur_ai=%"PRIu64"(blk_id=%"PRIu64")", cur_ai, blk_id);
#if 0
    rho_hexdump(sibling_hashes[si], hashsize, "computed hash");
    rho_hexdump(expected_hash, hashsize, "expected hash");
#endif

    if (!rho_mem_equal(expected_hash, sibling_hashes[si], hashsize)) {
        rho_warn("bad leaf hash: blk_id=%"PRIu64", file offset=%zu, ai=%zu",
                blk_id, off, cur_ai);
        goto done;
    }

    /* verify path up to the root */
    while (cur_ai != 0) {
        sibling_ai = MT_SIBLING_INDEX(cur_ai);
        si = MT_WHICH_SIBLING(sibling_ai);
        mt_read_index(mt, sibling_ai, sibling_hashes[si]);
        mt->hashfn(sibling_hashes, 2 * hashsize, parent_hash);
#if 0
        rho_hexdump(sibling_hashes, 2 * hashsize, "sibling hashes");
#endif

        parent_ai = MT_PARENT_INDEX(cur_ai);
        mt_read_index(mt, parent_ai, expected_hash);

        rho_debug("cur_ai=%"PRIu64", sibling_ai=%"PRIu64", parent_ai=%"PRIu64,
                cur_ai, sibling_ai, parent_ai);
#if 0
        rho_hexdump(parent_hash, hashsize, "computed hash");
        rho_hexdump(expected_hash, hashsize, "expected hash");
#endif

        if (!rho_mem_equal(expected_hash, parent_hash, hashsize)) {
            rho_warn("bad intermediate node hash, ai=%zu", parent_ai);
            goto done;
        }

        si = MT_WHICH_SIBLING(parent_ai);
        memcpy(sibling_hashes[si], parent_hash, hashsize);

        cur_ai = parent_ai;
    }

    /* verify root hash */
    if (!rho_mem_equal(mt->root_hash, sibling_hashes[1], hashsize)) {
        rho_warn("bad root hash");
        goto done;
    }

    ret = true;

done:
    RHO_TRACE_EXIT("ret=%d", ret);
    return (ret);
}

void
mt_update(struct mt *mt, const void *blk, size_t blk_size, uint64_t blk_id)
{
    int si = 0; /* sibling; 0 means left, 1 means right */
    uint8_t sibling_hashes[2][MT_MAX_HASH_SIZE] = { 0 };
    uint8_t parent_hash[MT_MAX_HASH_SIZE] = { 0 };
    uint64_t cur_ai = 0;
    uint64_t sibling_ai = 0;
    uint64_t parent_ai = 0;
    size_t off = 0;
    size_t hashsize = mt->hashsize;

    RHO_TRACE_ENTER("blk_id=%"PRIu64, blk_id);

    off = MT_BLKID_TO_FILE_OFFSET(mt, blk_id);
    cur_ai = MT_FILE_OFFSET_TO_INDEX(mt, off);

    /* compute hash of block */
    si = MT_WHICH_SIBLING(cur_ai);
    mt->hashfn(blk, blk_size, sibling_hashes[si]);
    mt_write_index(mt, cur_ai, sibling_hashes[si]);

    /* FIXME: add rollback attack mitigation.
     * 
     * Verify current branch values as you compute 
     * the new branch values; do not write the new branch values 
     * -- save them.  Once you have verified the current branch,
     * commit these saved values.
     */
    /* propagate up to the root */
    while (cur_ai != 0) {
        sibling_ai = MT_SIBLING_INDEX(cur_ai);
        si = MT_WHICH_SIBLING(sibling_ai);
        mt_read_index(mt, sibling_ai, sibling_hashes[si]);
        mt->hashfn(sibling_hashes, 2 * hashsize, parent_hash);

        parent_ai = MT_PARENT_INDEX(cur_ai);
        mt_write_index(mt, parent_ai, parent_hash);

        si = MT_WHICH_SIBLING(parent_ai);
        memcpy(sibling_hashes[si], parent_hash, hashsize);

        cur_ai = parent_ai; 
    }

    /* set root_hash to cur_hashval */
    memcpy(mt->root_hash, sibling_hashes[1], hashsize);

    RHO_TRACE_EXIT();
    return;
}
