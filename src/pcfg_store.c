/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * The counting table.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcfg_common.h"
#include "pcfg_platform.h"

#define HP_TYPES 256
#define HP_LENS 256
#define HP_LOAD_NUM 3 /* grow when count exceeds 3/4 of the bucket array */
#define HP_LOAD_DEN 4

typedef struct hp_node
{
  struct hp_node *next;
  int64_t cnt;
  uint64_t hash;
  uint16_t vlen;
  uint8_t type;
  uint8_t len;
  char val[];
} hp_node_t;

typedef struct hp_arena
{
  struct hp_arena *next;
  size_t used, size;
  char base[];
} hp_arena_t;

typedef struct
{
  hp_node_t **buckets;
  size_t nbucket; /* always a power of two */
  size_t count;
  hp_arena_t *arena;
  size_t arena_block;
  size_t bytes;

  /* One lock per shard, and a key belongs to exactly one shard, so workers only
   * meet where they touch the same key: no per-worker copy, and no merge. */
  hp_mutex_t *mux;
  hp_mem_t *mem;
} hp_shard_t;

struct hp_store
{
  hp_shard_t *shard;
  int nshard; /* always a power of two */
  int64_t total[HP_TYPES][HP_LENS];

  /* The two things that keep a run inside the memory it was given. */
  size_t budget;   /* 0 = no limit, and see mem below */
  hp_mem_t *mem;   /* the ceiling shared with the word set and the OMEN table */
  int64_t refused; /* keys the ceiling would not make room for */
  bool full;

  uint8_t *cbf;      /* two 4-bit counters per byte */
  uint64_t cbf_mask; /* counter count - 1, a power of two */
  int admit;         /* 0 = admit everything */

  bool locked; /* set once more than one thread may add */
  hp_mutex_t *total_mux;
};

static inline void hp_unlock (hp_store_t *st, hp_shard_t *sh)
{
  if (st->locked == true) hp_mutex_unlock (sh->mux);
}

/* The per (type, length) totals are the one thing every shard writes to, so a
 * mutex here sat on the hot path of every add. An atomic costs a locked add. */
static inline void hp_total_add (hp_store_t *st, uint8_t type, uint8_t len, int64_t n)
{
  if (st->locked == true)
  {
    __atomic_fetch_add (&st->total[type][len], n, __ATOMIC_RELAXED);

    return;
  }

  st->total[type][len] += n;
}

/* FNV-1a over the value, then the type and length folded in: the value is what
 * varies, the rest only separates namespaces that would share a bucket. */
static inline uint64_t hp_hash (uint8_t type, uint8_t len, const char *val, int vlen)
{
  uint64_t h = 1469598103934665603ULL;

  for (int i = 0; i < vlen; i++)
  {
    h ^= (unsigned char) val[i];
    h *= 1099511628211ULL;
  }

  h ^= ((uint64_t) type << 8) | (uint64_t) len;
  h *= 1099511628211ULL;

  return h;
}

static void *hp_arena_alloc (hp_shard_t *sh, size_t size)
{
  size = (size + 15) & ~(size_t) 15;

  if ((sh->arena == NULL) || ((sh->arena->used + size) > sh->arena->size))
  {
    size_t block = (size > sh->arena_block) ? size : sh->arena_block;

    /* Charged before it exists, because refusing here is all the ceiling does. */
    if (hp_mem_take (sh->mem, sizeof (hp_arena_t) + block) == false) return NULL;

    hp_arena_t *a = (hp_arena_t *) hp_map (sizeof (hp_arena_t) + block);

    if (a == NULL)
    {
      hp_mem_give (sh->mem, sizeof (hp_arena_t) + block);

      return NULL;
    }

    a->next = sh->arena;
    a->used = 0;
    a->size = block;

    sh->arena = a;
    sh->bytes += sizeof (hp_arena_t) + block;
  }

  void *p = sh->arena->base + sh->arena->used;

  sh->arena->used += size;

  return p;
}

static bool hp_shard_grow (hp_shard_t *sh)
{
  const size_t nb = (sh->nbucket == 0) ? 1024 : (sh->nbucket * 2);

  if (hp_mem_take (sh->mem, (nb - sh->nbucket) * sizeof (hp_node_t *)) == false) return false;

  hp_node_t **nbk = (hp_node_t **) calloc (nb, sizeof (hp_node_t *));

  if (nbk == NULL) return false;

  for (size_t i = 0; i < sh->nbucket; i++)
  {
    hp_node_t *n = sh->buckets[i];

    while (n != NULL)
    {
      hp_node_t *next = n->next;

      const size_t b = (size_t) (n->hash & (nb - 1));

      n->next = nbk[b];
      nbk[b]  = n;
      n       = next;
    }
  }

  free (sh->buckets);

  sh->bytes -= sh->nbucket * sizeof (hp_node_t *);
  sh->bytes += nb * sizeof (hp_node_t *);
  sh->buckets = nbk;
  sh->nbucket = nb;

  return true;
}

/* Has this key been seen `admit` times? Counts it either way. */
static inline uint8_t cbf_bump (uint8_t *cell, int shift)
{
  uint8_t old = __atomic_load_n (cell, __ATOMIC_RELAXED);

  for (;;)
  {
    const uint8_t v = (uint8_t) ((old >> shift) & 0x0f);

    if (v == 15) return v; /* saturated, and nothing to write */

    const uint8_t up = (uint8_t) ((old & ~(0x0f << shift)) | ((v + 1) << shift));

    if (__atomic_compare_exchange_n (cell, &old, up, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED) == true)
      return (uint8_t) (v + 1);
  }
}

static bool cbf_seen_enough (hp_store_t *st, uint64_t h)
{
  if (st->cbf == NULL) return true;

  const uint64_t h2 = (h << 33) | (h >> 31); /* a second, independent-enough hash */

  uint8_t lowest = 15;

  for (int i = 0; i < 3; i++)
  {
    const uint64_t pos = (h + ((uint64_t) i * h2)) & st->cbf_mask;
    const size_t idx   = (size_t) (pos >> 1);
    const int shift    = (int) ((pos & 1) << 2);

    const uint8_t v = cbf_bump (&st->cbf[idx], shift);

    if (v < lowest) lowest = v;
  }

  return (lowest >= (uint8_t) st->admit);
}

/* What the ceiling cost this table, in occurrences that were not counted. */
int64_t hp_store_refused (const hp_store_t *st)
{
  if (st == NULL) return 0;

  return __atomic_load_n (&st->refused, __ATOMIC_RELAXED);
}

/* Every table sharing the ceiling is told about it once, before the workers. */
void hp_store_account (hp_store_t *st, hp_mem_t *m)
{
  if (st == NULL) return;

  st->mem = m;

  for (int i = 0; i < st->nshard; i++) st->shard[i].mem = m;
}

void hp_store_threaded (hp_store_t *st, bool on)
{
  if ((on == true) && (st->locked == false))
  {
    hp_mutex_init (&st->total_mux);
  }

  st->locked = on;
}

/* The filter is a flat allocation of its own, and is charged like the rest. */
void hp_store_limit (hp_store_t *st, size_t budget, int admit, size_t filter_bytes)
{
  st->budget = budget;
  st->admit  = (admit > 15) ? 15 : admit;

  if ((admit > 1) && (filter_bytes > 0))
  {
    size_t n = 1;

    while ((n * 2) <= filter_bytes) n *= 2;

    st->cbf = (uint8_t *) calloc (n, 1);

    if (st->cbf != NULL) st->cbf_mask = (uint64_t) (n * 2) - 1;
  }
}

bool hp_store_is_full (const hp_store_t *st)
{
  return st->full;
}

hp_store_t *hp_store_new (int nshard, size_t arena_block)
{
  if (nshard < 1) nshard = 1;

  int n = 1;

  while (n < nshard) n *= 2;

  hp_store_t *st = (hp_store_t *) calloc (1, sizeof (hp_store_t));

  if (st == NULL) return NULL;

  st->shard  = (hp_shard_t *) calloc ((size_t) n, sizeof (hp_shard_t));
  st->nshard = n;

  if (st->shard == NULL)
  {
    free (st);
    return NULL;
  }

  for (int i = 0; i < n; i++)
  {
    st->shard[i].arena_block = arena_block;

    hp_mutex_init (&st->shard[i].mux);
  }

  return st;
}

void hp_store_free (hp_store_t *st)
{
  if (st == NULL) return;

  /* What this table held is room again: a spill frees it and the pass goes on. */
  for (int i = 0; i < st->nshard; i++) hp_mem_give (st->mem, st->shard[i].bytes);

  if (st == NULL) return;

  for (int i = 0; i < st->nshard; i++)
  {
    hp_arena_t *a = st->shard[i].arena;

    while (a != NULL)
    {
      hp_arena_t *nx = a->next;

      hp_unmap (a, sizeof (hp_arena_t) + a->size);

      a = nx;
    }

    free (st->shard[i].buckets);

    hp_mutex_destroy (st->shard[i].mux);
  }

  free (st->cbf);
  free (st->shard);
  free (st);
}

void hp_store_add (hp_store_t *st, uint8_t type, uint8_t len, const char *val, int vlen, int64_t n)
{
  if ((st == NULL) || (vlen < 0) || (vlen > 0xffff)) return;

  const uint64_t h = hp_hash (type, len, val, vlen);
  hp_shard_t *sh   = &st->shard[(size_t) (h >> 40) & (size_t) (st->nshard - 1)];

  if (st->locked == true) hp_mutex_lock (sh->mux);

  if (sh->nbucket == 0)
  {
    if (hp_shard_grow (sh) == false)
    {
      hp_unlock (st, sh);
      return;
    }
  }

  const size_t b = (size_t) (h & (sh->nbucket - 1));

  for (hp_node_t *e = sh->buckets[b]; e != NULL; e = e->next)
  {
    if (e->hash != h) continue;
    if (e->type != type || e->len != len) continue;
    if (e->vlen != (uint16_t) vlen) continue;
    if (memcmp (e->val, val, (size_t) vlen) != 0) continue;

    e->cnt += n;

    hp_total_add (st, type, len, n);

    if (st->locked == true) hp_mutex_unlock (sh->mux);

    return;
  }

  /* Not in the table, and whether it earns a slot is the filter's and the
   * budget's to decide. A line's own weight is occurrences already counted, so
   * one line carrying enough earns the slot outright: asking the filter first
   * would count that line once and throw away what a weighted list puts first. */
  if ((n < (int64_t) st->admit) && (cbf_seen_enough (st, h) == false))
  {
    hp_unlock (st, sh);
    return;
  }

  if ((st->budget != 0) && (hp_store_bytes (st) >= st->budget))
  {
    if (st->full == false)
    {
      fprintf (stderr, "hpcfg: memory budget reached, no new terminals from here on\n");
      st->full = true;
    }

    hp_unlock (st, sh);

    return;
  }

  if (((sh->count + 1) * HP_LOAD_DEN) > (sh->nbucket * HP_LOAD_NUM))
  {
    if (hp_shard_grow (sh) == false)
    {
      __atomic_fetch_add (&st->refused, n, __ATOMIC_RELAXED);

      hp_unlock (st, sh);
      return;
    }
  }

  hp_node_t *e = (hp_node_t *) hp_arena_alloc (sh, sizeof (hp_node_t) + (size_t) vlen);

  if (e == NULL)
  {
    /* No room: this key is not counted, and the run has to say what that cost. */
    __atomic_fetch_add (&st->refused, n, __ATOMIC_RELAXED);

    hp_unlock (st, sh);
    return;
  }

  memcpy (e->val, val, (size_t) vlen);

  /* A key the filter held back arrives having already occurred `admit` times, and
   * nothing counted those. Starting at the threshold puts them back. */
  e->hash = h;
  e->vlen = (uint16_t) vlen;
  e->type = type;
  e->len  = len;
  e->cnt  = (st->admit > 1 && n <= (int64_t) st->admit) ? (int64_t) st->admit : n;

  /* The grow above may have moved every bucket, so the index is taken again. */
  const size_t nb = (size_t) (h & (sh->nbucket - 1));

  e->next         = sh->buckets[nb];
  sh->buckets[nb] = e;
  sh->count++;

  hp_total_add (st, type, len, e->cnt);

  hp_unlock (st, sh);
}

int64_t hp_store_get (const hp_store_t *st, uint8_t type, uint8_t len, const char *val, int vlen)
{
  if (vlen < 0 || vlen > 0xffff) return 0;

  const uint64_t h     = hp_hash (type, len, val, vlen);
  const hp_shard_t *sh = &st->shard[(size_t) (h >> 40) & (size_t) (st->nshard - 1)];

  if (sh->nbucket == 0) return 0;

  for (const hp_node_t *e = sh->buckets[h & (sh->nbucket - 1)]; e != NULL; e = e->next)
  {
    if (e->hash != h) continue;
    if (e->vlen != (uint16_t) vlen) continue;
    if (memcmp (e->val, val, (size_t) vlen) != 0) continue;

    return e->cnt;
  }

  return 0;
}

/* How many keys the table holds, which is how many entries a write will make. */
int64_t hp_store_count (const hp_store_t *st)
{
  int64_t c = 0;

  for (int i = 0; i < st->nshard; i++) c += (int64_t) st->shard[i].count;

  return c;
}

size_t hp_store_bytes (const hp_store_t *st)
{
  size_t b = 0;

  for (int i = 0; i < st->nshard; i++) b += st->shard[i].bytes;

  return b;
}

int64_t hp_store_entries (const hp_store_t *st)
{
  int64_t c = 0;

  for (int i = 0; i < st->nshard; i++) c += (int64_t) st->shard[i].count;

  return c;
}

int64_t hp_store_total (const hp_store_t *st, uint8_t type, uint8_t len)
{
  return st->total[type][len];
}

/* Every entry, once, with its type and length. */
void hp_store_foreach_all (const hp_store_t *st, hp_store_all_fn fn, void *arg)
{
  for (int i = 0; i < st->nshard; i++)
  {
    const hp_shard_t *sh = &st->shard[i];

    for (size_t b = 0; b < sh->nbucket; b++)
      for (const hp_node_t *e = sh->buckets[b]; e != NULL; e = e->next)
        fn (e->type, e->len, e->val, e->vlen, e->cnt, arg);
  }
}

void hp_store_foreach (const hp_store_t *st, uint8_t type, uint8_t len, hp_store_fn fn, void *arg)
{
  for (int i = 0; i < st->nshard; i++)
  {
    const hp_shard_t *sh = &st->shard[i];

    for (size_t b = 0; b < sh->nbucket; b++)
    {
      for (const hp_node_t *e = sh->buckets[b]; e != NULL; e = e->next)
      {
        if (e->type == type && e->len == len) fn (e->val, e->vlen, e->cnt, arg);
      }
    }
  }
}
