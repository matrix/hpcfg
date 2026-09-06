/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * The character-level Markov escape.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcfg_common.h"
#include "pcfg_platform.h"
#include "pcfg_trainer_omen.h"

#define OMEN_MAX_LEVEL 10
#define OMEN_MIN_LEN 4
#define OMEN_MAX_LEN 24
#define OMEN_MAX_INDEX (16u << 20) /* pointers; beyond this the ngram is too wide */

/* A guess pays a level per item, so it costs well past the cap on any one of
 * them. Above the ceiling a model generates nothing and says nothing about why:
 * eighteen, where pcfg-go stops, does that to long passwords. */
#ifndef OMEN_KS_MAXLEVEL
#define OMEN_KS_MAXLEVEL 40
#endif

#define OMEN_KS_LEVELS (OMEN_KS_MAXLEVEL + 1)

/* What the walk goes to unless --omen-level-max says otherwise: pcfg-go's
 * depth, for the reasons set out at omen_ks_max below. */
#ifndef OMEN_KS_DEFAULT
#define OMEN_KS_DEFAULT 18
#endif
#define OMEN_KS_ENOUGH 10000000000LL

/* Kept switchable for benchmark builds: the default is the fast single-edge
 * path in omen_ks_worker below. */
#ifndef HP_OMEN_SINGLE_FAST
#define HP_OMEN_SINGLE_FAST 1
#endif

#ifndef HP_OMEN_DOUBLE_FAST
#define HP_OMEN_DOUBLE_FAST 1
#endif

typedef struct
{
  int64_t ip_count;
  int64_t ep_count;
  int64_t cp_count;
  int64_t next_count[256];
  int ip_level;
  int ep_level;
  uint8_t next_level[256];
} omen_ctx_t;

struct omen
{
  bool threaded;   /* set once more than one worker may train */
  bool compat;     /* count and write what only pcfg_cracker and pcfg-go read */
  int nw;          /* workers the keyspace walk may spread over */
  hp_mem_t *mem;   /* the ceiling shared with the counting tables */
  int64_t refused; /* contexts the ceiling would not make room for */
  int ngram;
  int ks_max; /* deepest keyspace level to compute and write */
  int alpha_size;
  char alphabet[256];
  int alpha_n;
  int alpha_map[256]; /* byte -> alphabet index, -1 if outside */

  omen_ctx_t **index; /* prefix number -> context, NULL where unseen */
  size_t index_n;

  int64_t byte_freq[256]; /* the raw counts the alphabet was chosen from */
  int64_t ln_count[OMEN_MAX_LEN + 1];
  int ln_level[OMEN_MAX_LEN + 1];
  int64_t total_ip;
  int64_t total_ep;
  int64_t ctx_cnt;
};

typedef struct
{
  unsigned char c;
  int64_t n;
} freq_t;

static int freq_desc (const void *a, const void *b)
{
  const freq_t *x = (const freq_t *) a;
  const freq_t *y = (const freq_t *) b;

  if (x->n != y->n) return (y->n > x->n) ? 1 : -1;

  return (int) x->c - (int) y->c;
}

omen_t *omen_new (int ngram, int alpha_size)
{
  omen_t *o = (omen_t *) calloc (1, sizeof (omen_t));

  if (o == NULL) return NULL;

  o->ngram      = (ngram < 2) ? 2 : ngram;
  o->alpha_size = (alpha_size < 2) ? 2 : ((alpha_size > 255) ? 255 : alpha_size);

  for (int i = 0; i < 256; i++) o->alpha_map[i] = -1;

  return o;
}

void omen_free (omen_t *o)
{
  if (o != NULL) hp_mem_give (o->mem, (size_t) o->ctx_cnt * sizeof (omen_ctx_t));

  if (o == NULL) return;

  for (size_t i = 0; i < o->index_n; i++) free (o->index[i]);

  free (o->index);
  free (o);
}

/* The alphabet must exist before any n-gram can be counted. */
int omen_build_alphabet (omen_t *o, const int64_t *byte_freq)
{
  freq_t f[256];

  /* Kept, because a merge makes this same choice over the sum of the corpora and
   * cannot make it from the n-grams: those were counted after the alphabet
   * existed, so a byte that just missed the cut leaves no trace in them. */
  memcpy (o->byte_freq, byte_freq, sizeof (o->byte_freq));

  for (int i = 0; i < 256; i++)
  {
    f[i].c = (unsigned char) i;
    f[i].n = byte_freq[i];
  }

  qsort (f, 256, sizeof (freq_t), freq_desc);

  o->alpha_n = 0;

  for (int i = 0; (i < 256) && (o->alpha_n < o->alpha_size); i++)
  {
    if (f[i].n == 0) break;

    /* A byte a reader breaks a line on cannot be in the alphabet: the n-grams
     * are one per line in the level files. 0x85 is the one that occurs, NEL when
     * the file is read as latin-1. */
    {
      const unsigned char c = f[i].c;

      if ((c == 0x0b) || (c == 0x0c) || (c == 0x85) || ((c >= 0x1c) && (c <= 0x1e))) continue;
    }

    o->alphabet[o->alpha_n] = (char) f[i].c;
    o->alpha_map[f[i].c]    = o->alpha_n;
    o->alpha_n++;
  }

  if (o->alpha_n < 2) return 1;

  /* The prefix is ngram-1 alphabet symbols, so the index is alpha_n to that
   * power. Refuse rather than allocate something absurd. */
  size_t n = 1;

  for (int i = 1; i < o->ngram; i++)
  {
    if (n > (OMEN_MAX_INDEX / (size_t) o->alpha_n))
    {
      fprintf (stderr, "hpcfg: ngram %d over an alphabet of %d needs too wide a context index; "
                       "lower the ngram or the alphabet\n",
               o->ngram, o->alpha_n);
      return 1;
    }

    n *= (size_t) o->alpha_n;
  }

  o->index = (omen_ctx_t **) calloc (n, sizeof (omen_ctx_t *));

  if (o->index == NULL) return 1;

  o->index_n = n;

  return 0;
}

/* The frequencies this run saw, where the alphabet came from someone else's:
 * counts.txt has to describe this corpus, or a merge counts the shared ones twice. */
void omen_note_freq (omen_t *o, const int64_t *byte_freq)
{
  if ((o != NULL) && (byte_freq != NULL)) memcpy (o->byte_freq, byte_freq, sizeof (o->byte_freq));
}

/* The prefix's number, or -1 if any of its bytes is outside the alphabet. */
static inline int64_t omen_prefix (const omen_t *o, const char *s)
{
  int64_t k = 0;

  for (int i = 0; i < o->ngram - 1; i++)
  {
    const int a = o->alpha_map[(unsigned char) s[i]];

    if (a < 0) return -1;

    k = (k * (int64_t) o->alpha_n) + (int64_t) a;
  }

  return k;
}

static omen_ctx_t *omen_at (omen_t *o, int64_t k, int create)
{
  if ((k < 0) || ((size_t) k >= o->index_n)) return NULL;

  omen_ctx_t *c = o->index[k];

  if ((c != NULL) || (create == 0)) return c;

  /* A context is two kilobytes of counters, one per prefix the corpus shows: on a
   * large list the largest thing here after the terminals. Past the ceiling the
   * n-gram is not counted, the answer the terminal table gives when it is full. */
  if (hp_mem_take (o->mem, sizeof (omen_ctx_t)) == false)
  {
    __atomic_fetch_add (&o->refused, (int64_t) 1, __ATOMIC_RELAXED);

    return NULL;
  }

  omen_ctx_t *fresh = (omen_ctx_t *) calloc (1, sizeof (omen_ctx_t));

  if (fresh == NULL) return NULL;

  if (o->threaded == false)
  {
    o->index[k] = fresh;
    o->ctx_cnt++;

    return fresh;
  }

  omen_ctx_t *expect = NULL;

  if (__atomic_compare_exchange_n (&o->index[k], &expect, fresh, false,
                                   __ATOMIC_RELEASE, __ATOMIC_ACQUIRE) == true)
  {
    __atomic_fetch_add (&o->ctx_cnt, 1, __ATOMIC_RELAXED);

    return fresh;
  }

  free (fresh);

  return expect;
}

void omen_compat (omen_t *o, bool on)
{
  if (o != NULL) o->compat = on;
}

int64_t omen_refused (const omen_t *o)
{
  if (o == NULL) return 0;

  return __atomic_load_n (&o->refused, __ATOMIC_RELAXED);
}

void omen_account (omen_t *o, hp_mem_t *m)
{
  if (o != NULL) o->mem = m;
}

void omen_workers (omen_t *o, int nw)
{
  if (o != NULL) o->nw = (nw > 0) ? nw : 1;
}

void omen_ks_max (omen_t *o, int m)
{
  if (o == NULL) return;

  /* Nothing asked for is the default depth, not the shallowest one. */
  if (m <= 0) m = OMEN_KS_DEFAULT;

  if (m > OMEN_KS_MAXLEVEL) m = OMEN_KS_MAXLEVEL;

  o->ks_max = m;
}

void omen_threaded (omen_t *o, bool on)
{
  if (o != NULL) o->threaded = on;
}

static int in_alphabet (const omen_t *o, const char *s, int len)
{
  for (int i = 0; i < len; i++)
    if (o->alpha_map[(unsigned char) s[i]] < 0) return 0;

  return 1;
}

static inline int omen_min_len (const omen_t *o)
{
  return (o->ngram > OMEN_MIN_LEN) ? o->ngram : OMEN_MIN_LEN;
}

void omen_train (omen_t *o, const char *pw, int pwlen, int64_t n)
{
  if ((pwlen < omen_min_len (o)) || (pwlen > OMEN_MAX_LEN)) return;
  if (o->index == NULL) return;
  if (in_alphabet (o, pw, pwlen) == 0) return;

  const int plen = o->ngram - 1;

  if (o->threaded == true)
    __atomic_fetch_add (&o->ln_count[pwlen], n, __ATOMIC_RELAXED);
  else
    o->ln_count[pwlen] += n;

  for (int i = 0; i <= pwlen - plen; i++)
  {
    omen_ctx_t *c = omen_at (o, omen_prefix (o, pw + i), 1);

    if (c == NULL) continue;

    const bool th = o->threaded;

    if (i == 0)
    {
      if (th)
      {
        __atomic_fetch_add (&c->ip_count, n, __ATOMIC_RELAXED);
        __atomic_fetch_add (&o->total_ip, n, __ATOMIC_RELAXED);
      }
      else
      {
        c->ip_count += n;
        o->total_ip += n;
      }
    }

    if ((i + plen) < pwlen)
    {
      const unsigned char nx = (unsigned char) pw[i + plen];

      if (o->alpha_map[nx] >= 0)
      {
        if (th)
        {
          __atomic_fetch_add (&c->next_count[nx], n, __ATOMIC_RELAXED);
          __atomic_fetch_add (&c->cp_count, n, __ATOMIC_RELAXED);
        }
        else
        {
          c->next_count[nx] += n;
          c->cp_count += n;
        }
      }
    }
    else
    {
      if (th)
      {
        __atomic_fetch_add (&c->ep_count, n, __ATOMIC_RELAXED);
        __atomic_fetch_add (&o->total_ep, n, __ATOMIC_RELAXED);
      }
      else
      {
        c->ep_count += n;
        o->total_ep += n;
      }
    }
  }
}

/*
 * One context per seen prefix with a 256-wide count row, plus the flat index.
 * Neither is in the counting table, so neither was in the budget.
 */
size_t omen_bytes (const omen_t *o)
{
  if (o == NULL) return 0;

  return sizeof (omen_t) + ((size_t) o->ctx_cnt * sizeof (omen_ctx_t)) + (o->index_n * sizeof (omen_ctx_t *));
}

static int calc_level (int64_t base, int64_t total, double adjust)
{
  if ((total == 0) || (base == 0)) return OMEN_MAX_LEVEL;

  const double p = (((double) base / (double) total) * adjust) + 1e-11;

  int lvl = (int) floor (-log (p));

  if (lvl < 0) lvl = 0;
  if (lvl > OMEN_MAX_LEVEL) lvl = OMEN_MAX_LEVEL;

  return lvl;
}

/* The three quantities are scaled before they are turned into levels. */
#define OMEN_ADJUST_IP 250.0
#define OMEN_ADJUST_EP 250.0
#define OMEN_ADJUST_CP 2.0

void omen_smooth (omen_t *o)
{
  int64_t ln_total = 0;

  for (int i = 0; i <= OMEN_MAX_LEN; i++) ln_total += o->ln_count[i];

  /* Length pays twice, for how rare it is and per character. The scale is then
   * moved so the cheapest length is free, which keeps the sums inside the range
   * the readers enumerate. */
  int min_level = -1; /* no length seen yet, which a level can never be */

  o->ln_level[0] = OMEN_MAX_LEVEL; /* no password is zero characters long */

  for (int i = 1; i <= OMEN_MAX_LEN; i++)
  {
    const int lvl = calc_level (o->ln_count[i], ln_total, 1.0) + (i - 1);

    o->ln_level[i] = lvl;

    if ((o->ln_count[i] > 0) && ((min_level < 0) || (lvl < min_level))) min_level = lvl;
  }

  /* The anchor is the cheapest seen length whatever it costs, and is not bounded
   * by the cap on one item: the per-character term alone can put it past that.
   * Capping it left every length at the maximum, equally unreachable. */
  if (min_level < 0) min_level = 0; /* no length at all: nothing to anchor to */

  for (int i = 1; i <= OMEN_MAX_LEN; i++)
  {
    /* A length the corpus never had is not cheap, it is out of reach. */
    if (o->ln_count[i] == 0)
    {
      o->ln_level[i] = OMEN_MAX_LEVEL;

      continue;
    }

    int lvl = o->ln_level[i] - min_level;

    if (lvl > OMEN_MAX_LEVEL) lvl = OMEN_MAX_LEVEL;
    if (lvl < 0) lvl = 0;

    o->ln_level[i] = lvl;
  }

  for (size_t k = 0; k < o->index_n; k++)
  {
    omen_ctx_t *c = o->index[k];

    if (c == NULL) continue;

    c->ip_level = calc_level (c->ip_count, o->total_ip, OMEN_ADJUST_IP);
    if (o->compat == true) c->ep_level = calc_level (c->ep_count, o->total_ep, OMEN_ADJUST_EP);

    for (int j = 0; j < 256; j++)
      c->next_level[j] = (uint8_t) calc_level (c->next_count[j], c->cp_count, OMEN_ADJUST_CP);
  }
}

/*
 * The length level, the initial prefix's, and every transition's. That is
 * hashcat's composition, and EP has no part in it.
 */
int omen_level (omen_t *o, const char *pw, int pwlen)
{
  if ((pwlen < omen_min_len (o)) || (pwlen > OMEN_MAX_LEN)) return -1;
  if (o->index == NULL) return -1;
  if (in_alphabet (o, pw, pwlen) == 0) return -1;

  const int plen = o->ngram - 1;

  if (pwlen < plen) return -1;

  omen_ctx_t *c = omen_at (o, omen_prefix (o, pw), 0);

  if (c == NULL) return -1;

  int lvl = o->ln_level[pwlen] + c->ip_level;

  for (int i = 0; (i + plen) < pwlen; i++)
  {
    omen_ctx_t *t = omen_at (o, omen_prefix (o, pw + i), 0);

    if (t == NULL) return -1;

    lvl += (int) t->next_level[(unsigned char) pw[i + plen]];
  }

  return lvl;
}

int64_t omen_contexts (const omen_t *o)
{
  return o->ctx_cnt;
}

static int64_t sat_add (int64_t a, int64_t b)
{
  if (a > (INT64_MAX - b)) return INT64_MAX;

  return a + b;
}

/* One transition, resolved: which context it lands in and at which level. */
typedef struct
{
  int32_t dst;
  uint8_t lvl;
} omen_ks_tr_t;

/* One slice of the levels for one length of the keyspace walk. */
typedef struct
{
  const omen_ks_tr_t *tr;
  const int64_t *off;
  const int64_t *cur;
  int64_t *nxt;
  int64_t nctx;
  int nlvl;
  int rmax;
  int64_t lo, hi;
} omen_ks_job_t;

static void *omen_ks_worker (void *arg)
{
  omen_ks_job_t *j = (omen_ks_job_t *) arg;

  const int nlvl = j->nlvl;

  /*
   * Contexts outside, levels inside, so one context's transitions are read
   * once and stay in cache down the level loop.
   */
  for (int64_t c = j->lo; c < j->hi; c++)
  {
    const int64_t e0 = j->off[c];
    const int64_t e1 = j->off[c + 1];

    int64_t *row = j->nxt + (c * nlvl);

    if (e0 == e1)
    {
      for (int r = 0; r <= j->rmax; r++) row[r] = 0;

      continue;
    }

    /* A context seen once normally has one continuation, and its row is then the
     * source shifted by that transition's level - a contiguous copy, which
     * cannot saturate with a single term. The leading levels are zero. */
#if HP_OMEN_SINGLE_FAST
    if (e1 == (e0 + 1))
    {
      const int lv = (int) j->tr[e0].lvl;

      if (lv > j->rmax)
      {
        memset (row, 0, ((size_t) j->rmax + 1) * sizeof (*row));
      }
      else
      {
        if (lv > 0) memset (row, 0, (size_t) lv * sizeof (*row));

        const int64_t *src = j->cur + ((int64_t) j->tr[e0].dst * nlvl);

        memcpy (row + lv, src, ((size_t) j->rmax - (size_t) lv + 1) * sizeof (*row));
      }

      continue;
    }
#endif

    for (int r = 0; r <= j->rmax; r++)
    {
      int64_t acc = 0;

      for (int64_t e = e0; e < e1; e++)
      {
        const int lv = (int) j->tr[e].lvl;

        if (lv > r) break;

        acc = sat_add (acc, j->cur[((int64_t) j->tr[e].dst * nlvl) + (r - lv)]);
      }

      row[r] = acc;
    }
  }

  return NULL;
}

static int omen_keyspace (const omen_t *o, int64_t *ks)
{
  const int clen = o->ngram - 1;
  const int nlvl = ((o->ks_max > 0) ? o->ks_max : OMEN_KS_DEFAULT) + 1;

  for (int i = 0; i < nlvl; i++) ks[i] = 0;

  if ((o->index == NULL) || (o->ctx_cnt <= 0)) return 1;

  /* The contexts that exist, numbered from zero, so the layers are the size
   * of the model rather than of the index it is spread over. */
  int32_t *id = (int32_t *) malloc (o->index_n * sizeof (int32_t));

  if (id == NULL) return 1;

  int64_t *at = (int64_t *) malloc ((size_t) o->ctx_cnt * sizeof (int64_t));

  if (at == NULL)
  {
    free (id);
    return 1;
  }

  int64_t nctx = 0;

  for (size_t k = 0; k < o->index_n; k++)
  {
    if (o->index[k] == NULL)
    {
      id[k] = -1;
      continue;
    }

    if (nctx >= o->ctx_cnt) break;

    id[k]    = (int32_t) nctx;
    at[nctx] = (int64_t) k;
    nctx++;
  }

  int64_t *cur = (int64_t *) calloc ((size_t) nctx * (size_t) nlvl, sizeof (int64_t));
  int64_t *nxt = (int64_t *) calloc ((size_t) nctx * (size_t) nlvl, sizeof (int64_t));

  if ((cur == NULL) || (nxt == NULL))
  {
    free (cur);
    free (nxt);
    free (at);
    free (id);

    return 1;
  }

  /* Appending nothing costs nothing, and there is one way to do it. */
  for (int64_t c = 0; c < nctx; c++) cur[c * nlvl] = 1;

  /* The number the prefix keeps when its first character falls off, which is
   * where the next context's number is built from. */
  int64_t drop = 1;

  for (int i = 1; i < clen; i++) drop *= (int64_t) o->alpha_n;

  /* One length at a time; inside it the contexts are independent, each writing
   * its own row and reading only the layer before. So they split across workers
   * and the length is the barrier. */
  int64_t *off = (int64_t *) calloc ((size_t) nctx + 1, sizeof (int64_t));

  if (off == NULL)
  {
    free (cur);
    free (nxt);
    free (at);
    free (id);

    return 1;
  }

  for (int64_t c = 0; c < nctx; c++)
  {
    const omen_ctx_t *x = o->index[at[c]];

    int64_t deg = 0;

    if (x->cp_count != 0)
    {
      const int64_t tail = (at[c] % drop) * (int64_t) o->alpha_n;

      for (int b = 0; b < 256; b++)
      {
        if (x->next_count[b] == 0) continue;

        const int a = o->alpha_map[b];

        if (a < 0) continue;

        if (id[tail + a] < 0) continue;

        deg++;
      }
    }

    off[c + 1] = deg;
  }

  for (int64_t c = 0; c < nctx; c++) off[c + 1] += off[c];

  const int64_t ntr = off[nctx];

  omen_ks_tr_t *tr = (omen_ks_tr_t *) malloc ((size_t) ((ntr > 0) ? ntr : 1) * sizeof (omen_ks_tr_t));

  if (tr == NULL)
  {
    free (off);
    free (cur);
    free (nxt);
    free (at);
    free (id);

    return 1;
  }

  for (int64_t c = 0; c < nctx; c++)
  {
    const omen_ctx_t *x = o->index[at[c]];

    if (x->cp_count == 0) continue;

    const int64_t tail = (at[c] % drop) * (int64_t) o->alpha_n;

    int64_t e = off[c];

    for (int b = 0; b < 256; b++)
    {
      if (x->next_count[b] == 0) continue;

      const int a = o->alpha_map[b];

      if (a < 0) continue;

      const int32_t t = id[tail + a];

      if (t < 0) continue;

      tr[e].dst = t;
      tr[e].lvl = x->next_level[b];

      e++;
    }

    /*
     * Sorted by level so the scan stops rather than skips. A counting sort
     * over a small fixed set, and it keeps the byte order inside one level.
     */
    int64_t cnt[256];

    memset (cnt, 0, sizeof (cnt));

    for (int64_t k = off[c]; k < e; k++) cnt[tr[k].lvl]++;

    int64_t run = off[c];

    for (int l = 0; l < 256; l++)
    {
      const int64_t m = cnt[l];

      cnt[l] = run;
      run += m;
    }

    omen_ks_tr_t *tmp = (omen_ks_tr_t *) malloc ((size_t) (e - off[c]) * sizeof (omen_ks_tr_t));

    if (tmp != NULL)
    {
      memcpy (tmp, tr + off[c], (size_t) (e - off[c]) * sizeof (omen_ks_tr_t));

      for (int64_t k = 0; k < (e - off[c]); k++) tr[cnt[tmp[k].lvl]++] = tmp[k];

      free (tmp);
    }
  }

  const int nw = (o->nw > 1) ? o->nw : 1;

  omen_ks_job_t *jobs = (omen_ks_job_t *) calloc ((size_t) nw, sizeof (omen_ks_job_t));

  hp_thread_t **th = (hp_thread_t **) calloc ((size_t) nw, sizeof (hp_thread_t *));

  if ((jobs == NULL) || (th == NULL))
  {
    free (jobs);
    free (th);
    free (tr);
    free (off);
    free (cur);
    free (nxt);
    free (at);
    free (id);

    return 1;
  }

  /* A length reads the layer from base = ln_level[len] + ip_level and stops at
   * nlvl, so nothing above nlvl - ln_level[len] - min_ip is ever read, at this
   * length or a later one since ln_level only grows. */
  int min_ip = nlvl;

  for (int64_t c = 0; c < nctx; c++)
  {
    const omen_ctx_t *x = o->index[at[c]];

    if (x->ip_level < min_ip) min_ip = x->ip_level;
  }

  if (min_ip < 0) min_ip = 0;

  for (int len = clen + 1; len <= OMEN_MAX_LEN; len++)
  {
    int rmax = nlvl - 1 - o->ln_level[len] - min_ip;

    if (rmax < 0) rmax = 0;
    if (rmax > (nlvl - 1)) rmax = nlvl - 1;

    /* No clearing: every level and every context is written below, so the
     * layer is filled rather than accumulated into. */
    for (int i = 0; i < nw; i++)
    {
      jobs[i].tr   = tr;
      jobs[i].off  = off;
      jobs[i].cur  = cur;
      jobs[i].nxt  = nxt;
      jobs[i].nlvl = nlvl;
      jobs[i].rmax = rmax;
      jobs[i].lo   = (nctx * i) / nw;
      jobs[i].hi   = (nctx * (i + 1)) / nw;
    }

    for (int i = 1; i < nw; i++) th[i] = hp_thread_start (omen_ks_worker, &jobs[i]);

    omen_ks_worker (&jobs[0]);

    /* A slice whose thread never started is walked here instead: the contexts
     * are independent, so it does not matter which thread does which. */
    for (int i = 1; i < nw; i++)
      if (th[i] == NULL) omen_ks_worker (&jobs[i]);

    for (int i = 1; i < nw; i++) hp_thread_join (th[i]);

    int64_t *tmp = cur;

    cur = nxt;
    nxt = tmp;

    /* What the initial prefixes reach at this length. */
    for (int64_t c = 0; c < nctx; c++)
    {
      const omen_ctx_t *x = o->index[at[c]];

      const int base = o->ln_level[len] + x->ip_level;

      if (base >= nlvl) continue;

      const int64_t *row = cur + (c * nlvl);

      for (int r = 0; (base + r) < nlvl; r++)
        if (row[r] != 0) ks[base + r] = sat_add (ks[base + r], row[r]);
    }
  }

  free (jobs);
  free (th);
  free (tr);
  free (off);
  free (cur);
  free (nxt);
  free (at);
  free (id);

  return 0;
}

/* Millions of small lines, where fprintf takes a lock, walks a format string and
 * calls the number formatter once each. A letter, a string and an integer are
 * built by hand into one buffer instead: same bytes, a fraction of the work. */
#define OMEN_WBUF (1u << 20)

typedef struct
{
  FILE *f;
  char *buf;
  size_t n;
} omen_w_t;

static void ow_flush (omen_w_t *w)
{
  if (w->n > 0) fwrite (w->buf, 1, w->n, w->f);

  w->n = 0;
}

static inline void ow_room (omen_w_t *w, size_t need)
{
  if ((w->n + need) > OMEN_WBUF) ow_flush (w);
}

static inline void ow_str (omen_w_t *w, const char *s, size_t len)
{
  memcpy (w->buf + w->n, s, len);

  w->n += len;
}

static inline void ow_i64 (omen_w_t *w, int64_t v)
{
  char tmp[24];
  int i = 0;

  if (v == 0) tmp[i++] = '0';

  while (v > 0)
  {
    tmp[i++] = (char) ('0' + (v % 10));
    v /= 10;
  }

  while (i > 0) w->buf[w->n++] = tmp[--i];
}

static void omen_unprefix (const omen_t *o, int64_t k, char *out)
{
  for (int i = o->ngram - 2; i >= 0; i--)
  {
    out[i] = o->alphabet[k % (int64_t) o->alpha_n];
    k /= (int64_t) o->alpha_n;
  }

  out[o->ngram - 1] = '\0';
}

int omen_save (omen_t *o, const char *dir, const int64_t *lvl_counts, int nlevels, int64_t pw_total)
{
  char path[PCFG_MAXPATH];
  char pre[16];
  FILE *f;

  /* Millions of lines, so they are built in a buffer rather than printed one by one. */
  const size_t plen = (size_t) (o->ngram - 1);

  omen_w_t w;

  w.f   = NULL;
  w.n   = 0;
  w.buf = (char *) malloc (OMEN_WBUF + 64);

  if (w.buf == NULL) return 1;

  snprintf (path, sizeof (path), "%s/config.txt", dir);

  f = fopen (path, "wb");
  if (f == NULL) return 1;

  /* pcfg_cracker's configparser insists on the section header: a bare "ngram=4"
   * is a MissingSectionHeaderError. hashcat skips lines without an '='. */
  bool ascii = true;

  for (int i = 0; i < o->alpha_n; i++)
    if ((unsigned char) o->alphabet[i] >= 0x80) ascii = false;

  fprintf (f, "[training_settings]\nngram = %d\nencoding = %s\nalphabet_size = %d\n",
           o->ngram, (ascii == true) ? "utf-8" : "latin-1", o->alpha_n);
  if (hp_fclose_w (f, path) != 0) return 1;

  if (o->compat == true)
  {
    snprintf (path, sizeof (path), "%s/alphabet.txt", dir);

    f = fopen (path, "wb");
    if (f == NULL) return 1;
    fwrite (o->alphabet, 1, (size_t) o->alpha_n, f);
    fputc ('\n', f);
    if (hp_fclose_w (f, path) != 0) return 1;
  }

  /* IP and CP and LN are what the reader wants, as "level<TAB>gram". */

  snprintf (path, sizeof (path), "%s/IP.level", dir);

  f = fopen (path, "wb");
  if (f == NULL) return 1;

  w.f = f;
  w.n = 0;

  /* Every context, not only the ones a password started with: a prefix never
   * seen at the start still has the level smoothing floors it at, and
   * pcfg_cracker writes it. Dropping them loses every OMEN guess starting where
   * no password did. */
  for (size_t k = 0; k < o->index_n; k++)
  {
    const omen_ctx_t *c = o->index[k];

    if (c == NULL) continue;

    omen_unprefix (o, (int64_t) k, pre);
    ow_room (&w, plen + 24);
    ow_i64 (&w, c->ip_level);
    w.buf[w.n++] = '\t';
    ow_str (&w, pre, plen);
    w.buf[w.n++] = '\n';
  }

  ow_flush (&w);
  if (hp_fclose_w (f, path) != 0) return 1;

  /* EP is the level of a prefix ending a password. Neither this trainer nor
   * hashcat uses it, but pcfg_cracker and pcfg-go both open EP.level while
   * loading and stop if it is missing. */
  if (o->compat == true)
  {
    snprintf (path, sizeof (path), "%s/EP.level", dir);

    f = fopen (path, "wb");
    if (f == NULL) return 1;

    w.f = f;
    w.n = 0;

    for (size_t k = 0; k < o->index_n; k++)
    {
      const omen_ctx_t *c = o->index[k];

      if (c == NULL) continue;

      omen_unprefix (o, (int64_t) k, pre);
      ow_room (&w, plen + 24);
      ow_i64 (&w, c->ep_level);
      w.buf[w.n++] = '\t';
      ow_str (&w, pre, plen);
      w.buf[w.n++] = '\n';
    }

    ow_flush (&w);
    if (hp_fclose_w (f, path) != 0) return 1;
  }

  snprintf (path, sizeof (path), "%s/CP.level", dir);

  f = fopen (path, "wb");
  if (f == NULL) return 1;

  w.f = f;
  w.n = 0;

  for (size_t k = 0; k < o->index_n; k++)
  {
    const omen_ctx_t *c = o->index[k];

    if (c == NULL) continue;

    omen_unprefix (o, (int64_t) k, pre);

    for (int j = 0; j < 256; j++)
    {
      if (c->next_count[j] == 0) continue;

      ow_room (&w, plen + 26);
      ow_i64 (&w, c->next_level[j]);
      w.buf[w.n++] = '\t';
      ow_str (&w, pre, plen);
      w.buf[w.n++] = (char) j;
      w.buf[w.n++] = '\n';
    }
  }

  ow_flush (&w);
  if (hp_fclose_w (f, path) != 0) return 1;

  snprintf (path, sizeof (path), "%s/LN.level", dir);

  f = fopen (path, "wb");
  if (f == NULL) return 1;

  /* The first line is length 1, not length 0. */
  for (int i = 1; i <= OMEN_MAX_LEN; i++) fprintf (f, "%d\n", o->ln_level[i]);
  if (hp_fclose_w (f, path) != 0) return 1;

  int64_t tot = 0;

  for (int i = 0; i < nlevels; i++) tot += lvl_counts[i];

  if (pw_total <= 0) pw_total = tot;

  /* Both remaining files are shares of the keyspace, so it comes first. */
  int64_t ks[OMEN_KS_LEVELS];

  /* The two files that name levels are cut at the same place, always. */
  const int ksmax = (o->ks_max > 0) ? o->ks_max : OMEN_KS_DEFAULT;

  const bool have_ks = (omen_keyspace (o, ks) == 0);

  /* What one guess at a level is worth. */
  if ((tot > 0) && (have_ks == true))
  {
    snprintf (path, sizeof (path), "%s/pcfg_omen_prob.txt", dir);

    f = fopen (path, "wb");
    if (f == NULL) return 1;

    for (int i = 0; (i < nlevels) && (i <= ksmax); i++)
    {
      if (lvl_counts[i] == 0) continue;
      if (ks[i] <= 0) continue;

      const double share = (double) lvl_counts[i] / (double) pw_total;

      fprintf (f, "%d\t%.17g\n", i, share / (double) ks[i]);
    }

    if (hp_fclose_w (f, path) != 0) return 1;
  }

  /* The same distribution as counts rather than shares, for pcfg_cracker's tooling. */
  if (tot > 0)
  {
    snprintf (path, sizeof (path), "%s/omen_pws_per_level.txt", dir);

    f = fopen (path, "wb");
    if (f == NULL) return 1;

    for (int i = 0; i < nlevels; i++)
    {
      if (lvl_counts[i] == 0) continue;

      fprintf (f, "%d\t%" PRId64 "\n", i, lvl_counts[i]);
    }

    if (hp_fclose_w (f, path) != 0) return 1;
  }

  /* pcfg_cracker opens this while building the grammar, then asks it for the
   * level of every guess it makes: a level the model generates and this does not
   * name is a KeyError mid-run. So every level is written, empty ones too. */
  if (have_ks == true)
  {
    if (o->compat == true)
    {
      snprintf (path, sizeof (path), "%s/omen_keyspace.txt", dir);

      f = fopen (path, "wb");
      if (f == NULL) return 1;

      /* Every level, and no stopping at the first large one. */
      for (int i = 0; i <= ksmax; i++) fprintf (f, "%d\t%" PRId64 "\n", i, ks[i]);

      if (hp_fclose_w (f, path) != 0) return 1;
    }
  }

  free (w.buf);

  return 0;
}

int omen_write_counts (const omen_t *o, const char *dir)
{
  char path[PCFG_MAXPATH];
  char pre[16];

  snprintf (path, sizeof (path), "%s/counts.txt", dir);

  FILE *f = fopen (path, "wb");

  if (f == NULL) return 1;

  fprintf (f, "ngram=%d\n", o->ngram);

  /* The alphabet as chosen, so a merge takes the union rather than guessing. */
  fprintf (f, "alphabet=");
  fwrite (o->alphabet, 1, (size_t) o->alpha_n, f);
  fputc ('\n', f);

  fprintf (f, "width=%d\n", o->alpha_size);

  /* And what it was chosen from, so the merge can choose again over the sum. */
  fprintf (f, "bytes=");

  for (int i = 0; i < 256; i++) fprintf (f, "%s%" PRId64, (i > 0) ? "," : "", o->byte_freq[i]);

  fputc ('\n', f);

  omen_w_t w;

  w.f   = f;
  w.n   = 0;
  w.buf = (char *) malloc (OMEN_WBUF + 64);

  if (w.buf == NULL)
  {
    if (hp_fclose_w (f, path) != 0) return 1;

    return 1;
  }

  for (int i = 1; i <= OMEN_MAX_LEN; i++)
  {
    if (o->ln_count[i] == 0) continue;

    ow_room (&w, 64);
    ow_str (&w, "L\t", 2);
    ow_i64 (&w, i);
    w.buf[w.n++] = '\t';
    ow_i64 (&w, o->ln_count[i]);
    w.buf[w.n++] = '\n';
  }

  const size_t plen = (size_t) (o->ngram - 1);

  for (size_t k = 0; k < o->index_n; k++)
  {
    const omen_ctx_t *c = o->index[k];

    if (c == NULL) continue;

    omen_unprefix (o, (int64_t) k, pre);

    if (c->ip_count > 0)
    {
      ow_room (&w, plen + 40);
      ow_str (&w, "I\t", 2);
      ow_str (&w, pre, plen);
      w.buf[w.n++] = '\t';
      ow_i64 (&w, c->ip_count);
      w.buf[w.n++] = '\n';
    }

    if (c->ep_count > 0)
    {
      ow_room (&w, plen + 40);
      ow_str (&w, "E\t", 2);
      ow_str (&w, pre, plen);
      w.buf[w.n++] = '\t';
      ow_i64 (&w, c->ep_count);
      w.buf[w.n++] = '\n';
    }

    for (int j = 0; j < 256; j++)
    {
      if (c->next_count[j] == 0) continue;

      ow_room (&w, plen + 42);
      ow_str (&w, "C\t", 2);
      ow_str (&w, pre, plen);
      w.buf[w.n++] = (char) j;
      w.buf[w.n++] = '\t';
      ow_i64 (&w, c->next_count[j]);
      w.buf[w.n++] = '\n';
    }
  }

  ow_flush (&w);

  free (w.buf);

  if (hp_fclose_w (f, path) != 0) return 1;

  return 0;
}

static int omen_union_alphabet (const char *dir, char *alpha, int *n)
{
  char path[PCFG_MAXPATH];

  snprintf (path, sizeof (path), "%s/Omen/counts.txt", dir);

  FILE *f = fopen (path, "rb");

  if (f == NULL) return 1;

  char line[4096];

  int ngram = 0;

  while (fgets (line, sizeof (line), f) != NULL)
  {
    if (strncmp (line, "ngram=", 6) == 0)
    {
      ngram = atoi (line + 6);

      continue;
    }

    if (strncmp (line, "alphabet=", 9) != 0) break;

    int len = (int) strlen (line);

    while ((len > 0) && ((line[len - 1] == '\n') || (line[len - 1] == '\r'))) len--;

    for (int i = 9; i < len; i++)
    {
      bool seen = false;

      for (int j = 0; j < *n; j++)
        if (alpha[j] == line[i]) seen = true;

      if ((seen == false) && (*n < 255)) alpha[(*n)++] = line[i];
    }

    break;
  }

  fclose (f);

  return (ngram > 0) ? ngram : 1;
}

omen_t *omen_merge_counts (char **dirs, const double *weight, int nin, bool compat)
{
  char alpha[256];
  int an = 0;

  int ngram = 0;

  for (int i = 0; i < nin; i++)
  {
    const int n = omen_union_alphabet (dirs[i], alpha, &an);

    if (n <= 1) return NULL; /* no counts file: nothing to merge from */

    if (ngram == 0)
      ngram = n;
    else if (ngram != n)
      return NULL;
  }

  if ((an < 2) || (ngram < 2)) return NULL;

  /*
   * The alphabet, chosen the way training chooses it: over the summed byte
   * frequencies of the corpora, by the same rule and to the same width.
   */
  int64_t freq[256];

  memset (freq, 0, sizeof (freq));

  int want = 0;

  for (int i = 0; i < nin; i++)
  {
    char path[PCFG_MAXPATH];

    snprintf (path, sizeof (path), "%s/Omen/counts.txt", dirs[i]);

    FILE *f = fopen (path, "rb");

    if (f == NULL) continue;

    char line[4096];

    const double w0 = (weight != NULL) ? (weight[i] * (double) nin) : 1.0;

    while (fgets (line, sizeof (line), f) != NULL)
    {
      if (strncmp (line, "width=", 6) == 0)
      {
        const int mine = atoi (line + 6);

        if (mine > want) want = mine;

        continue;
      }

      if (strncmp (line, "bytes=", 6) != 0) continue;

      const char *at = line + 6;

      for (int c = 0; c < 256; c++)
      {
        char *end = NULL;

        const int64_t v = strtoll (at, &end, 10);

        if (end == at) break;

        freq[c] += (int64_t) ((v * w0) + 0.5);

        at = (*end == ',') ? (end + 1) : end;
      }

      break; /* the header is all this pass wanted */
    }

    fclose (f);
  }

  if (want <= 0) want = an;

  omen_t *o = omen_new (ngram, want);

  if (o == NULL) return NULL;

  /* The same function training uses, which also allocates the context index. */
  if (omen_build_alphabet (o, freq) != 0)
  {
    omen_free (o);

    return NULL;
  }

  an = o->alpha_n;

  const int clen = ngram - 1;

  for (int i = 0; i < nin; i++)
  {
    char path[PCFG_MAXPATH];

    snprintf (path, sizeof (path), "%s/Omen/counts.txt", dirs[i]);

    FILE *f = fopen (path, "rb");

    if (f == NULL) continue;

    const double w = (weight != NULL) ? (weight[i] * (double) nin) : 1.0;

    char line[4096];

    while (fgets (line, sizeof (line), f) != NULL)
    {
      const char kind = line[0];

      if ((kind != 'L') && (kind != 'I') && (kind != 'E') && (kind != 'C')) continue;

      char *a = strchr (line, '\t');

      if (a == NULL) continue;

      char *b = strchr (a + 1, '\t');

      if (b == NULL) continue;

      *a = '\0';
      *b = '\0';

      const char *key = a + 1;
      const int64_t n = (int64_t) ((strtoll (b + 1, NULL, 10) * w) + 0.5);

      if (n <= 0) continue;

      if (kind == 'L')
      {
        const int len = atoi (key);

        if ((len >= 0) && (len <= OMEN_MAX_LEN)) o->ln_count[len] += n;

        continue;
      }

      const int klen = (int) strlen (key);

      if (klen < clen) continue;

      omen_ctx_t *c = omen_at (o, omen_prefix (o, key), 1);

      if (c == NULL) continue;

      if (kind == 'I')
      {
        c->ip_count += n;
        o->total_ip += n;
      }
      else if (kind == 'E')
      {
        c->ep_count += n;
        o->total_ep += n;
      }
      else if (klen > clen)
      {
        const unsigned char nx = (unsigned char) key[clen];

        c->next_count[nx] += n;
        c->cp_count += n;
      }
    }

    fclose (f);
  }

  if (o->ctx_cnt == 0)
  {
    omen_free (o);

    return NULL;
  }

  /* Before the levels: the end prefix level is one of them, and it is computed
   * only for the readers that want it. */
  omen_compat (o, compat);

  omen_smooth (o);

  return o;
}
