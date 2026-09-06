/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * Splitting a compound alpha run into known words.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcfg_common.h"

struct pcfg_words
{
  hp_store_t *words;
  int threshold;
  int min_len;
  int max_len;
  int min_check_len;
  int readonly;
  int pretrain; /* the words being read are a dictionary, not a corpus */
};

pcfg_words_t *pcfg_multiword_init (int threshold, int min_len, int max_len)
{
  pcfg_words_t *mw = (pcfg_words_t *) calloc (1, sizeof (pcfg_words_t));

  if (mw == NULL) return NULL;

  mw->words     = hp_store_new (16, 4u << 20);
  mw->threshold = threshold;

  /* The admission filter cannot be used here, though it looks as if it could. */

  mw->min_len       = min_len;
  mw->max_len       = max_len;
  mw->min_check_len = min_len * 2;

  return mw;
}

void pcfg_multiword_destroy (pcfg_words_t *mw)
{
  if (mw == NULL) return;

  hp_store_free (mw->words);
  free (mw);
}

/* While this is on, pcfg_multiword_train () reads a dictionary, not a corpus. */
void pcfg_multiword_pretrain (pcfg_words_t *mw, bool on)
{
  if (mw != NULL) mw->pretrain = (on == true) ? 1 : 0;
}

void pcfg_multiword_set_readonly (pcfg_words_t *mw)
{
  if (mw == NULL) return;

  mw->readonly = 1;

  /* Nothing writes to it after this, so the locks come off: every parse in the
   * counting pass looks words up, and a lock each would serialise the threads. */
  hp_store_threaded (mw->words, false);
}

/* The word set draws on the same ceiling as everything else. */
void pcfg_multiword_account (pcfg_words_t *mw, hp_mem_t *mem)
{
  if (mw != NULL) hp_store_account (mw->words, mem);
}

/* Written by every worker of the first pass, so it needs the same per-shard
 * locking the counters use, or a bucket list becomes a cycle and lookup hangs. */
void pcfg_multiword_threaded (pcfg_words_t *mw, bool on)
{
  if (mw != NULL) hp_store_threaded (mw->words, on);
}

/* The key a word is filed under: its codepoints lowered, every byte kept. */
static int mw_key (const char *word, int len, char *out, int outsz)
{
  int oi = 0, i = 0;

  while (i < len)
  {
    uint32_t cp;

    const int n = utf8_decode (word + i, len - i, &cp);

    if (n == 0) break;

    char enc[4];

    const int elen = utf8_encode (enc, utf8_to_lower (cp));

    if ((oi + elen) > outsz) return -1;

    for (int b = 0; b < elen; b++) out[oi++] = enc[b];

    i += n;
  }

  return oi;
}

void pcfg_multiword_train (pcfg_words_t *mw, const char *pw, int pwlen, int64_t n)
{
  if ((mw == NULL) || (mw->readonly != 0)) return;

  char key[PCFG_MAXLINE];

  /* A DELIBERATE DIVERGENCE from pcfg-cracker and pcfg-go. */

  int i = 0;

  while (i < pwlen)
  {
    uint32_t cp;

    const int cn = utf8_decode (pw + i, pwlen - i, &cp);

    if (cn == 0)
    {
      i++;

      continue;
    }

    if (utf8_is_alpha (cp) == 0)
    {
      i += cn;

      continue;
    }

    /* One letter run, measured in codepoints: a word is letters and not bytes. */
    const int start = i;

    int run = 0;

    while (i < pwlen)
    {
      uint32_t c2;

      const int n2 = utf8_decode (pw + i, pwlen - i, &c2);

      if ((n2 == 0) || (utf8_is_alpha (c2) == 0)) break;

      run++;
      i += n2;
    }

    if ((run < mw->min_len) || (run > mw->max_len)) continue;

    const int klen = mw_key (pw + start, i - start, key, (int) sizeof (key));

    if (klen <= 0) continue;

    /* A dictionary word starts at the threshold, however rare it is here. */
    if (mw->pretrain != 0)
    {
      const int64_t have = hp_store_get (mw->words, (uint8_t) 'W', 0, key, klen);

      hp_store_add (mw->words, (uint8_t) 'W', 0, key, klen,
                    (have == 0) ? (int64_t) mw->threshold : 1);
    }
    else
    {
      hp_store_add (mw->words, (uint8_t) 'W', 0, key, klen, n);
    }
  }
}

static int64_t word_count (pcfg_words_t *mw, const char *word, int len)
{
  char key[PCFG_MAXLINE];

  const int klen = mw_key (word, len, key, (int) sizeof (key));

  if (klen <= 0) return 0;

  return hp_store_get (mw->words, (uint8_t) 'W', 0, key, klen);
}

/* A counting table of its own, and on a large list the biggest thing here: every
 * distinct lowercase run between the bounds. It has to be inside the budget. */
size_t pcfg_multiword_bytes (const pcfg_words_t *mw)
{
  if ((mw == NULL) || (mw->words == NULL)) return 0;

  return hp_store_bytes (mw->words);
}

/* One word per line, which is what --multiword reads back. */
typedef struct
{
  FILE *f;
  int64_t min;
  int64_t n;
} mw_dump_t;

static void mw_dump_one (const char *val, int vlen, int64_t cnt, void *arg)
{
  mw_dump_t *d = (mw_dump_t *) arg;

  if (cnt < d->min) return;

  /* A word carrying a byte a reader breaks a line on cannot be written either. */
  for (int i = 0; i < vlen; i++)
  {
    const unsigned char c = (unsigned char) val[i];

    if ((c == '\n') || (c == '\r') || (c == 0x0b) || (c == 0x0c) || (c == 0x85)) return;
    if ((c >= 0x1c) && (c <= 0x1e)) return;
  }

  fwrite (val, 1, (size_t) vlen, d->f);
  fputc ('\n', d->f);

  d->n++;
}

/* The words this run decided were words. */
int pcfg_multiword_save (pcfg_words_t *mw, const char *path, int64_t min_count)
{
  if (mw == NULL) return 1;

  FILE *f = fopen (path, "wb");

  if (f == NULL)
  {
    fprintf (stderr, "hpcfg: cannot create \"%s\": %s\n", path, strerror (errno));

    return 1;
  }

  mw_dump_t d;

  d.f   = f;
  d.min = (min_count > 0) ? min_count : mw->threshold;
  d.n   = 0;

  hp_store_foreach (mw->words, (uint8_t) 'W', 0, mw_dump_one, &d);

  if (hp_fclose_w (f, path) != 0) return 1;

  fprintf (stderr, "hpcfg: %" PRId64 " words written to %s\n", d.n, path);

  return 0;
}

static int multiword_split (pcfg_words_t *mw, const char *s, int slen, int *splits, int *nsplits, int max)
{
  const int max_front = slen - mw->min_len;

  for (int front = max_front; front >= mw->min_len; front--)
  {
    if (word_count (mw, s, front) < mw->threshold) continue;

    const int back = slen - front;

    if ((back >= mw->min_len) && (word_count (mw, s + front, back) >= mw->threshold))
    {
      if ((*nsplits + 2) > max) return 0;

      splits[(*nsplits)++] = front;
      splits[(*nsplits)++] = back;

      return 1;
    }

    if (back >= mw->min_check_len)
    {
      if ((*nsplits + 1) > max) return 0;

      const int saved = *nsplits;

      splits[(*nsplits)++] = front;

      if (multiword_split (mw, s + front, back, splits, nsplits, max)) return 1;

      *nsplits = saved;
    }
  }

  return 0;
}

int pcfg_multiword_parse (pcfg_words_t *mw, const char *alpha, int alen, int *parts, int max_parts)
{
  if ((mw == NULL) || (max_parts < 2)) return 0;
  /* maximum included, as in training: there it is excluded here and included there */
  if ((alen < mw->min_len) || (alen > mw->max_len)) return 0;

  if (word_count (mw, alpha, alen) >= mw->threshold)
  {
    parts[0] = alen;

    return 1;
  }

  if (alen < mw->min_check_len) return 0;

  int nsplits = 0;

  if (multiword_split (mw, alpha, alen, parts, &nsplits, max_parts)) return nsplits;

  return 0;
}
