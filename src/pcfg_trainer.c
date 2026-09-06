/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * The training run: the passes over the corpus, what each password puts into the
 * counters, and the writing that follows.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pcfg_trainer_utils.h"
#include "pcfg_platform.h"
#include "pcfg_common.h"
#include "pcfg_trainer_omen.h"
#include "pcfg_ruleset.h"
#include "pcfg_trainer.h"

/* Set by a coverage of zero: the grammar gives up its share, so the structures
 * are not counted at all rather than counted and thrown away. */
static bool hp_no_structs = false;

/* Set by --no-multiword: no run is ever split. The pass still runs, because it
 * is also where the byte frequencies come from. */
static bool hp_mw_off = false;

/* Set from --save-sensitive: addresses and URLs are counted only when asked. */
static bool hp_sensitive = false;
static bool hp_compat    = false; /* write what only the other readers use */

#ifndef HP_FUSE_ALPHA
#define HP_FUSE_ALPHA 1
#endif

#if HP_FUSE_ALPHA
/* The lowercase spelling and the U/L mask of one run, in a single walk rather
 * than two passes decoding every codepoint twice. */
static int hp_lower_and_mask (const char *in, int inlen, char *low, char *mask, int *masklen)
{
  int si = 0, li = 0, mi = 0;

  while (si < inlen)
  {
    const unsigned char c = (unsigned char) in[si];

    if (c < 0x80)
    {
      mask[mi++] = ((c >= 'A') && (c <= 'Z')) ? 'U' : 'L';

      if (li < PCFG_MAXLINE - 4) low[li++] = ((c >= 'A') && (c <= 'Z')) ? (char) (c + 32) : (char) c;

      si++;

      continue;
    }

    uint32_t cp;

    const int adv = utf8_decode (in + si, inlen - si, &cp);

    if (adv == 0) break;

    mask[mi++] = utf8_is_upper (cp) ? 'U' : 'L';

    if (li < PCFG_MAXLINE - 4) li += utf8_encode (low + li, utf8_to_lower (cp));

    si += adv;
  }

  mask[mi] = '\0';
  *masklen = mi;

  return li;
}
#endif

static void hp_train_one (hp_store_t *st, hp_store_t *base, char *pw, int len, int64_t n,
                          unsigned char *tag, char *lower, int64_t *pw_cnt)
{
  pcfg_token_t sects[PCFG_MAXSECTIONS];
  hp_seen_t seen;

  const int nsects = pcfg_tokenize (pw, len, sects, PCFG_MAXSECTIONS, tag, lower, &seen);

  if (nsects <= 0) return;

  for (int i = 0; i < nsects; i++)
    if (sects[i].cp_len > 255) return;

  /* And a structure with more tokens than a reader has slots for: hashcat drops
   * it on the way in, so its mass would go where nothing can guess. */
  if (hp_structure_fits (sects, nsects) == false) return;

  (*pw_cnt) += n;

  for (int i = 0; i < nsects; i++)
  {
    pcfg_token_t *s = &sects[i];

    const char ty = s->type[0];

    if (ty == PCFG_ST_ALPHA)
    {
      char low[PCFG_MAXLINE];
      char mask[PCFG_MAXLINE];

      int li, masklen;

#if HP_FUSE_ALPHA
      li = hp_lower_and_mask (s->value, s->vlen, low, mask, &masklen);
#else
      li = 0;

      for (int si = 0; (si < s->vlen) && (li < PCFG_MAXLINE - 4);)
      {
        uint32_t cp;

        const int adv = utf8_decode (s->value + si, s->vlen - si, &cp);

        if (adv == 0) break;

        li += utf8_encode (low + li, utf8_to_lower (cp));
        si += adv;
      }

      build_case_mask (s->value, s->vlen, mask);
      masklen = (int) strlen (mask);
#endif

      hp_store_add (st, (uint8_t) PCFG_ST_ALPHA, (uint8_t) s->cp_len, low, li, n);

      hp_store_add (st, (uint8_t) PCFG_ST_CASE, (uint8_t) s->cp_len, mask, masklen, n);
    }
    else if (ty != PCFG_ST_EMAIL && ty != PCFG_ST_WEBSITE && ty != PCFG_ST_UNTYPED)
    {
      hp_store_add (st, (uint8_t) ty, (uint8_t) s->cp_len, s->value, s->vlen, n);
    }
    else if ((hp_sensitive == true) && (ty == PCFG_ST_EMAIL))
    {
      /* The address as the readers keep it, lowered: it is the same address in
       * either case, and counting both halves the count. */
      char low[PCFG_MAXLINE];

      int li = 0, si = 0;

      while ((si < s->vlen) && (li < PCFG_MAXLINE - 4))
      {
        uint32_t cp;

        const int adv = utf8_decode (s->value + si, s->vlen - si, &cp);

        if (adv == 0) break;

        li += utf8_encode (low + li, utf8_to_lower (cp));
        si += adv;
      }

      hp_store_add (st, (uint8_t) HP_TY_FULLMAIL, 0, low, li, n);
    }
    else if ((hp_sensitive == true) && (ty == PCFG_ST_WEBSITE))
    {
      /* The URL as written, not lowered: a path is case sensitive, a host not. */
      hp_store_add (st, (uint8_t) HP_TY_FULLURL, 0, s->value, s->vlen, n);
    }

    /* What each section was, the list Prince guessing walks: E and W included. */
    if (ty != PCFG_ST_UNTYPED)
      hp_store_add (base, (uint8_t) HP_TY_PRINCE, 0, s->type, (int) strlen (s->type), n);
  }

  /* Terminals of their own: nothing generates them, but the readers expect them. */
  if (seen.provlen > 0)
    if (hp_compat == true) hp_store_add (st, (uint8_t) PCFG_ST_EMAIL, 0, seen.provider, seen.provlen, n);

  if (seen.hostlen > 0)
    if (hp_compat == true) hp_store_add (st, (uint8_t) PCFG_ST_WEBSITE, 0, seen.host, seen.hostlen, n);

  if (seen.pfxlen > 0)
    if (hp_compat == true) hp_store_add (st, (uint8_t) HP_TY_WEBPFX, 0, seen.prefix, seen.pfxlen, n);

  char base_str[PCFG_MAXLINE];

  if (hp_no_structs == false)
  {
    build_base_structure (sects, nsects, base_str, PCFG_MAXLINE);

    if (base_str[0] != '\0')
      hp_store_add (base, (uint8_t) 'G', 0, base_str, (int) strlen (base_str), n);
  }

  build_raw_structure (sects, nsects, base_str, PCFG_MAXLINE);

  if (base_str[0] != '\0')
    if (hp_compat == true)
      hp_store_add (base, (uint8_t) HP_TY_RAW, 0, base_str, (int) strlen (base_str), n);
}

/* A worker takes a byte range and opens its own handle: no queue, no shared
 * reader. Ranges are cut by size and walked to the next newline. */
typedef struct
{
  const hp_opts_t *o;
  hp_store_t *st;
  hp_store_t *base;
  pcfg_words_t *mw;
  omen_t *om;
  off_t start, end;
  int phase; /* 0 = words and byte frequencies, 1 = count, 2 = omen levels */
  int64_t byte_freq[256];
  int64_t lvl[OMEN_LVL_CNT];
  int64_t lines, pw_cnt;
  int64_t bad;   /* lines that were not a password, counted once, in phase 1 */
  int64_t junk;  /* lines the junk filter rejected, same pass */
  int64_t empty; /* lines with nothing on them */
  int failed;    /* this worker could not read its slice at all */
  int64_t below; /* weighted lines below --min, or with no weight to read */
  int64_t pos;   /* how far it has read, for the report */
  int64_t nread; /* lines read in this phase, which is the rate worth showing */
} hp_worker_t;

#define HP_READ_BLOCK (1u << 20)

static void *hp_worker (void *arg)
{
  hp_worker_t *w = (hp_worker_t *) arg;

  FILE *f = fopen (w->o->infile, "rb");

  /* Its slice would be missing from the model with nothing saying so. */
  if (f == NULL)
  {
    w->failed = 1;

    return NULL;
  }

  char *line         = (char *) malloc (PCFG_MAXLINE + 64);
  unsigned char *tag = (unsigned char *) malloc (PCFG_MAXLINE);
  char *lower        = (char *) malloc (PCFG_MAXLINE + 1);

  if ((line == NULL) || (tag == NULL) || (lower == NULL))
  {
    free (line);
    free (tag);
    free (lower);
    fclose (f);

    w->failed = 1;

    return NULL;
  }

  char *rbuf = (char *) malloc (HP_READ_BLOCK);

  if (rbuf == NULL)
  {
    free (line);
    free (tag);
    free (lower);
    fclose (f);

    w->failed = 1;

    return NULL;
  }

  size_t rn = 0; /* bytes the block holds */
  size_t rc = 0; /* how far into it the reader has come */

  int64_t at = 0;

#define HP_TAKE_LINE(OUT_LEN, OUT_RAW)                                   \
  do                                                                     \
  {                                                                      \
    (OUT_LEN) = 0;                                                       \
    (OUT_RAW) = 0;                                                       \
    for (;;)                                                             \
    {                                                                    \
      if (rc >= rn)                                                      \
      {                                                                  \
        rc = 0;                                                          \
        rn = fread (rbuf, 1, HP_READ_BLOCK, f);                          \
        if (rn == 0) break;                                              \
      }                                                                  \
      const char *nl = (const char *) memchr (rbuf + rc, '\n', rn - rc); \
      size_t take    = (nl != NULL) ? (size_t) (nl - (rbuf + rc)) + 1    \
                                    : (rn - rc);                         \
      if (((size_t) (OUT_LEN) + take) > (size_t) PCFG_MAXLINE + 63)      \
        take = (size_t) PCFG_MAXLINE + 63 - (size_t) (OUT_LEN);          \
      memcpy (line + (OUT_LEN), rbuf + rc, take);                        \
      (OUT_LEN) += (int) take;                                           \
      (OUT_RAW) += (int) take;                                           \
      rc += take;                                                        \
      if ((OUT_LEN) >= (int) (PCFG_MAXLINE + 63)) break;                 \
      if (nl != NULL) break;                                             \
    }                                                                    \
    line[OUT_LEN] = '\0';                                                \
  } while (0)

  /* Everything but the first range starts mid-line; that line belongs to the
   * range before, which reads past its own end to finish it. */
  if (w->start > 0)
  {
    int skip_len = 0, skip_raw = 0;

    hp_fseek64 (f, (int64_t) w->start, SEEK_SET);

    at = (int64_t) w->start;

    HP_TAKE_LINE (skip_len, skip_raw);

    if (skip_raw == 0) goto done;

    at += skip_raw;
  }

  for (;;)
  {
    if (at > (int64_t) w->end) break;

    int len = 0, raw = 0;

    HP_TAKE_LINE (len, raw);

    if (raw == 0) break;

    at += raw;

    w->pos = at;

    while ((len > 0) && ((line[len - 1] == '\n') || (line[len - 1] == '\r'))) len--;

    line[len] = '\0';

    /* Counted here and not at the bottom: a line a filter throws away is still a
     * line read, and a total leaving it out cannot be reconciled with `wc -l`. */
    if (w->phase == 1) w->lines++;

    if (len <= 0)
    {
      if (w->phase == 1) w->empty++;

      continue;
    }

    char *pw  = line;
    int64_t n = 1;

    if (w->o->weighted == true)
    {
      int i = 0;

      while ((i < len) && (pw[i] >= '0') && (pw[i] <= '9')) i++;

      if ((i == 0) || (i >= len) || (strchr (w->o->sep, pw[i]) == NULL))
      {
        if (w->phase == 1) w->below++;

        continue;
      }

      n = strtoll (pw, NULL, 10);
      pw += i + 1;
      len -= i + 1;

      if (n <= 0) n = 1;

      /* Below the threshold the line is not read at all, a different lever from
       * -f and -S, which drop a terminal after the password was counted. */
      if (n < w->o->mincount)
      {
        if (w->phase == 1) w->below++;

        continue;
      }
    }

    /* $HEX[...] is an encoding: left as it is, the line trains on the literal
     * characters and contributes terminals nothing ever had. */
    char hexbuf[PCFG_MAXLINE];

    if ((len >= 7) && (pw[0] == '$') && (pw[1] == 'H'))
    {
      const int dl = hp_unhex (pw, len, hexbuf, (int) sizeof (hexbuf));

      if (dl > 0)
      {
        const int rl = hp_recover (hexbuf, dl, (int) sizeof (hexbuf));

        if (rl > 0)
        {
          pw  = hexbuf;
          len = rl;
        }
      }
    }

    /* Counted in the counting pass only, so one line is not counted three times. */
    if (hp_is_password (pw, len) == false)
    {
      if (w->phase == 1) w->bad += n;

      continue;
    }

    if ((w->o->keep_junk == false) && (hp_is_junk (pw, len) == true))
    {
      if (w->phase == 1) w->junk += n;

      continue;
    }

    if (w->phase == 0)
    {
      for (int i = 0; i < len; i++) w->byte_freq[(unsigned char) pw[i]] += n;

      if (hp_mw_off == false) pcfg_multiword_train (w->mw, pw, len, n);
    }
    else if (w->phase == 1)
    {
      hp_train_one (w->st, w->base, pw, len, n, tag, lower, &w->pw_cnt);

      if (w->om != NULL) omen_train (w->om, pw, len, n);
    }
    else
    {
      const int l = omen_level (w->om, pw, len);

      if ((l >= 0) && (l < OMEN_LVL_CNT)) w->lvl[l] += n;
    }

    w->nread++;
  }

done:
#undef HP_TAKE_LINE
  free (rbuf);
  free (line);
  free (tag);
  free (lower);

  fclose (f);

  return NULL;
}

/* Where each kind of terminal goes, and whether one file holds every length. */
static const hp_dir_t dirs[] = {
  { PCFG_ST_ALPHA,    "Alpha",          false, NULL                   },
  { PCFG_ST_CASE,     "Capitalization", false, NULL                   },
  { PCFG_ST_DIGIT,    "Digits",         false, NULL                   },
  { PCFG_ST_OTHER,    "Other",          false, NULL                   },
  { PCFG_ST_KEYBOARD, "Keyboard",       false, NULL                   },
  { PCFG_ST_CONTEXT,  "Context",        true,  NULL                   },
  { PCFG_ST_YEAR,     "Years",          true,  NULL                   },
  /* Not guessable and named by no base structure: what the training set held. */
  { PCFG_ST_EMAIL,    "Emails",         true,  "email_providers.txt"  },
  { PCFG_ST_WEBSITE,  "Websites",       true,  "website_hosts.txt"    },
  { HP_TY_WEBPFX,     "Websites",       true,  "website_prefixes.txt" },
  /* Written only when --save-sensitive asked: otherwise nothing is counted. */
  { HP_TY_FULLMAIL,   "Emails",         true,  "full_emails.txt"      },
  { HP_TY_FULLURL,    "Websites",       true,  "website_urls.txt"     },
  { 0,                NULL,             false, NULL                   }
};

/* Only grammar.txt is read by something that guesses. Prince is the merge's
 * fallback when a ruleset carries no totals, so every format gets it. */
static const hp_dir_t gdir[] = {
  { 'G',          "Grammar", true,  "grammar.txt"     },
  { HP_TY_RAW,    "Grammar", true,  "raw_grammar.txt" },
  { HP_TY_PRINCE, "Prince",  true,  "grammar.txt"     },
  { 0,            NULL,      false, NULL              }
};

static const hp_dir_t gdir_min[] = {
  { 'G',          "Grammar", true,  "grammar.txt" },
  { HP_TY_PRINCE, "Prince",  true,  "grammar.txt" },
  { 0,            NULL,      false, NULL          }
};

static bool hp_timing = false;

/* Which pass this is, in the order they run and not the order they are numbered. */
static int hp_phase_no (int p)
{
  switch (p)
  {
    case 0: return 1;
    case 1: return 2;
    case 2: return 3;
  }

  return 0;
}

static const char *hp_phase_name (int p)
{
  switch (p)
  {
    case 0: return "multiword";
    case 1: return "grammar and omen";
    case 2: return "omen levels";
  }

  return "?";
}

typedef struct
{
  const hp_worker_t *w;
  const hp_store_t *st;
  const pcfg_words_t *mw;
  const omen_t *om;
  int nw, phase, slice, nslice;
  int64_t base, span; /* bytes done by earlier slices, and the whole file */
  size_t budget;
  volatile int stop;
} hp_report_t;

static void hp_fmt_time (double sec, char *out, size_t n)
{
  const long t = (long) ((sec < 0.0) ? 0.0 : sec);

  if (t >= 3600)
    snprintf (out, n, "%ldh %02ldm", t / 3600, (t % 3600) / 60);
  else if (t >= 60)
    snprintf (out, n, "%ldm %02lds", t / 60, t % 60);
  else
    snprintf (out, n, "%lds", t);
}

/* Everything the run is holding, not just the counting table. */
static size_t hp_live_bytes (const hp_store_t *st, const pcfg_words_t *mw, const omen_t *om)
{
  return ((st != NULL) ? hp_store_bytes (st) : 0) + pcfg_multiword_bytes (mw) + omen_bytes (om);
}

#define HP_COL 16 /* the longest phase name, "grammar and omen"; the rest lines up after it */

static double hp_report_last = 0.0;
static double hp_started     = 0.0; /* when the run began, for the elapsed column */

/* To the millisecond: a pass that takes a quarter of a second is not "0 seconds",
 * and a difference of a few hundred between two runs is the whole of what a
 * timing comparison has to go on. */
static const char *hp_secs (double sec, char *out, size_t n)
{
  if (sec < 0.0) sec = 0.0;

  const long t = (long) sec;

  if (t >= 3600)
    snprintf (out, n, "%ld hours %ld minutes %.3f seconds", t / 3600, (t % 3600) / 60,
              sec - (double) ((t / 60) * 60));
  else if (t >= 60)
    snprintf (out, n, "%ld minutes %.3f seconds", t / 60, sec - (double) ((t / 60) * 60));
  else
    snprintf (out, n, "%.3f seconds", sec);

  return out;
}

static const char *hp_clock (double sec, char *out, size_t n)
{
  const long t = (long) ((sec < 0.0) ? 0.0 : sec);

  if (t >= 3600)
    snprintf (out, n, "%ld:%02ld:%02ld", t / 3600, (t % 3600) / 60, t % 60);
  else
    snprintf (out, n, "%02ld:%02ld", t / 60, t % 60);

  return out;
}

static void *hp_reporter (void *arg)
{
  hp_report_t *r = (hp_report_t *) arg;

  const double t0    = hp_now ();
  const bool tty     = hp_stderr_is_tty ();
  const double every = (tty == true) ? 0.5 : 20.0;
  const int64_t span = (r->span > 0) ? r->span : 1;

  while (r->stop == 0)
  {
    hp_sleep_ms (100);

    const double now = hp_now ();

    /* The cadence belongs to the program, not the slice: with fifty-six slices a
     * timer restarting with each prints fifty-six lines all reading 100%. */
    if ((now - hp_report_last) < every) continue;

    hp_report_last = now;

    int64_t done = r->base;

    for (int i = 0; i < r->nw; i++) done += r->w[i].pos - r->w[i].start;

    if (done < 0) done = 0;
    if (done > span) done = span;

    const double el = now - t0;
    /* Bytes drive the percentage, the line count not being known in advance.
     * Lines drive the rate, because "190 MB/s" says how fast a disk is. */
    const double rate = (el > 0.0) ? ((double) (done - r->base) / el) : 0.0;

    char eta[32];

    hp_fmt_time ((rate > 0.0) ? (((double) (span - done)) / rate) : 0.0, eta, sizeof (eta));

    char mem[48];

    mem[0] = 0;

    if (r->st != NULL)
    {
      const double used = (double) hp_live_bytes (r->st, r->mw, r->om) / (double) (1u << 30);

      /* Gigabytes normally, megabytes when "0.0 GB" would be all anyone saw. */
      if (r->budget == 0)
        mem[0] = 0;
      else if (r->budget < (1u << 30))
        snprintf (mem, sizeof (mem), ", %.0f/%.0f MB", used * 1024.0, (double) r->budget / (double) (1u << 20));
      else
        snprintf (mem, sizeof (mem), ", %.1f/%.1f GB", used, (double) r->budget / (double) (1u << 30));
    }

    int64_t nread = 0;

    for (int i = 0; i < r->nw; i++) nread += r->w[i].nread;

    const double lps = (el > 0.0) ? ((double) nread / el) : 0.0;

    char clk[16];

    hp_clock (now - hp_started, clk, sizeof (clk));

    /* On a terminal the line is rewritten in place and padded over the one
     * before; in a log it is a line, and a line does not end in spaces. */
    fprintf (stderr, "hpcfg: %-*s (%d of 3) %3.0f%%, %.2f M lines/s%s, %s, ETA %s%s",
             HP_COL, hp_phase_name (r->phase), hp_phase_no (r->phase),
             ((double) done / (double) span) * 100.0, lps / 1000000.0, mem, clk, eta,
             (tty == true) ? "        \r" : "\n");

    fflush (stderr);
  }

  return NULL;
}

/* One phase over a slice of the file, on `nw` workers; the whole file is slice 0
 * of 1. Non-zero when a worker could not read its slice, which makes it a lie. */
static int hp_phase_slice (hp_worker_t *w, int nw, int phase, off_t size, int slice, int nslice)
{
  const double t0 = hp_now ();

  const off_t lo = (off_t) ((double) size * (double) slice / (double) nslice);
  const off_t hi = (off_t) ((double) size * (double) (slice + 1) / (double) nslice);
  const off_t sp = hi - lo;

  hp_thread_t *th[256];

  for (int i = 0; i < nw; i++)
  {
    w[i].phase = phase;
    w[i].start = lo + (off_t) ((double) sp * (double) i / (double) nw);
    w[i].end   = lo + (off_t) ((double) sp * (double) (i + 1) / (double) nw);
  }

  for (int i = 0; i < nw; i++)
  {
    w[i].pos   = w[i].start;
    w[i].nread = 0;
  }

  hp_report_t rep;

  memset (&rep, 0, sizeof (rep));

  rep.w      = w;
  rep.st     = w[0].st;
  rep.mw     = w[0].mw;
  rep.om     = w[0].om;
  rep.nw     = nw;
  rep.phase  = phase;
  rep.slice  = slice;
  rep.nslice = nslice;
  rep.base   = (int64_t) lo;
  rep.span   = (int64_t) size;
  rep.budget = w[0].o->budget;

  /* Without this only a pass long enough to print a progress line says it started. */
  if (slice == 0)
    fprintf (stderr, "hpcfg: %-*s (%d of 3) started\n", HP_COL, hp_phase_name (phase),
             hp_phase_no (phase));

  hp_thread_t *rt = hp_thread_start (hp_reporter, &rep);

  for (int i = 1; i < nw; i++) th[i] = hp_thread_start (hp_worker, &w[i]);

  hp_worker (&w[0]);

  /* A thread that could not start would leave its slice read by nobody. The
   * platform's contract is that the caller does that work itself. */
  for (int i = 1; i < nw; i++)
    if (th[i] == NULL) hp_worker (&w[i]);

  for (int i = 1; i < nw; i++) hp_thread_join (th[i]);

  rep.stop = 1;

  if (rt != NULL) hp_thread_join (rt);

  if (hp_stderr_is_tty () == true) fprintf (stderr, "%96s\r", "");

  for (int i = 0; i < nw; i++)
  {
    if (w[i].failed == 0) continue;

    fprintf (stderr, "hpcfg: a worker could not read its part of %s, so the pass is incomplete and "
                     "the ruleset would be missing whatever it holds\n",
             w[0].o->infile);

    return 1;
  }

  /* Counting prints one line for all its slices; without this the single-slice
   * case prints that same line twice. */
  if ((hp_timing == true) && (nslice == 1) && (phase != 1))
  {
    char tb[48];

    fprintf (stderr, "hpcfg: %-*s (%d of 3) finished in %s\n", HP_COL, hp_phase_name (phase),
             hp_phase_no (phase), hp_secs (hp_now () - t0, tb, sizeof (tb)));
  }

  return 0;
}

static int hp_phase (hp_worker_t *w, int nw, int phase, off_t size)
{
  return hp_phase_slice (w, nw, phase, size, 0, 1);
}

static void hp_base_merge (uint8_t type, uint8_t len, const char *val, int vlen, int64_t cnt, void *arg)
{
  hp_store_add ((hp_store_t *) arg, type, len, val, vlen, cnt);
}

static int hp_train_run (hp_opts_t *o, char *spoolpath, size_t spoolsz)
{
  hp_started = hp_now ();
  hp_timing  = o->verbose;

  hp_no_structs = (o->coverage == 0.0);
  hp_sensitive  = o->sensitive;
  hp_compat     = (o->format == HP_FMT_CRACKER);
  hp_mw_off     = o->mw_off;

  /* stdin cannot be walked three times, so it is spooled and cut from that. */
  if (strcmp (o->infile, "-") == 0)
  {
    hp_tmpname (spoolpath, spoolsz, "hpcfg.spool");

    FILE *sp = fopen (spoolpath, "wb");

    if (sp == NULL)
    {
      fprintf (stderr, "hpcfg: cannot spool stdin\n");
      return 1;
    }

    char buf[1 << 16];
    size_t got;

    while ((got = fread (buf, 1, sizeof (buf), stdin)) > 0) fwrite (buf, 1, got, sp);

    if (hp_fclose_w (sp, spoolpath) != 0) return 1;

    o->infile = spoolpath;
  }

  struct stat sb;

  if (stat (o->infile, &sb) != 0)
  {
    fprintf (stderr, "hpcfg: cannot read \"%s\"\n", o->infile);
    return 1;
  }

  const off_t fsize = sb.st_size;

  int nw = (o->threads > 0) ? o->threads : hp_cpu_count ();

  if (nw < 1) nw = 1;
  if (nw > 256) nw = 256;

  /* Ranges have to be wider than a line. */
  const int64_t min_span = 64 * 1024;

  while ((nw > 1) && ((int64_t) fsize / nw) < min_span) nw--;

  /* A shard reserves a whole block before it holds one entry, so the block falls
   * as the shards rise. */
  if (o->budget == 0) o->budget = hp_default_budget ();

  const int nshard = nw * 8;

  size_t block = (64u << 20) / (size_t) nshard;

  /* The cap wins over the floor, which is the opposite of what this did. */
  if (o->budget != 0)
  {
    const size_t cap = o->budget / (size_t) (nshard * 4);

    if (cap < block) block = cap;
  }

  if (block < (64u << 10)) block = 64u << 10;

  /* One ceiling for everything that grows with the corpus: terminals, base
   * structures, word set, OMEN contexts. Not the terminals alone. */
  static hp_mem_t mem, mem_unspill;

  hp_mem_init (&mem, (o->budget_set == true) ? o->budget : 0);

  /* The two tables that cannot spill share three quarters of the ceiling and
   * compete for it: which is larger depends on the corpus. */
  hp_mem_share (&mem_unspill, &mem, (o->budget_set == true) ? ((o->budget / 4) * 3) : 0);

  hp_store_t *st = hp_store_new (nshard, block);

  hp_store_account (st, &mem);
  hp_store_t **wbase = (hp_store_t **) calloc ((size_t) nw, sizeof (hp_store_t *));

  if (wbase == NULL) return 1;

  for (int i = 0; i < nw; i++)
  {
    wbase[i] = hp_store_new (16, 256u << 10);

    /* One per worker, each holding every base structure the corpus shows: they
     * grow with it like everything else, so they draw on the same ceiling. */
    hp_store_account (wbase[i], &mem);
  }

  hp_store_t *base = hp_store_new (nw * 2, 256u << 10);

  hp_store_account (base, &mem);

  if ((o->budget_set == true) || (o->seen > 1))
  {
    const size_t filt = (o->budget != 0) ? (o->budget / 16) : (64u << 20);

    hp_store_limit (st, (o->budget_set == true) ? o->budget : 0, o->seen, filt);
  }

  if (nw > 1)
  {
    hp_store_threaded (st, true);
    hp_store_threaded (base, true);
  }

  pcfg_words_t *mw = pcfg_multiword_init ((o->mw_thr > 0) ? o->mw_thr : 5,
                                          (o->mw_min > 0) ? o->mw_min : 4,
                                          (o->mw_max > 0) ? o->mw_max : 21);
  omen_t *om       = omen_new (o->ngram, o->alpha);

  omen_workers (om, nw);
  omen_ks_max (om, (o->ks_max > 0) ? o->ks_max : 0);

  omen_account (om, &mem_unspill);
  pcfg_multiword_account (mw, &mem_unspill);

  omen_compat (om, o->format == HP_FMT_CRACKER);

  hp_words = mw;

  /* A dictionary, read before the corpus and single threaded. */
  if ((o->dict != NULL) && (o->mw_off == true))
  {
    fprintf (stderr, "hpcfg: --multiword-disable and --mw-file ask for opposite things; the words are not read\n");
  }

  if ((o->dict != NULL) && (o->mw_off == false))
  {
    FILE *df = fopen (o->dict, "rb");

    if (df == NULL)
    {
      fprintf (stderr, "hpcfg: cannot read \"%s\": %s\n", o->dict, strerror (errno));

      return 1;
    }

    char *line = (char *) malloc (PCFG_MAXLINE + 64);
    char *hex  = (char *) malloc (PCFG_MAXLINE);

    if ((line == NULL) || (hex == NULL))
    {
      fclose (df);

      return 1;
    }

    int64_t words = 0;

    pcfg_multiword_pretrain (mw, true);

    while (fgets (line, PCFG_MAXLINE + 64, df) != NULL)
    {
      int len = (int) strlen (line);

      while ((len > 0) && ((line[len - 1] == '\n') || (line[len - 1] == '\r'))) len--;

      line[len] = '\0';

      if (len <= 0) continue;

      char *pw = line;

      /* A dictionary comes from where a wordlist does, $HEX[] lines included. */
      if ((len >= 7) && (pw[0] == '$') && (pw[1] == 'H'))
      {
        const int dl = hp_unhex (pw, len, hex, PCFG_MAXLINE);

        if (dl > 0)
        {
          const int rl = hp_recover (hex, dl, PCFG_MAXLINE);

          if (rl > 0)
          {
            pw  = hex;
            len = rl;
          }
        }
      }

      if (hp_is_password (pw, len) == false) continue;

      pcfg_multiword_train (mw, pw, len, 1);

      words++;
    }

    pcfg_multiword_pretrain (mw, false);

    free (hex);
    free (line);
    fclose (df);

    fprintf (stderr, "hpcfg: %" PRId64 " lines of %s read as known words\n", words, o->dict);
  }

  if (nw > 1) pcfg_multiword_threaded (mw, true);

  hp_worker_t *w = (hp_worker_t *) calloc ((size_t) nw, sizeof (hp_worker_t));

  for (int i = 0; i < nw; i++)
  {
    w[i].o    = o;
    w[i].st   = st;
    w[i].base = wbase[i];
    w[i].mw   = mw;
    w[i].om   = om; /* NULL below if no alphabet could be built */
  }

  /* Three walks, each earning its place: the word set must be whole before a
   * password is parsed against it, the alphabet must exist before an n-gram is
   * counted, and a level can only be read once the model is smoothed. */

  if (hp_phase (w, nw, 0, fsize) != 0) return 1;

  pcfg_multiword_set_readonly (mw);

  /* The one moment the floor is known. */
  {
    const size_t words = pcfg_multiword_bytes (mw);
    const size_t avail = hp_available_ram ();

    char b1[32], b2[32];

    if ((o->budget_set == true) && (words > ((o->budget / 4) * 3) / 2))
    {
      fprintf (stderr, "hpcfg: the word set alone is %s MB of the %s MB ceiling, and it cannot be spilled; "
                       "what the OMEN contexts and the counters do not get, they lose\n",
               hp_group ((int64_t) (words >> 20), b1, sizeof (b1)),
               hp_group ((int64_t) (o->budget >> 20), b2, sizeof (b2)));
    }
    else if ((o->budget_set == false) && (avail != 0) && (words > (avail / 2)))
    {
      fprintf (stderr, "hpcfg: the word set is %s MB against %s MB free, and it stays in memory for the whole "
                       "run; this corpus may be larger than this machine\n",
               hp_group ((int64_t) (words >> 20), b1, sizeof (b1)),
               hp_group ((int64_t) (avail >> 20), b2, sizeof (b2)));
    }
  }

  /* The word set is complete here and never changes again, the only moment it is
   * worth writing: the chunks of a split run have to share it to merge. */
  if (o->dict_out != NULL)
  {
    if (pcfg_multiword_save (mw, o->dict_out, 0) != 0) return 1;
  }

  int64_t byte_freq[256];

  memset (byte_freq, 0, sizeof (byte_freq));

  for (int i = 0; i < nw; i++)
    for (int b = 0; b < 256; b++) byte_freq[b] += w[i].byte_freq[b];

  /* The alphabet is the commonest bytes of what was read, so two chunks get
   * different ones and a password is skipped in one and counted in the other.
   * One file of 256 frequencies over the whole corpus is what lets them merge. */
  if (o->freq_out != NULL)
  {
    FILE *bf = fopen (o->freq_out, "wb");

    if (bf == NULL)
    {
      fprintf (stderr, "hpcfg: cannot create \"%s\": %s\n", o->freq_out, strerror (errno));

      return 1;
    }

    for (int b = 0; b < 256; b++) fprintf (bf, "%d\t%" PRId64 "\n", b, byte_freq[b]);

    if (hp_fclose_w (bf, o->freq_out) != 0) return 1;

    fprintf (stderr, "hpcfg: byte frequencies written to %s\n", o->freq_out);
  }

  /* Asked for the shared state and nothing else: the corpus has been read. */
  if (o->outdir == NULL) return 0;

  bool omen_shared    = false;
  bool omen_ok_shared = false;

  if (o->freq_in != NULL)
  {
    FILE *bf = fopen (o->freq_in, "rb");

    if (bf == NULL)
    {
      fprintf (stderr, "hpcfg: cannot read \"%s\": %s\n", o->freq_in, strerror (errno));

      return 1;
    }

    char line[128];

    int64_t given[256];

    memset (given, 0, sizeof (given));

    int seen = 0;

    while (fgets (line, sizeof (line), bf) != NULL)
    {
      char *t = strchr (line, '\t');

      if (t == NULL) continue;

      *t = '\0';

      const int b = atoi (line);

      if ((b < 0) || (b > 255)) continue;

      given[b] = strtoll (t + 1, NULL, 10);

      seen++;
    }

    if (hp_fclose_w (bf, o->freq_out) != 0) return 1;

    if (seen == 0)
    {
      fprintf (stderr, "hpcfg: \"%s\" holds no byte frequencies\n", o->freq_in);

      return 1;
    }

    /* The alphabet comes from the shared frequencies; the counts are this chunk's. */
    const bool ok = (omen_build_alphabet (om, given) == 0);

    omen_note_freq (om, byte_freq);

    omen_shared    = true;
    omen_ok_shared = ok;
  }

  const bool omen_ok = (omen_shared == true) ? omen_ok_shared
                                             : (omen_build_alphabet (om, byte_freq) == 0);

  /* A model with no alphabet counts nothing, and the counting pass should not
   * have to ask about it once per password. */
  if (omen_ok == false)
    for (int i = 0; i < nw; i++) w[i].om = NULL;

  /* Counting, in as many slices as the budget turns out to need. */
  int nslice = (o->budget != 0) ? 64 : 1;

  while ((nslice > 1) && (((int64_t) fsize / nslice) < (min_span * (int64_t) nw))) nslice--;

  char **parts = NULL;
  /* Working files, in a directory of their own that goes when they are summed. */
  char scratch[PCFG_MAXPATH];

  snprintf (scratch, sizeof (scratch), "%s.parts.%d", o->outdir, hp_pid ());

  int nparts = 0;

  /* OMEN counts on every worker of that pass: a context's slot is claimed with a
   * compare-and-swap and the counts added atomically, so no lock and no copy. */
  if ((omen_ok == true) && (nw > 1)) omen_threaded (om, true);

  const double tcount = hp_now ();

  for (int sl = 0; sl < nslice; sl++)
  {
    if (hp_phase_slice (w, nw, 1, fsize, sl, nslice) != 0) return 1;

    const bool last = (sl == (nslice - 1));

    if ((o->budget == 0) || (last == true)) continue;

    /* Spill at four fifths, so what the next slice adds still fits. The write
     * makes one entry per terminal, so that room is known and counted here. */
    const size_t live = hp_live_bytes (st, mw, om) + ((size_t) hp_store_count (st) * 24);

    if (live < ((o->budget / 5) * 4)) continue;

    char dir[PCFG_MAXPATH];

    if (nparts == 0) hp_mkdir (scratch);

    snprintf (dir, sizeof (dir), "%s/%d", scratch, nparts);

    if (hp_write_counts (st, dir, dirs) != 0)
    {
      hp_rmtree (scratch);

      return 1;
    }

    parts           = (char **) realloc (parts, (size_t) (nparts + 1) * sizeof (char *));
    parts[nparts++] = strdup (dir);

    char nb[32];

    fprintf (stderr, "hpcfg: spill %d, %s terminals written to disk\n",
             nparts, hp_group (hp_store_entries (st), nb, sizeof (nb)));

    hp_store_free (st);

    /* The table is gone and the ceiling knows it; the allocator is asked to
     * agree, or the resident size keeps every spill's pages. */
    hp_mem_release ();

    st = hp_store_new (nshard, block);

    hp_store_account (st, &mem);

    hp_store_limit (st, (o->budget_set == true) ? o->budget : 0, o->seen,
                    (o->budget != 0) ? (o->budget / 16) : (64u << 20));

    if (nw > 1) hp_store_threaded (st, true);

    for (int i = 0; i < nw; i++) w[i].st = st;
  }

  for (int i = 0; i < nw; i++)
  {
    hp_store_foreach_all (wbase[i], hp_base_merge, base);
    hp_store_free (wbase[i]);
  }

  free (wbase);

  if (hp_timing == true)
  {
    char tb[48];

    fprintf (stderr, "hpcfg: %-*s (%d of 3) finished in %s%s\n", HP_COL, hp_phase_name (1),
             hp_phase_no (1), hp_secs (hp_now () - tcount, tb, sizeof (tb)),
             (nparts > 0) ? ", spilled" : "");
  }

  if (omen_ok == true) omen_threaded (om, false);

  int64_t lines = 0, pw_cnt = 0, dropped = 0, junk = 0, below = 0, empty = 0;

  for (int i = 0; i < nw; i++)
  {
    lines += w[i].lines;
    pw_cnt += w[i].pw_cnt;
    dropped += w[i].bad;
    junk += w[i].junk;
    below += w[i].below;
    empty += w[i].empty;
  }

  int64_t lvl_counts[OMEN_LVL_CNT];

  memset (lvl_counts, 0, sizeof (lvl_counts));

  if (omen_ok == true)
  {
    omen_smooth (om);

    if (hp_phase (w, nw, 2, fsize) != 0) return 1;

    for (int i = 0; i < nw; i++)
      for (int l = 0; l < OMEN_LVL_CNT; l++) lvl_counts[l] += w[i].lvl[l];
  }

  free (w);

  char n1[32], n2[32], n3[32], n4[32];

  /* The numbers carry commas of their own, so a comma between fields would not read. */
  if ((dropped + junk + below + empty) > 0)
  {
    char d1[32], d2[32], d3[32];

    fprintf (stderr, "hpcfg: %s lines not counted:", hp_group (dropped + junk + below + empty, d1, sizeof (d1)));

    if (empty > 0) fprintf (stderr, " %s empty", hp_group (empty, d2, sizeof (d2)));
    if (dropped > 0) fprintf (stderr, "%s %s not passwords", (empty > 0) ? "," : "", hp_group (dropped, d2, sizeof (d2)));
    if (junk > 0) fprintf (stderr, "%s %s taken for hashes, keys or tokens (--df-disable keeps them)",
                           ((empty > 0) || (dropped > 0)) ? "," : "", hp_group (junk, d3, sizeof (d3)));
    if (below > 0) fprintf (stderr, "%s %s below the weight asked for",
                            ((empty > 0) || (dropped > 0) || (junk > 0)) ? "," : "", hp_group (below, d2, sizeof (d2)));

    fprintf (stderr, "\n");
  }

  /* What the ceiling cost, beside what was counted. Dropping half the terminals
   * and reporting the rest as the model is what this prevents. */
  {
    const int64_t lost_t = hp_store_refused (st);
    const int64_t lost_c = omen_refused (om);

    if ((lost_t > 0) || (lost_c > 0))
    {
      char l1[32], l2[32];

      fprintf (stderr, "hpcfg: the memory ceiling refused ");

      if (lost_t > 0) fprintf (stderr, "%s occurrences of terminals", hp_group (lost_t, l1, sizeof (l1)));
      if ((lost_t > 0) && (lost_c > 0)) fprintf (stderr, " and ");
      if (lost_c > 0) fprintf (stderr, "%s OMEN contexts", hp_group (lost_c, l2, sizeof (l2)));

      fprintf (stderr, "; what was counted is less than the corpus holds. Raise --memory-max for all of it\n");
    }
  }

  fprintf (stderr, "hpcfg: %s lines, %s passwords, %s terminals, %s OMEN contexts%s\n",
           hp_group (lines, n1, sizeof (n1)),
           hp_group (pw_cnt, n2, sizeof (n2)),
           hp_group (hp_store_entries (st), n3, sizeof (n3)),
           hp_group (omen_contexts (om), n4, sizeof (n4)),
           hp_store_is_full (st) ? " (memory limit reached)" : "");

  /* A grammar of nothing but an escape that does not exist generates nothing. */
  if ((o->coverage == 0.0) && (pw_cnt > 0) && ((omen_ok == false) || (omen_contexts (om) == 0)))
  {
    fprintf (stderr, "hpcfg: coverage 0 asks for a grammar of nothing but the OMEN escape, and the "
                     "escape is empty; nothing would be generated from this ruleset. "
                     "Nothing written\n");

    hp_rmtree (scratch);

    return 1;
  }

  char path[PCFG_MAXPATH];

  if (hp_mkdir (o->outdir) != 0) return 1;

  const double tw = hp_now ();

  if (nparts == 0)
  {
    if (hp_write_ruleset (st, o->outdir, dirs, o->admit, nw) != 0)
    {
      hp_rmtree (scratch);

      return 1;
    }
  }
  else
  {
    char dir[PCFG_MAXPATH];

    if (nparts == 0) hp_mkdir (scratch);

    snprintf (dir, sizeof (dir), "%s/%d", scratch, nparts);

    if (hp_write_counts (st, dir, dirs) != 0)
    {
      hp_rmtree (scratch);

      return 1;
    }

    parts           = (char **) realloc (parts, (size_t) (nparts + 1) * sizeof (char *));
    parts[nparts++] = strdup (dir);

    fprintf (stderr, "hpcfg: merging %d spills\n", nparts);

    if (hp_merge_counts (parts, nparts, o->outdir, dirs, o->admit) != 0)
    {
      hp_rmtree (scratch);

      return 1;
    }

    for (int i = 0; i < nparts; i++)
    {
      free (parts[i]);
    }

    free (parts);

    hp_rmtree (scratch);
  }

  /* The M entry sends the reader to OMEN and takes what coverage leaves the
   * grammar. Without it the escape is never reached. */
  if ((o->coverage < 1.0) && (pw_cnt > 0))
  {
    if (omen_ok == false)
    {
      /* No structures and no escape generates nothing: there is nothing to write. */
      fprintf (stderr, "hpcfg: no OMEN escape was trained, so the ruleset is "
                       "the grammar alone, as coverage 1 asks for\n");
    }
    else if (o->coverage == 0.0)
    {
      hp_store_add (base, (uint8_t) 'G', 0, "M", 1, 1);
    }
    else
    {
      const int64_t markov = (int64_t) (((double) pw_cnt / o->coverage) - (double) pw_cnt);

      if (markov > 0) hp_store_add (base, (uint8_t) 'G', 0, "M", 1, markov);
    }
  }

  if (hp_write_ruleset (base, o->outdir, (hp_compat == true) ? gdir : gdir_min, 0, nw) != 0) return 1;

  if (omen_ok == true)
  {
    const double to = hp_now ();

    /* An empty escape generates less than the ruleset looks like it will, and
     * nothing at all at a coverage of zero. The corpus decides which. */
    if (omen_contexts (om) == 0)
    {
      fprintf (stderr, "hpcfg: no OMEN context was counted; the escape will be empty%s. Every "
                       "password was either shorter than the %d of --omen-ngram or outside the alphabet\n",
               (o->coverage == 0.0) ? ", and with a coverage of zero this ruleset generates nothing" : "",
               o->ngram);
    }

    snprintf (path, sizeof (path), "%s/Omen", o->outdir);

    if (hp_mkdir (path) != 0) return 1;

    if (omen_save (om, path, lvl_counts, OMEN_LVL_CNT, pw_cnt) != 0) return 1;
    if (omen_write_counts (om, path) != 0) return 1;

    /* On a large model the keyspace walk is the one part that is not linear. */
    if (hp_timing == true)
    {
      char tb[48];

      fprintf (stderr, "hpcfg: omen written in %s\n", hp_secs (hp_now () - to, tb, sizeof (tb)));
    }
  }

  if (hp_timing == true)
  {
    char tb[48];

    fprintf (stderr, "hpcfg: ruleset written in %s\n", hp_secs (hp_now () - tw, tb, sizeof (tb)));
  }

  /* Last, because it describes the directory: after a spill, what it names is
   * only settled here. */
  if (hp_write_totals (o->outdir) != 0) return 1;

  /* Four lists pcfg_cracker opens whether or not they hold anything. */
  if (hp_compat == true)
  {
    static const char *needed[] = { "Years/1.txt", "Context/1.txt",
                                    "Emails/email_providers.txt",
                                    "Websites/website_hosts.txt", NULL };

    for (int i = 0; needed[i] != NULL; i++)
    {
      char dir[PCFG_MAXPATH];

      snprintf (path, sizeof (path), "%s/%s", o->outdir, needed[i]);
      snprintf (dir, sizeof (dir), "%s/%s", o->outdir, needed[i]);

      char *slash = strrchr (dir, '/');

      if (slash != NULL) *slash = 0;

      hp_mkdir (dir);

      FILE *tf = fopen (path, "ab");

      if (tf != NULL) hp_fclose_w (tf, path);
    }
  }

  /* The readers' index of the directory, and where a merge finds what the ruleset
   * was trained on. hashcat never opens it, but every format writes it. */
  if (hp_write_config (o->outdir, o->infile, HP_VERSION, hp_compat, pw_cnt, dropped,
                       o->comments, o->encoding) != 0) return 1;

  omen_free (om);
  pcfg_multiword_destroy (mw);
  hp_store_free (st);
  hp_store_free (base);

  return 0;
}

/* The spool is a whole copy of what came in on stdin, and the run has thirty-odd
 * ways out. Owning it here rather than inside means every one of them drops it,
 * instead of leaving the corpus in the temporary directory for good. */
int pcfg_train (hp_opts_t *o)
{
  char spoolpath[PCFG_MAXPATH] = { 0 };

  const int rc = hp_train_run (o, spoolpath, sizeof (spoolpath));

  if (spoolpath[0] != 0) remove (spoolpath);

  return rc;
}

/* Rulesets in, a ruleset out, and no corpus unless the caller hands one over for
 * the level distribution, which the rulesets cannot carry between them. */
int pcfg_merge (char **in, int nin, const char *wspec, hp_opts_t *o)
{
  const int nmerge = nin;

  char **merge = in;

  hp_sensitive = o->sensitive;

  if (o->outdir == NULL)
  {
    fprintf (stderr, "hpcfg: --rulesets-merge needs --ruleset-save to say where the merged ruleset goes\n");

    return 1;
  }

  if (nmerge < 2)
  {
    fprintf (stderr, "hpcfg: --rulesets-merge takes two rulesets or more\n");

    return 1;
  }

  double w[64];

  if (wspec != NULL)
  {
    const char *at = wspec;

    int n = 0;

    double sum = 0.0;

    for (;;)
    {
      char *end = NULL;

      const double v = strtod (at, &end);

      if ((end == at) || (v <= 0.0))
      {
        fprintf (stderr, "hpcfg: --rulesets-merge-weights takes colon separated numbers above zero, one per "
                         "--merge, as in 2:1\n");

        return 1;
      }

      if (n < 64) w[n] = v;

      n++;
      sum += v;

      if (*end == 0) break;

      if (*end != ':')
      {
        fprintf (stderr, "hpcfg: --rulesets-merge-weights takes colon separated numbers, as in 2:1\n");

        return 1;
      }

      at = end + 1;
    }

    if (n != nmerge)
    {
      fprintf (stderr, "hpcfg: %d weights for %d rulesets\n", n, nmerge);

      return 1;
    }

    for (int i = 0; i < n; i++) w[i] /= sum;
  }

  /* -f counts occurrences, and shares given by hand have none behind them:
   * filtering against a number meaning something else prunes by the wrong amount. */
  if ((o->admit > 0) && (wspec != NULL))
  {
    fprintf (stderr, "hpcfg: --terminal-count-min counts occurrences, and --rulesets-merge-weights replaces the sizes it would "
                     "count them against; use one or the other\n");

    return 1;
  }

  /* Optional, and only the level distribution uses it - but say what it costs. */
  if ((o->infile == NULL) || (o->infile[0] == 0))
  {
    fprintf (stderr, "hpcfg: no corpus given, so the OMEN level distribution is the sum of the "
                     "rulesets' own, which is close and not exact; pass --train <corpus> to count it\n");
  }

  hp_merge_src_t src;

  src.corpus    = o->infile;
  src.weighted  = o->weighted;
  src.sep       = o->sep;
  src.keep_junk = o->keep_junk;
  src.mincount  = o->mincount;
  src.compat    = (o->format == HP_FMT_CRACKER);

  return hp_merge_rulesets (merge, (wspec != NULL) ? w : NULL, nmerge, o->outdir,
                            dirs, gdir, o->admit, &src);
}
