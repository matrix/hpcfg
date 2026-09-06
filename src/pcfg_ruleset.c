/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * Writing a ruleset hashcat reads.
 */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "pcfg_common.h"
#include "pcfg_trainer_utils.h"
#include "pcfg_trainer_omen.h"
#include "pcfg_platform.h"
#include "pcfg_ruleset.h"

typedef struct
{
  const char *val; /* into the store's arena, which outlives the write */
  int vlen;
  int64_t cnt;
} hp_entry_t;

typedef struct
{
  hp_entry_t *v;
  int n, cap;
  int64_t total;
} hp_list_t;

typedef struct
{
  hp_list_t (*list)[256]; /* [type][len] */
  int64_t admit;
} hp_bin_t;

static bool g_utf8 = true;

/* What each list was written out of. */
static int64_t g_total[256][256];

static void hp_note_total (uint8_t ty, uint8_t len, int64_t total)
{
  if (total > 0) g_total[ty][len] += total;
}

int hp_write_totals (const char *outdir)
{
  char path[PCFG_MAXPATH];

  snprintf (path, sizeof (path), "%s/totals.txt", outdir);

  FILE *f = fopen (path, "wb");

  if (f == NULL)
  {
    fprintf (stderr, "hpcfg: cannot create \"%s\": %s\n", path, strerror (errno));

    return 1;
  }

  for (int t = 0; t < 256; t++)
  {
    for (int l = 0; l < 256; l++)
    {
      if (g_total[t][l] == 0) continue;

      fprintf (f, "%c%d\t%" PRId64 "\n", (char) t, l, g_total[t][l]);
    }
  }

  if (hp_fclose_w (f, path) != 0) return 1;

  return 0;
}

int64_t hp_read_total (const char *dir, uint8_t ty, uint8_t len)
{
  char path[PCFG_MAXPATH];

  snprintf (path, sizeof (path), "%s/totals.txt", dir);

  FILE *f = fopen (path, "rb");

  if (f == NULL) return 0;

  char line[256];
  int64_t out = 0;

  while (fgets (line, sizeof (line), f) != NULL)
  {
    char *t = strchr (line, '\t');

    if (t == NULL) continue;

    *t = '\0';

    if ((unsigned char) line[0] != ty) continue;

    if (atoi (line + 1) != (int) len) continue;

    out = strtoll (t + 1, NULL, 10);

    break;
  }

  fclose (f);

  return out;
}

static bool hp_is_utf8 (const char *s, int n)
{
  for (int i = 0; i < n;)
  {
    const unsigned char c = (unsigned char) s[i];

    int need;
    uint32_t cp;

    if (c < 0x80)
    {
      i++;
      continue;
    }
    else if ((c & 0xe0) == 0xc0)
    {
      need = 1;
      cp   = c & 0x1fu;
    }
    else if ((c & 0xf0) == 0xe0)
    {
      need = 2;
      cp   = c & 0x0fu;
    }
    else if ((c & 0xf8) == 0xf0)
    {
      need = 3;
      cp   = c & 0x07u;
    }
    else
      return false;

    if ((i + need) >= n) return false;

    for (int j = 1; j <= need; j++)
    {
      const unsigned char t = (unsigned char) s[i + j];

      if ((t & 0xc0) != 0x80) return false;

      cp = (cp << 6) | (t & 0x3fu);
    }

    /* Overlong, out of range, or a surrogate: a strict decoder refuses all. */
    if (need == 1 && cp < 0x80) return false;
    if (need == 2 && cp < 0x800) return false;
    if (need == 3 && cp < 0x10000) return false;
    if (cp > 0x10ffff) return false;
    if ((cp >= 0xd800) && (cp <= 0xdfff)) return false;

    i += need + 1;
  }

  return true;
}

/* utf-8 or latin-1, whichever describes everything written so far. */
const char *hp_encoding_name (void)
{
  return (g_utf8 == true) ? "utf-8" : "latin-1";
}

static void hp_bin (uint8_t type, uint8_t len, const char *val, int vlen, int64_t cnt, void *arg)
{
  hp_bin_t *b = (hp_bin_t *) arg;

  if (cnt < b->admit) return;

  if ((g_utf8 == true) && (hp_is_utf8 (val, vlen) == false)) g_utf8 = false;

  /* A value the reader breaks a line on is not written, and leaves the total. */
  for (int i = 0; i < vlen; i++)
  {
    const unsigned char c = (unsigned char) val[i];

    if ((c == '\n') || (c == '\r') || (c == 0x0b) || (c == 0x0c) || (c == 0x85)) return;
    if ((c >= 0x1c) && (c <= 0x1e)) return;

    if ((c == 0xc2) && ((i + 1) < vlen) && ((unsigned char) val[i + 1] == 0x85)) return;

    if ((c == 0xe2) && ((i + 2) < vlen) && ((unsigned char) val[i + 1] == 0x80) && (((unsigned char) val[i + 2] == 0xa8) || ((unsigned char) val[i + 2] == 0xa9))) return;
  }

  hp_list_t *l = &b->list[type][len];

  if (l->n == l->cap)
  {
    const int cap = (l->cap == 0) ? 64 : (l->cap * 2);

    hp_entry_t *nv = (hp_entry_t *) realloc (l->v, (size_t) cap * sizeof (hp_entry_t));

    if (nv == NULL) return;

    l->v   = nv;
    l->cap = cap;
  }

  l->v[l->n].val  = val;
  l->v[l->n].vlen = vlen;
  l->v[l->n].cnt  = cnt;
  l->n++;

  l->total += cnt;
}

static int hp_cmp_desc (const void *a, const void *b)
{
  const hp_entry_t *x = (const hp_entry_t *) a;
  const hp_entry_t *y = (const hp_entry_t *) b;

  if (x->cnt != y->cnt) return (y->cnt > x->cnt) ? 1 : -1;

  const int n = (x->vlen < y->vlen) ? x->vlen : y->vlen;
  const int c = memcmp (x->val, y->val, (size_t) n);

  if (c != 0) return c;

  return (x->vlen > y->vlen) - (x->vlen < y->vlen);
}

int hp_write_one (const char *path, hp_list_t *l)
{
  if ((l->n == 0) || (l->total <= 0)) return 0;

  qsort (l->v, (size_t) l->n, sizeof (hp_entry_t), hp_cmp_desc);

  FILE *f = fopen (path, "wb");

  if (f == NULL)
  {
    fprintf (stderr, "hpcfg: cannot create \"%s\": %s\n", path, strerror (errno));
    return 1;
  }

  /* A value may be as long as a line, plus its probability with room to spare. */
  const size_t bufsz = PCFG_MAXLINE + 4096;

  char *buf = (char *) malloc (bufsz);

  if (buf == NULL)
  {
    if (hp_fclose_w (f, path) != 0) return 1;
    return 1;
  }

  size_t at = 0;

  for (int i = 0; i < l->n; i++)
  {
    const size_t need = (size_t) l->v[i].vlen + 48;

    if ((at + need) > bufsz)
    {
      fwrite (buf, 1, at, f);
      at = 0;
    }

    memcpy (buf + at, l->v[i].val, (size_t) l->v[i].vlen);

    at += (size_t) l->v[i].vlen;

    /* The size given has to be what is left of the buffer, not what this entry
     * might want: the compiler checks that claim and aborts rather than trust it. */
    at += (size_t) snprintf (buf + at, bufsz - at, "\t%.17g\n",
                             (double) l->v[i].cnt / (double) l->total);
  }

  if (at > 0) fwrite (buf, 1, at, f);

  free (buf);
  if (hp_fclose_w (f, path) != 0) return 1;

  return 0;
}

/* One list to write: they are handed out to workers and written in parallel. */
typedef struct
{
  char path[PCFG_MAXPATH];
  hp_list_t *list;
} hp_job_t;

typedef struct
{
  hp_job_t *job;
  int n;
  int next;
  int rc;
  hp_mutex_t *mux;
  int64_t done, total; /* entries written, and entries to write */
  volatile int stop;
} hp_jobs_t;

static void *hp_write_reporter (void *arg)
{
  hp_jobs_t *js = (hp_jobs_t *) arg;

  const bool tty     = hp_stderr_is_tty ();
  const double every = (tty == true) ? 0.5 : 20.0;
  const double t0    = hp_now ();

  double last = t0;

  while (js->stop == 0)
  {
    hp_sleep_ms (100);

    const double now = hp_now ();

    if ((now - last) < every) continue;

    last = now;

    hp_mutex_lock (js->mux);
    const int64_t d = js->done;
    hp_mutex_unlock (js->mux);

    const double pct = (js->total > 0) ? (100.0 * (double) d / (double) js->total) : 0.0;

    fprintf (stderr, "hpcfg: %-11s %5.1f%%  %" PRId64 "/%" PRId64 " entries%s",
             "writing", pct, d, js->total, (tty == true) ? "        \r" : "\n");

    fflush (stderr);
  }

  return NULL;
}

static void *hp_write_worker (void *arg)
{
  hp_jobs_t *js = (hp_jobs_t *) arg;

  for (;;)
  {
    hp_mutex_lock (js->mux);

    const int i = js->next++;

    hp_mutex_unlock (js->mux);

    if (i >= js->n) break;

    const int64_t did = (int64_t) js->job[i].list->n;

    if (hp_write_one (js->job[i].path, js->job[i].list) != 0)
    {
      hp_mutex_lock (js->mux);
      js->rc = 1;
      hp_mutex_unlock (js->mux);
    }

    hp_mutex_lock (js->mux);
    js->done += did;
    hp_mutex_unlock (js->mux);
  }

  return NULL;
}

/* A partial: the same layout, but "value<TAB>count" with the count an integer. */
static int hp_write_counts_one (const char *path, hp_list_t *l)
{
  if (l->n == 0) return 0;

  FILE *f = fopen (path, "wb");

  if (f == NULL)
  {
    fprintf (stderr, "hpcfg: cannot create \"%s\": %s\n", path, strerror (errno));
    return 1;
  }

  const size_t bufsz = PCFG_MAXLINE + 4096;

  char *buf = (char *) malloc (bufsz);

  if (buf == NULL)
  {
    if (hp_fclose_w (f, path) != 0) return 1;
    return 1;
  }

  size_t at = 0;

  for (int i = 0; i < l->n; i++)
  {
    if ((at + (size_t) l->v[i].vlen + 48) > bufsz)
    {
      fwrite (buf, 1, at, f);
      at = 0;
    }

    memcpy (buf + at, l->v[i].val, (size_t) l->v[i].vlen);

    at += (size_t) l->v[i].vlen;
    at += (size_t) snprintf (buf + at, bufsz - at, "\t%" PRId64 "\n", l->v[i].cnt);
  }

  if (at > 0) fwrite (buf, 1, at, f);

  free (buf);
  if (hp_fclose_w (f, path) != 0) return 1;

  return 0;
}

/* Most lists are named after their length, as Alpha/8.txt. A few are not, and two
 * lists may share a directory, so the table names the file. */
void hp_dir_path (char *out, size_t n, const char *outdir, const hp_dir_t *d, int len)
{
  if (d->file != NULL)
    snprintf (out, n, "%s/%s/%s", outdir, d->dir, d->file);
  else
    snprintf (out, n, "%s/%s/%d.txt", outdir, d->dir, d->flat ? 1 : len);
}

static int hp_num_cmp (const void *a, const void *b)
{
  const int x = *(const int *) a;
  const int y = *(const int *) b;

  return (x > y) - (x < y);
}

/* The "<n>.txt" in a directory, as a JSON list in the order of the lengths. */
static void hp_len_files (const char *outdir, const char *sub, char *out, size_t outn)
{
  char path[PCFG_MAXPATH];

  int len[256];
  int n = 0;

  snprintf (path, sizeof (path), "%s/%s", outdir, sub);

  DIR *d = opendir (path);

  if (d != NULL)
  {
    struct dirent *e;

    while (((e = readdir (d)) != NULL) && (n < 256))
    {
      int v         = 0;
      const char *s = e->d_name;

      if ((s[0] < '0') || (s[0] > '9')) continue;

      while ((*s >= '0') && (*s <= '9')) v = (v * 10) + (*s++ - '0');

      if (strcmp (s, ".txt") != 0) continue;

      len[n++] = v;
    }

    closedir (d);
  }

  qsort (len, (size_t) n, sizeof (int), hp_num_cmp);

  size_t at = 0;

  at += (size_t) snprintf (out + at, outn - at, "[");

  for (int i = 0; (i < n) && (at < outn); i++)
    at += (size_t) snprintf (out + at, outn - at, "%s\"%d.txt\"", (i > 0) ? ", " : "", len[i]);

  if (at < outn) snprintf (out + at, outn - at, "]");
}

/* A unique enough name: a saved guessing session is checked against it. */
static void hp_uuid (char *out, size_t n)
{
  unsigned char b[16];

  FILE *f = fopen ("/dev/urandom", "rb");

  if ((f == NULL) || (fread (b, 1, sizeof (b), f) != sizeof (b)))
  {
    /* No urandom: the clock and a stack address, which differ between runs. */
    const uint64_t t = (uint64_t) time (NULL) ^ (uint64_t) (uintptr_t) &b;

    for (size_t i = 0; i < sizeof (b); i++) b[i] = (unsigned char) ((t >> ((i % 8) * 8)) ^ (i * 37));
  }

  if (f != NULL) fclose (f);

  size_t at = 0;

  for (size_t i = 0; (i < sizeof (b)) && ((at + 2) < n); i++)
    at += (size_t) snprintf (out + at, n - at, "%02x", b[i]);
}

int hp_write_config (const char *outdir, const char *infile, const char *version, bool compat,
                     int64_t pw_cnt, int64_t enc_err, const char *comments, const char *encoding)
{
  char path[PCFG_MAXPATH];

  snprintf (path, sizeof (path), "%s/config.ini", outdir);

  FILE *f = fopen (path, "wb");

  if (f == NULL)
  {
    fprintf (stderr, "hpcfg: cannot create \"%s\": %s\n", path, strerror (errno));
    return 1;
  }

  /* The path's last part, unless the caller already made a name of several. */
  const char *base = (strstr (infile, " + ") != NULL) ? NULL : strrchr (infile, '/');

  base = (base != NULL) ? (base + 1) : infile;

  char uuid[64];

  hp_uuid (uuid, sizeof (uuid));

  /* The four keys mean what the other producers make them mean: the program name
   * bare, and in "version" the format's version, claimed for one reader only. */
  fprintf (f, "[TRAINING_PROGRAM_DETAILS]\n");
  fprintf (f, "contact = %s\n", "https://github.com/matrix/hpcfg");
  fprintf (f, "author = %s\n", "Gabriele \"matrix\" Gristina");
  fprintf (f, "program = hpcfg\n");
  fprintf (f, "version = %s\n\n", (compat == true) ? "4.7" : version);

  fprintf (f, "[TRAINING_DATASET_DETAILS]\n");
  fprintf (f, "comments = %s\n", (comments != NULL) ? comments : "");
  fprintf (f, "filename = %s\n", base);
  /* What the values turn out to be, unless the caller insists otherwise. */
  if ((encoding != NULL) && (strcmp (encoding, hp_encoding_name ()) != 0))
    fprintf (stderr, "hpcfg: the values written are %s, and config.ini will say %s as asked\n",
             hp_encoding_name (), encoding);

  fprintf (f, "encoding = %s\n", (encoding != NULL) ? encoding : hp_encoding_name ());
  fprintf (f, "uuid = %s\n", uuid);
  fprintf (f, "number_of_passwords_in_set = %" PRId64 "\n", pw_cnt);
  fprintf (f, "number_of_encoding_errors = %" PRId64 "\n\n", enc_err);

  /* The rest indexes the directory: which section holds which type, and named how. */
  fprintf (f, "[START]\n");
  fprintf (f, "name = Base Structure\n");
  fprintf (f, "function = Transparent\n");
  fprintf (f, "directory = Grammar\n");
  fprintf (f, "comments = Base structures as defined by the original PCFG Paper, with some renaming to prevent naming collisions. Examples are A4D2 from the training word pass12\n");
  fprintf (f, "file_type = Flat\n");
  fprintf (f, "inject_type = Wordlist\n");
  fprintf (f, "is_terminal = False\n");
  fprintf (f, "replacements = [{\"Config_id\": \"BASE_A\", \"Transition_id\": \"A\"}, {\"Config_id\": \"BASE_D\", \"Transition_id\": \"D\"}, {\"Config_id\": \"BASE_O\", \"Transition_id\": \"O\"}, {\"Config_id\": \"BASE_K\", \"Transition_id\": \"K\"}, {\"Config_id\": \"BASE_X\", \"Transition_id\": \"X\"}, {\"Config_id\": \"BASE_Y\", \"Transition_id\": \"Y\"}]\n");
  fprintf (f, "filenames = [\"grammar.txt\"]\n\n");

  char files[8192];

  hp_len_files (outdir, "Alpha", files, sizeof (files));

  fprintf (f, "[BASE_A]\n");
  fprintf (f, "name = A\n");
  fprintf (f, "function = Shadow\n");
  fprintf (f, "directory = Alpha\n");
  fprintf (f, "comments = (A)lpha letter replacements for base structure. Aka pass12 = A4D2, so this is the A4. Note, this is encoding specific so non-ASCII characters may be considered alpha. For example Cyrillic characters will be considered alpha characters\n");
  fprintf (f, "file_type = Length\n");
  fprintf (f, "inject_type = Wordlist\n");
  fprintf (f, "is_terminal = False\n");
  fprintf (f, "replacements = [{\"Config_id\": \"CAPITALIZATION\", \"Transition_id\": \"Capitalization\"}]\n");
  fprintf (f, "filenames = %s\n\n", files);

  const struct
  {
    const char *sect, *name, *dir, *comment;
  } copy[] = {
    { "BASE_D", "D", "Digits",   "(D)igit replacement for base structure. Aka pass12 = L4D2, so this is the D2"             },
    { "BASE_O", "O", "Other",    "(O)ther character replacement for base structure. Aka pass$$ = L4S2, so this is the S2"   },
    { "BASE_K", "K", "Keyboard", "(K)eyboard replacement for base structure. Aka test1qaz2wsx = L4K4K4, so this is the K4s" },
  };

  for (size_t i = 0; i < (sizeof (copy) / sizeof (copy[0])); i++)
  {
    hp_len_files (outdir, copy[i].dir, files, sizeof (files));

    fprintf (f, "[%s]\n", copy[i].sect);
    fprintf (f, "name = %s\n", copy[i].name);
    fprintf (f, "function = Copy\n");
    fprintf (f, "directory = %s\n", copy[i].dir);
    fprintf (f, "comments = %s\n", copy[i].comment);
    fprintf (f, "file_type = Length\n");
    fprintf (f, "inject_type = Copy\n");
    fprintf (f, "is_terminal = True\n");
    fprintf (f, "filenames = %s\n\n", files);
  }

  /* Context and Years are one file whatever the length, hence 1.txt. */
  const struct
  {
    const char *sect, *name, *dir, *comment;
  } flat[] = {
    { "BASE_X", "X", "Context", "conte(X)t sensitive replacements to the base structure. This is mostly a grab bag of things like #1 or ;p" },
    { "BASE_Y", "Y", "Years",   "Years to replace with"                                                                                     },
  };

  for (size_t i = 0; i < (sizeof (flat) / sizeof (flat[0])); i++)
  {
    fprintf (f, "[%s]\n", flat[i].sect);
    fprintf (f, "name = %s\n", flat[i].name);
    fprintf (f, "function = Copy\n");
    fprintf (f, "directory = %s\n", flat[i].dir);
    fprintf (f, "comments = %s\n", flat[i].comment);
    fprintf (f, "file_type = Flat\n");
    fprintf (f, "inject_type = Copy\n");
    fprintf (f, "is_terminal = True\n");
    fprintf (f, "filenames = [\"1.txt\"]\n\n");
  }

  hp_len_files (outdir, "Capitalization", files, sizeof (files));

  fprintf (f, "[CAPITALIZATION]\n");
  fprintf (f, "name = C\n");
  fprintf (f, "function = Capitalization\n");
  fprintf (f, "directory = Capitalization\n");
  fprintf (f, "comments = Capitalization Masks for words. Aka LLLLUUUU for passWORD\n");
  fprintf (f, "file_type = Length\n");
  fprintf (f, "inject_type = Copy\n");
  fprintf (f, "is_terminal = True\n");
  fprintf (f, "filenames = %s\n", files);

  if (hp_fclose_w (f, path) != 0) return 1;

  return 0;
}

int hp_write_counts (const hp_store_t *st, const char *outdir, const hp_dir_t *dirs)
{
  hp_bin_t b;

  b.admit = 0;
  b.list  = (hp_list_t (*)[256]) calloc (256 * 256, sizeof (hp_list_t));

  if (b.list == NULL) return 1;

  hp_store_foreach_all (st, hp_bin, &b);

  int rc = 0;
  char path[PCFG_MAXPATH];

  if (hp_mkdir (outdir) != 0) rc = 1;

  for (int d = 0; (dirs[d].dir != NULL) && (rc == 0); d++)
  {
    const uint8_t ty = (uint8_t) dirs[d].ty;

    bool any = false;

    for (int len = 0; len < 256; len++)
      if (b.list[ty][len].n > 0) any = true;

    if (any == false) continue;

    snprintf (path, sizeof (path), "%s/%s", outdir, dirs[d].dir);

    if (hp_mkdir (path) != 0)
    {
      rc = 1;
      break;
    }

    for (int len = 0; len < 256; len++)
    {
      if (b.list[ty][len].n == 0) continue;

      hp_dir_path (path, sizeof (path), outdir, &dirs[d], len);

      if (hp_write_counts_one (path, &b.list[ty][len]) != 0)
      {
        rc = 1;
        break;
      }
    }
  }

  for (int t = 0; t < 256; t++)
    for (int l = 0; l < 256; l++) free (b.list[t][l].v);

  free (b.list);

  return rc;
}

int hp_merge_counts (char **parts, int nparts, const char *outdir,
                     const hp_dir_t *dirs, int64_t admit)
{
  char path[PCFG_MAXPATH];

  if (hp_mkdir (outdir) != 0) return 1;

  char *line = (char *) malloc (PCFG_MAXLINE + 64);

  if (line == NULL) return 1;

  int rc = 0;

  /* One list at a time, and as long as the run that produced them. Saying
   * "summing 4 partials" and then nothing looks like a hang from outside. */
  int ndirs = 0;

  while (dirs[ndirs].dir != NULL) ndirs++;

  const double t0 = hp_now ();
  const bool tty  = hp_stderr_is_tty ();

  double last = t0;

  for (int d = 0; (dirs[d].dir != NULL) && (rc == 0); d++)
  {
    bool made = false;

    for (int len = 0; (len < 256) && (rc == 0); len++)
    {
      /* A flat type keeps every length in one file. Running the whole loop
       * rewrote it 256 times per spill and left 256 rows in totals.txt. */
      if ((dirs[d].flat == true) && (len != 1)) continue;

      const double now = hp_now ();

      if ((now - last) >= ((tty == true) ? 0.5 : 20.0))
      {
        last = now;

        const double frac = ((double) d + ((double) len / 256.0)) / (double) ndirs;

        if (tty == true)
          fprintf (stderr, "hpcfg: %-16s %5.1f%%  %s/%d              \r", "merging", frac * 100.0, dirs[d].dir, len);
        else
          fprintf (stderr, "hpcfg: %-16s %5.1f%%  %s/%d\n", "merging", frac * 100.0, dirs[d].dir, len);

        fflush (stderr);
      }

      hp_store_t *acc = NULL;

      for (int p = 0; p < nparts; p++)
      {
        hp_dir_path (path, sizeof (path), parts[p], &dirs[d], len);

        FILE *f = fopen (path, "rb");

        if (f == NULL) continue;

        if (acc == NULL) acc = hp_store_new (4, 4u << 20);

        while (fgets (line, PCFG_MAXLINE + 64, f) != NULL)
        {
          int n = (int) strlen (line);

          while ((n > 0) && ((line[n - 1] == '\n') || (line[n - 1] == '\r'))) n--;

          line[n] = '\0';

          /* The value comes first and may contain tabs; the count cannot. */
          char *tab = strrchr (line, '\t');

          if (tab == NULL) continue;

          *tab = '\0';

          const int64_t cnt = strtoll (tab + 1, NULL, 10);

          if (cnt > 0) hp_store_add (acc, (uint8_t) dirs[d].ty, (uint8_t) len,
                                     line, (int) (tab - line), cnt);
        }

        fclose (f);
      }

      if (acc == NULL) continue;

      if (made == false)
      {
        snprintf (path, sizeof (path), "%s/%s", outdir, dirs[d].dir);

        if (hp_mkdir (path) != 0)
        {
          rc = 1;
          hp_store_free (acc);
          break;
        }

        made = true;
      }

      hp_dir_path (path, sizeof (path), outdir, &dirs[d], len);

      hp_bin_t b;

      b.admit = admit;
      b.list  = (hp_list_t (*)[256]) calloc (256 * 256, sizeof (hp_list_t));

      if (b.list == NULL)
      {
        rc = 1;
        hp_store_free (acc);
        break;
      }

      hp_store_foreach_all (acc, hp_bin, &b);

      hp_note_total ((uint8_t) dirs[d].ty, (uint8_t) len, b.list[(uint8_t) dirs[d].ty][len].total);

      if (hp_write_one (path, &b.list[(uint8_t) dirs[d].ty][len]) != 0) rc = 1;

      for (int t = 0; t < 256; t++)
        for (int l = 0; l < 256; l++) free (b.list[t][l].v);

      free (b.list);
      hp_store_free (acc);
    }
  }

  free (line);

  return rc;
}

int hp_write_ruleset (const hp_store_t *st, const char *outdir,
                      const hp_dir_t *dirs, int64_t admit, int nthread)
{
  hp_bin_t b;

  b.admit = admit;
  b.list  = (hp_list_t (*)[256]) calloc (256 * 256, sizeof (hp_list_t));

  if (b.list == NULL) return 1;

  hp_store_foreach_all (st, hp_bin, &b);

  int rc = 0;

  char path[PCFG_MAXPATH];

  hp_jobs_t js;

  memset (&js, 0, sizeof (js));

  js.job = (hp_job_t *) calloc (256 * 256, sizeof (hp_job_t));

  if (js.job == NULL)
  {
    free (b.list);
    return 1;
  }

  hp_mutex_init (&js.mux);

  /* The directories are made up front, single threaded, so no two workers race. */
  for (int d = 0; (dirs[d].dir != NULL) && (rc == 0); d++)
  {
    const uint8_t ty = (uint8_t) dirs[d].ty;

    bool any = false;

    for (int len = 0; len < 256; len++)
      if (b.list[ty][len].n > 0) any = true;

    if (any == false) continue;

    snprintf (path, sizeof (path), "%s/%s", outdir, dirs[d].dir);

    if (hp_mkdir (path) != 0)
    {
      rc = 1;
      break;
    }

    for (int len = 0; len < 256; len++)
    {
      if (b.list[ty][len].n == 0) continue;

      hp_dir_path (js.job[js.n].path, sizeof (js.job[js.n].path), outdir, &dirs[d], len);

      js.job[js.n].list = &b.list[ty][len];
      js.total += (int64_t) b.list[ty][len].n;
      js.n++;

      hp_note_total (ty, (uint8_t) len, b.list[ty][len].total);
    }
  }

  if (rc == 0)
  {
    int nw = (nthread > 0) ? nthread : 1;

    if (nw > js.n) nw = (js.n > 0) ? js.n : 1;
    if (nw > 256) nw = 256;

    hp_thread_t *th[256];

    hp_thread_t *rt = hp_thread_start (hp_write_reporter, &js);

    for (int i = 1; i < nw; i++) th[i] = hp_thread_start (hp_write_worker, &js);

    hp_write_worker (&js);

    for (int i = 1; i < nw; i++) hp_thread_join (th[i]);

    js.stop = 1;

    if (rt != NULL) hp_thread_join (rt);

    if (hp_stderr_is_tty () == true) fprintf (stderr, "%60s\r", "");

    rc = js.rc;
  }

  hp_mutex_destroy (js.mux);

  free (js.job);

  for (int t = 0; t < 256; t++)
    for (int l = 0; l < 256; l++) free (b.list[t][l].v);

  free (b.list);

  return rc;
}

/* The training set a ruleset names, for a merge to say what it merged. */
static int hp_config_name (const char *dir, char *out, size_t n)
{
  char path[PCFG_MAXPATH];

  snprintf (path, sizeof (path), "%s/config.ini", dir);

  FILE *f = fopen (path, "rb");

  if (f == NULL) return 1;

  char line[1024];
  int rc = 1;

  while (fgets (line, sizeof (line), f) != NULL)
  {
    if (strncmp (line, "filename", 8) != 0) continue;

    const char *eq = strchr (line, '=');

    if (eq == NULL) continue;

    eq++;

    while ((*eq == ' ') || (*eq == '\t')) eq++;

    snprintf (out, n, "%s", eq);

    size_t len = strlen (out);

    while ((len > 0) && ((out[len - 1] == '\n') || (out[len - 1] == '\r') || (out[len - 1] == ' '))) out[--len] = 0;

    rc = (len > 0) ? 0 : 1;

    break;
  }

  fclose (f);

  return rc;
}

static int64_t hp_config_total (const char *dir)
{
  char path[PCFG_MAXPATH];

  snprintf (path, sizeof (path), "%s/config.ini", dir);

  FILE *f = fopen (path, "rb");

  if (f == NULL) return -1;

  char line[1024];

  int64_t n = -1;

  while (fgets (line, sizeof (line), f) != NULL)
  {
    const char *k = "number_of_passwords_in_set";

    if (strncmp (line, k, strlen (k)) != 0) continue;

    const char *eq = strchr (line, '=');

    if (eq == NULL) continue;

    n = strtoll (eq + 1, NULL, 10);

    break;
  }

  fclose (f);

  return n;
}

/* The lengths a directory holds across every ruleset merged, trained or not. */
static int hp_merge_lens (char **in, int nin, const hp_dir_t *d, int *len, int maxlen)
{
  int n = 0;

  for (int i = 0; i < nin; i++)
  {
    char path[PCFG_MAXPATH];

    snprintf (path, sizeof (path), "%s/%s", in[i], d->dir);

    DIR *dp = opendir (path);

    if (dp == NULL) continue;

    struct dirent *e;

    while (((e = readdir (dp)) != NULL) && (n < maxlen))
    {
      const char *s = e->d_name;

      if ((s[0] < '0') || (s[0] > '9')) continue;

      int v = 0;

      while ((*s >= '0') && (*s <= '9')) v = (v * 10) + (*s++ - '0');

      if (strcmp (s, ".txt") != 0) continue;

      bool seen = false;

      for (int j = 0; j < n; j++)
        if (len[j] == v) seen = true;

      if (seen == false) len[n++] = v;
    }

    closedir (dp);
  }

  return n;
}

static int hp_copy_file (const char *from, const char *to)
{
  FILE *a = fopen (from, "rb");

  if (a == NULL) return 1;

  FILE *b = fopen (to, "wb");

  if (b == NULL)
  {
    fclose (a);

    return 1;
  }

  char buf[65536];
  size_t n;

  while ((n = fread (buf, 1, sizeof (buf), a)) > 0)
  {
    if (fwrite (buf, 1, n, b) != n)
    {
      fclose (a);
      fclose (b);

      return 1;
    }
  }

  fclose (a);

  return hp_fclose_w (b, to);
}

static double hp_solve_total (const double *p, size_t n, double small, int *rarest)
{
  const double guess = 1.0 / small;

  if (rarest != NULL) *rarest = 0;

  if ((p == NULL) || (n == 0)) return guess;

  size_t probe[64];
  size_t np = 0;

  const size_t step = (n > 64) ? (n / 64) : 1;

  for (size_t i = 0; (i < n) && (np < 64); i += step) probe[np++] = i;

  for (int k = 1; k <= 100000; k++)
  {
    const double t = (double) k * guess;

    bool ok = true;

    for (size_t j = 0; (j < np) && (ok == true); j++)
    {
      const double x = p[probe[j]] * t;
      const double d = x - (double) ((int64_t) (x + 0.5));

      if (((d < 0.0) ? -d : d) > (1e-6 * ((x > 1.0) ? x : 1.0))) ok = false;
    }

    if (ok == false) continue;

    for (size_t j = 0; (j < n) && (ok == true); j++)
    {
      const double x = p[j] * t;
      const double d = x - (double) ((int64_t) (x + 0.5));

      if (((d < 0.0) ? -d : d) > (1e-6 * ((x > 1.0) ? x : 1.0))) ok = false;
    }

    if (ok == true)
    {
      if (rarest != NULL) *rarest = k;

      return t;
    }
  }

  return guess;
}

/* The count of every kind of section a ruleset saw, which is what its terminal
 * lists were counted out of. */
typedef struct
{
  char ty;
  int len;
  int64_t cnt;
} hp_prince_t;

static hp_prince_t *hp_prince_load (const char *dir, size_t *out_n)
{
  char path[PCFG_MAXPATH];

  *out_n = 0;

  snprintf (path, sizeof (path), "%s/Prince/grammar.txt", dir);

  FILE *f = fopen (path, "rb");

  if (f == NULL) return NULL;

  char line[1024];

  double *ps = NULL;
  size_t pn = 0, pcap = 0;

  hp_prince_t *pr = NULL;
  size_t n = 0, cap = 0;

  double small = 0.0;

  while (fgets (line, sizeof (line), f) != NULL)
  {
    char *t = strrchr (line, '\t');

    if (t == NULL) continue;

    *t = '\0';

    const double p = strtod (t + 1, NULL);

    if (p <= 0.0) continue;

    if ((small == 0.0) || (p < small)) small = p;

    if (pn == pcap)
    {
      const size_t c = (pcap == 0) ? 256 : (pcap * 2);

      double *nv = (double *) realloc (ps, c * sizeof (double));

      if (nv == NULL) break;

      ps   = nv;
      pcap = c;
    }

    ps[pn++] = p;

    if (n == cap)
    {
      const size_t c = (cap == 0) ? 256 : (cap * 2);

      hp_prince_t *nv = (hp_prince_t *) realloc (pr, c * sizeof (hp_prince_t));

      if (nv == NULL) break;

      pr  = nv;
      cap = c;
    }

    pr[n].ty  = line[0];
    pr[n].len = 0;

    for (const char *c = line + 1; (*c >= '0') && (*c <= '9'); c++)
      pr[n].len = (pr[n].len * 10) + (*c - '0');

    pr[n].cnt = (int64_t) (p * 1e18); /* filled properly below */

    n++;
  }

  fclose (f);

  if ((pr == NULL) || (n == 0) || (small <= 0.0))
  {
    free (ps);
    free (pr);

    return NULL;
  }

  const double total = hp_solve_total (ps, pn, small, NULL);

  for (size_t i = 0; i < n; i++) pr[i].cnt = (int64_t) ((ps[i] * total) + 0.5);

  free (ps);

  *out_n = n;

  return pr;
}

/* What this list was counted out of, or zero if the file does not say. A
 * capitalisation mask is counted once per alpha run, so it shares the run's
 * count; the prefixes and sensitive lists have none and fall back to solving. */
static double hp_prince_total (const hp_prince_t *pr, size_t n, char ty, int len)
{
  if (pr == NULL) return 0.0;

  if (ty == 'C') ty = 'A';

  for (size_t i = 0; i < n; i++)
    if ((pr[i].ty == ty) && (pr[i].len == len)) return (double) pr[i].cnt;

  return 0.0;
}

/* The level distribution a ruleset recorded, summed across the rulesets. */
static int hp_levels_load (const char *dir, const double w, int64_t *lvl, int nlvl)
{
  char path[PCFG_MAXPATH];

  snprintf (path, sizeof (path), "%s/Omen/omen_pws_per_level.txt", dir);

  FILE *f = fopen (path, "rb");

  if (f == NULL) return 1;

  char line[512];

  while (fgets (line, sizeof (line), f) != NULL)
  {
    char *t = strchr (line, '\t');

    if (t == NULL) continue;

    *t = '\0';

    const int l = atoi (line);

    if ((l < 0) || (l >= nlvl)) continue;

    lvl[l] += (int64_t) ((strtoll (t + 1, NULL, 10) * w) + 0.5);
  }

  fclose (f);

  return 0;
}

/* One pass over the corpus with the merged model, counting where each password
 * lands. The line handling is the reader's, the same the training pass makes. */
static int64_t hp_levels_walk (const hp_merge_src_t *src, omen_t *om, int64_t *lvl, int nlvl)
{
  FILE *f = fopen (src->corpus, "rb");

  if (f == NULL)
  {
    fprintf (stderr, "hpcfg: cannot read \"%s\": %s\n", src->corpus, strerror (errno));

    return -1;
  }

  char *line = (char *) malloc (PCFG_MAXLINE + 64);
  char *hex  = (char *) malloc (PCFG_MAXLINE);

  if ((line == NULL) || (hex == NULL))
  {
    free (line);
    free (hex);
    fclose (f);

    return -1;
  }

  /* The corpus is weighted, so this counts occurrences and not lines: on a list
   * the size of HIBP an int wraps and the denominator comes out too small. */
  int64_t seen = 0;

  while (fgets (line, PCFG_MAXLINE + 64, f) != NULL)
  {
    int len = (int) strlen (line);

    while ((len > 0) && ((line[len - 1] == '\n') || (line[len - 1] == '\r'))) len--;

    line[len] = '\0';

    if (len <= 0) continue;

    char *pw  = line;
    int64_t n = 1;

    if (src->weighted == true)
    {
      int i = 0;

      while ((i < len) && (pw[i] >= '0') && (pw[i] <= '9')) i++;

      if ((i == 0) || (i >= len) || (strchr (src->sep, pw[i]) == NULL)) continue;

      n = strtoll (pw, NULL, 10);
      pw += i + 1;
      len -= i + 1;

      if (n <= 0) n = 1;

      if (n < src->mincount) continue;
    }

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

    if ((src->keep_junk == false) && (hp_is_junk (pw, len) == true)) continue;

    /* Counted as trained whether or not the escape can place it: a level's share
     * is a share of the training set, which the training pass divides by too. */
    seen += n;

    const int l = omen_level (om, pw, len);

    if ((l >= 0) && (l < nlvl)) lvl[l] += n;
  }

  free (hex);
  free (line);
  fclose (f);

  return seen;
}

static int omen_merged (char **in, const double *weight, int nin, const char *outdir,
                        int64_t total_pw, const hp_merge_src_t *src)
{
  /* The merged ruleset is written for whoever the merge was asked to write for. */
  omen_t *om = omen_merge_counts (in, weight, nin, (src != NULL) && (src->compat == true));

  if (om == NULL) return 1;

  int64_t lvl[OMEN_LVL_CNT];

  memset (lvl, 0, sizeof (lvl));

  int seen = 0;

  if ((src != NULL) && (src->corpus != NULL))
  {
    const int64_t n = hp_levels_walk (src, om, lvl, OMEN_LVL_CNT);

    if (n < 0)
    {
      omen_free (om);

      return 1;
    }

    /* And the number it is a share of comes from the same pass. */
    if (n > 0) total_pw = n;

    fprintf (stderr, "hpcfg: level distribution counted over %s, %" PRId64 " passwords\n",
             src->corpus, n);
  }
  else
  {
    for (int i = 0; i < nin; i++)
    {
      const double w = (weight != NULL) ? (weight[i] * (double) nin) : 1.0;

      if (hp_levels_load (in[i], w, lvl, OMEN_LVL_CNT) == 0) seen++;
    }

    /* A ruleset whose distribution could not be read leaves the sum covering
     * fewer models than the grammar beside it. Going quiet hides that. */
    if (seen < nin)
    {
      fprintf (stderr, "hpcfg: %d of %d rulesets had no level distribution to add; "
                       "the merged one is theirs alone\n",
               nin - seen, nin);
    }
  }

  char path[PCFG_MAXPATH];

  snprintf (path, sizeof (path), "%s/Omen", outdir);

  if (hp_mkdir (path) != 0)
  {
    omen_free (om);

    return 1;
  }

  const int rc = omen_save (om, path, lvl, OMEN_LVL_CNT,
                            (total_pw > 0) ? total_pw : 0);

  if (rc == 0) omen_write_counts (om, path);

  omen_free (om);

  return rc;
}

static bool hp_same_dir (const char *a, const char *b)
{
  struct stat sa, sb;

  if ((stat (a, &sa) != 0) || (stat (b, &sb) != 0)) return false;

  return ((sa.st_dev == sb.st_dev) && (sa.st_ino == sb.st_ino));
}

int hp_merge_rulesets (char **in, const double *weight, int nin, const char *outdir,
                       const hp_dir_t *dirs, const hp_dir_t *gdirs, int64_t admit,
                       const hp_merge_src_t *src)
{
  char path[PCFG_MAXPATH];

  /* The output cannot be one of the inputs. */
  for (int i = 0; i < nin; i++)
  {
    if (hp_same_dir (outdir, in[i]) == false) continue;

    fprintf (stderr, "hpcfg: -g names \"%s\", which is also being merged; the merge would overwrite "
                     "it while reading it. Write the result somewhere else\n",
             in[i]);

    return 1;
  }

  if (hp_mkdir (outdir) != 0) return 1;

  /* What share each ruleset takes: what it was trained on, or what the caller
   * asked for. Normalised, because only the ratio between them means anything. */
  double *wt = (double *) calloc ((size_t) nin, sizeof (double));

  if (wt == NULL) return 1;

  int64_t total_pw = 0;

  double sum = 0.0;

  for (int i = 0; i < nin; i++)
  {
    if (weight != NULL)
    {
      wt[i] = weight[i];
    }
    else
    {
      const int64_t n = hp_config_total (in[i]);

      if (n <= 0)
      {
        fprintf (stderr, "hpcfg: %s/config.ini does not say how many passwords it was trained on, "
                         "so its share cannot be worked out; give --weights\n",
                 in[i]);

        free (wt);

        return 1;
      }

      wt[i] = (double) n;
      total_pw += n;
    }

    sum += wt[i];
  }

  for (int i = 0; i < nin; i++) wt[i] /= sum;

  char *line = (char *) malloc (PCFG_MAXLINE + 64);

  if (line == NULL)
  {
    free (wt);

    return 1;
  }

  hp_prince_t *pr[64];
  size_t prn[64];

  for (int i = 0; i < nin; i++) pr[i] = hp_prince_load (in[i], &prn[i]);

  int rc = 0;

  /* Both tables: the terminals, and the three lists beside the grammar. */
  const hp_dir_t *table[2] = { dirs, gdirs };

  for (int t = 0; (t < 2) && (rc == 0); t++)
  {
    const hp_dir_t *tab = table[t];

    for (int d = 0; (tab[d].dir != NULL) && (rc == 0); d++)
    {
      /* The provider, host and prefix lists exist for readers other than
       * hashcat, so a merge writing for hashcat does not carry them across. */
      if (((src == NULL) || (src->compat == false)) &&
          ((tab[d].ty == PCFG_ST_EMAIL) || (tab[d].ty == PCFG_ST_WEBSITE) ||
           (tab[d].ty == HP_TY_WEBPFX) || (tab[d].ty == HP_TY_FULLMAIL) ||
           (tab[d].ty == HP_TY_FULLURL))) continue;

      int len[512];
      int nlen = 0;

      if (tab[d].file != NULL)
      {
        len[nlen++] = 0; /* one file, named in the table */
      }
      else
      {
        nlen = hp_merge_lens (in, nin, &tab[d], len, 512);
      }

      bool made = false;

      for (int li = 0; (li < nlen) && (rc == 0); li++)
      {
        hp_store_t *acc = NULL;

        /* Putting the counts back. */
        double scale[64];
        double lift = 1.0;

        {
          double least = 0.0;

          for (int i = 0; i < nin; i++)
          {
            scale[i] = 0.0;

            hp_dir_path (path, sizeof (path), in[i], &tab[d], len[li]);

            FILE *f = fopen (path, "rb");

            if (f == NULL) continue;

            double small = 0.0;

            /* The shares themselves, to solve for the total they were taken
             * against. One list is live at a time. */
            double *ps = NULL;
            size_t pn = 0, pcap = 0;

            while (fgets (line, PCFG_MAXLINE + 64, f) != NULL)
            {
              char *t = strrchr (line, '\t');

              if (t == NULL) continue;

              const double p = strtod (t + 1, NULL);

              if (p <= 0.0) continue;

              if ((small == 0.0) || (p < small)) small = p;

              const double c = p * wt[i];

              if ((least == 0.0) || (c < least)) least = c;

              if (pn == pcap)
              {
                const size_t cap = (pcap == 0) ? 1024 : (pcap * 2);

                double *nv = (double *) realloc (ps, cap * sizeof (double));

                if (nv == NULL) break;

                ps   = nv;
                pcap = cap;
              }

              ps[pn++] = p;
            }

            fclose (f);

            if (small > 0.0)
            {
              /* Said outright if the ruleset says it, counted sections if not,
               * and solved from the shares as the last resort. */
              scale[i] = (double) hp_read_total (in[i], (uint8_t) tab[d].ty, (uint8_t) len[li]);

              if (scale[i] <= 0.0)
                scale[i] = hp_prince_total (pr[i], prn[i], (char) tab[d].ty, len[li]);

              if (scale[i] <= 0.0) scale[i] = hp_solve_total (ps, pn, small, NULL);
            }

            free (ps);
          }

          if (weight != NULL)
          {
            if (least > 0.0) lift = 1e9 / least;

            if (lift < 1.0) lift = 1.0;
            if (lift > 1e15) lift = 1e15;
          }
          else
          {
            /* The fallback scale, for a list whose total the solver could not
             * settle. One constant across every ruleset, so the ratios hold. */
            lift = 1.0;
          }
        }

        for (int i = 0; i < nin; i++)
        {
          hp_dir_path (path, sizeof (path), in[i], &tab[d], len[li]);

          FILE *f = fopen (path, "rb");

          if (f == NULL) continue;

          if (acc == NULL) acc = hp_store_new (4, 4u << 20);

          while (fgets (line, PCFG_MAXLINE + 64, f) != NULL)
          {
            int n = (int) strlen (line);

            while ((n > 0) && ((line[n - 1] == '\n') || (line[n - 1] == '\r'))) n--;

            line[n] = '\0';

            /* The value comes first and may contain tabs; the probability cannot. */
            char *tab_at = strrchr (line, '\t');

            if (tab_at == NULL) continue;

            *tab_at = '\0';

            const double p = strtod (tab_at + 1, NULL);

            if (p <= 0.0) continue;

            /* Counts when they can be had, shares lifted when they cannot. */
            const int64_t cnt = (weight != NULL)
                                    ? (int64_t) ((p * wt[i] * lift) + 0.5)
                                    : (int64_t) ((p * scale[i]) + 0.5);

            if (cnt > 0)
              hp_store_add (acc, (uint8_t) tab[d].ty, (uint8_t) len[li],
                            line, (int) (tab_at - line), cnt);
          }

          fclose (f);
        }

        if (acc == NULL) continue;

        if (made == false)
        {
          snprintf (path, sizeof (path), "%s/%s", outdir, tab[d].dir);

          if (hp_mkdir (path) != 0)
          {
            rc = 1;

            hp_store_free (acc);

            break;
          }

          made = true;
        }

        hp_dir_path (path, sizeof (path), outdir, &tab[d], len[li]);

        hp_bin_t b;

        /* The counts are occurrences again, times the constant just applied, so
         * the filter goes through the same multiplier and -f means here what it
         * means when training. Against the lifted counts it dropped nothing. */
        b.admit = admit;

        b.list = (hp_list_t (*)[256]) calloc (256 * 256, sizeof (hp_list_t));

        if (b.list == NULL)
        {
          rc = 1;

          hp_store_free (acc);

          break;
        }

        hp_store_foreach_all (acc, hp_bin, &b);

        hp_note_total ((uint8_t) tab[d].ty, (uint8_t) len[li], b.list[(uint8_t) tab[d].ty][len[li]].total);

        if (hp_write_one (path, &b.list[(uint8_t) tab[d].ty][len[li]]) != 0) rc = 1;

        for (int x = 0; x < 256; x++)
          for (int y = 0; y < 256; y++) free (b.list[x][y].v);

        free (b.list);
        hp_store_free (acc);
      }
    }
  }

  free (line);

  for (int i = 0; i < nin; i++) free (pr[i]);

  /* The escape, merged where the counts are there and carried across where not. */
  if ((rc == 0) && (omen_merged (in, weight, nin, outdir, total_pw, src) == 0))
  {
    fprintf (stderr, "hpcfg: OMEN merged from the counts of %d rulesets\n", nin);
  }
  else if (rc == 0)
  {
    static const char *omen[] = { "config.txt", "alphabet.txt", "IP.level", "EP.level",
                                  "CP.level", "LN.level", "omen_keyspace.txt",
                                  "omen_pws_per_level.txt", "pcfg_omen_prob.txt", NULL };

    char from[PCFG_MAXPATH], to[PCFG_MAXPATH];

    snprintf (from, sizeof (from), "%s/Omen", in[0]);

    DIR *dp = opendir (from);

    if (dp != NULL)
    {
      closedir (dp);

      snprintf (to, sizeof (to), "%s/Omen", outdir);

      if (hp_mkdir (to) != 0) rc = 1;

      int copied = 0;

      for (int i = 0; (omen[i] != NULL) && (rc == 0); i++)
      {
        snprintf (from, sizeof (from), "%s/Omen/%s", in[0], omen[i]);
        snprintf (to, sizeof (to), "%s/Omen/%s", outdir, omen[i]);

        if (hp_copy_file (from, to) == 0) copied++;
      }

      fprintf (stderr, "hpcfg: OMEN levels cannot be merged, so the escape is the one from \"%s\", "
                       "carried across whole (%d files)\n",
               in[0], copied);
    }
  }

  free (wt);

  if (rc == 0) rc = hp_write_totals (outdir);

  if (rc == 0)
  {
    char named[PCFG_MAXPATH];

    size_t at = 0;

    /* What each was trained on, if it says so, not the paths they sit at now. */
    for (int i = 0; (i < nin) && (at < (sizeof (named) - 2)); i++)
    {
      char what[256];

      if (hp_config_name (in[i], what, sizeof (what)) != 0)
      {
        const char *b = strrchr (in[i], '/');

        snprintf (what, sizeof (what), "%s", (b != NULL) ? (b + 1) : in[i]);
      }

      at += (size_t) snprintf (named + at, sizeof (named) - at, "%s%s", (i > 0) ? " + " : "", what);
    }

    rc = hp_write_config (outdir, named, HP_VERSION, (src != NULL) && (src->compat == true),
                          (total_pw > 0) ? total_pw : 0, 0, NULL, NULL);
  }

  return rc;
}
