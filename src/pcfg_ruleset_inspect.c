/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * Look at the ruleset instead of trusting it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "pcfg_common.h"
#include "pcfg_ruleset_inspect.h"
#include "pcfg_platform.h"

#define INS_MAXLIST 256

typedef struct
{
  long entries;
  double prob_sum;
  int bad_len;  /* entries whose length is not the list's own */
  int bad_byte; /* entries carrying a byte the format cannot transport */
  int loaded;

  /* For the report: what this list most likely contributes, and of what mass. */
  char top[128];
  double top_p;
  double used; /* summed probability of the structures naming it */
} ins_list_t;

static ins_list_t lists[128][INS_MAXLIST]; /* [token letter][length] */

static const char *ins_clock (double sec, char *out, size_t n)
{
  const long t = (long) ((sec < 0.0) ? 0.0 : sec);

  if (t >= 3600)
    snprintf (out, n, "%ld:%02ld:%02ld", t / 3600, (t % 3600) / 60, t % 60);
  else
    snprintf (out, n, "%02ld:%02ld", t / 60, t % 60);

  return out;
}

static const char *ins_secs (double sec, char *out, size_t n)
{
  const long t = (long) (sec + 0.5);

  if (t >= 3600)
    snprintf (out, n, "%ld minutes", (t + 30) / 60);
  else if (t >= 60)
    snprintf (out, n, "%ld minutes %ld seconds", t / 60, t % 60);
  else if (t == 1)
    snprintf (out, n, "1 second");
  else
    snprintf (out, n, "%ld seconds", t);

  return out;
}

static int64_t ins_pg_total = 0;
static int64_t ins_pg_done  = 0;
static double ins_pg_start  = 0.0;
static double ins_pg_last   = 0.0;
static int ins_pg_on        = 0;
static int ins_pg_said      = 0; /* whether a progress line was ever printed */

/* Every byte the ruleset holds, so the share is of the whole and not a part. */
static int64_t ins_bytes_of (const char *root)
{
  static const char *dirs[] = { "Alpha", "Capitalization", "Digits", "Other",
                                "Keyboard", "Context", "Years", "Grammar",
                                "Prince", "Emails", "Websites", NULL };
  int64_t tot               = 0;
  char path[1024];
  struct stat sb;

  for (int d = 0; dirs[d] != NULL; d++)
  {
    for (int n = 0; n <= INS_MAXLIST; n++)
    {
      snprintf (path, sizeof (path), "%s/%s/%d.txt", root, dirs[d], n);

      if (stat (path, &sb) == 0) tot += (int64_t) sb.st_size;
    }

    snprintf (path, sizeof (path), "%s/%s/grammar.txt", root, dirs[d]);

    if (stat (path, &sb) == 0) tot += (int64_t) sb.st_size;
  }

  return tot;
}

/* Just the two files the diff reads before it can say anything. What follows -
 * the lists, one at a time - prints a row per list and is its own progress. */
static int64_t ins_grammar_bytes (const char *root)
{
  char path[1024];
  struct stat sb;

  snprintf (path, sizeof (path), "%s/Grammar/grammar.txt", root);

  return (stat (path, &sb) == 0) ? (int64_t) sb.st_size : 0;
}

static void ins_pg_begin (int64_t total)
{
  ins_pg_total = total;
  ins_pg_done  = 0;
  ins_pg_start = hp_now ();
  ins_pg_last  = ins_pg_start;
  ins_pg_on    = 1;
  ins_pg_said  = 0;
}

static void ins_pg_add (int64_t bytes, const char *what)
{
  if (ins_pg_on == 0) return;

  ins_pg_done += bytes;

  const double now = hp_now ();

  /* Nothing is said about work that finishes quickly: a line stopped at some
   * arbitrary share and then gone looks like a failure rather than speed. */
  if ((now - ins_pg_start) < 0.5) return;

  if ((now - ins_pg_last) < 0.20) return;

  ins_pg_last = now;
  ins_pg_said = 1;

  const double frac = (ins_pg_total > 0)
                          ? ((double) ins_pg_done / (double) ins_pg_total)
                          : 0.0;
  const double el   = now - ins_pg_start;

  char eta[32] = "?";

  if ((frac > 0.001) && (el > 0.5))
  {
    ins_clock ((el / frac) - el, eta, sizeof (eta));
  }

  /* A ruleset can be 60 MB or 13 GB, and one unit cannot show both. */
  const int gb = (ins_pg_total >= (1LL << 30));

  fprintf (stderr, "\rhpcfg: reading %s, %.0f%%, %.1f/%.1f %s, ETA %s   ",
           what, frac * 100.0,
           (double) ins_pg_done / (gb ? 1073741824.0 : 1048576.0),
           (double) ins_pg_total / (gb ? 1073741824.0 : 1048576.0),
           gb ? "GB" : "MB", eta);

  fflush (stderr);
}

static void ins_pg_end (void)
{
  if ((ins_pg_on == 0) || (ins_pg_said == 0))
  {
    ins_pg_on = 0;

    return;
  }

  char el[32];

  ins_secs (hp_now () - ins_pg_start, el, sizeof (el));

  fprintf (stderr, "\rhpcfg: ruleset read in %s%20s\n", el, "");

  ins_pg_on = 0;
}

static const char *dir_of (char t)
{
  switch (t)
  {
    case 'A': return "Alpha";
    case 'C': return "Capitalization";
    case 'D': return "Digits";
    case 'O': return "Other";
    case 'K': return "Keyboard";
    case 'X': return "Context";
    case 'Y': return "Years";
  }

  return NULL;
}

/* Context and Years all live in 1.txt: their entries vary in length. */
static int is_flat (char t)
{
  return ((t == 'X') || (t == 'Y')) ? 1 : 0;
}

static ins_list_t *list_get (const char *root, char t, int len)
{
  const char *d = dir_of (t);

  if (d == NULL) return NULL;
  if ((len < 0) || (len >= INS_MAXLIST)) return NULL;

  ins_list_t *L = &lists[(unsigned char) t][len];

  if (L->loaded != 0) return L;

  L->loaded = 1;

  char path[1024];

  snprintf (path, sizeof (path), "%s/%s/%d.txt", root, d, is_flat (t) ? 1 : len);

  FILE *f = fopen (path, "rb");

  if (f == NULL) return L;

  char line[PCFG_MAXLINE];

  int64_t seen = 0, sent = 0;

  while (fgets (line, sizeof (line), f) != NULL)
  {
    seen += (int64_t) strlen (line);

    /* Credited as it goes, not at the end: one list of this model is gigabytes
     * on its own, and a share that moves only at close sits at zero. */
    if ((seen - sent) >= (4 << 20))
    {
      ins_pg_add (seen - sent, "terminals");

      sent = seen;
    }

    char *tab = strrchr (line, '\t');

    if (tab == NULL) continue;

    *tab = 0;

    const int vlen = (int) strlen (line);

    const double p = strtod (tab + 1, NULL);

    L->entries++;
    L->prob_sum += p;

    if ((p > L->top_p) && (vlen < (int) sizeof (L->top)))
    {
      L->top_p = p;

      memcpy (L->top, line, (size_t) vlen);

      L->top[vlen] = 0;
    }

    for (int i = 0; i < vlen; i++)
    {
      const unsigned char c = (unsigned char) line[i];

      /* DEL is not here: it crosses the format intact and the trainer admits
       * it on purpose. What cannot be carried is the tab and the newline. */
      if (c < 0x20)
      {
        L->bad_byte++;
        break;
      }
    }

    /* The two trainers count characters differently - bytes under a declared
     * latin-1, codepoints where they are valid - so only neither reading is wrong. */
    if ((is_flat (t) == 0) && (vlen != len) && (utf8_cplen (line, vlen) != len)) L->bad_len++;
  }

  ins_pg_add (seen - sent, "terminals");

  fclose (f);

  return L;
}

typedef struct
{
  char text[128];
  double p;
  int len; /* characters it generates, -1 where a slot varies */
  int usable;
} ins_struct_t;

#define INS_KEEP 30

static ins_struct_t keep[INS_KEEP];
static int keep_n = 0;

static void keep_add (const char *text, double p, int len, int usable)
{
  int at = keep_n;

  if (keep_n < INS_KEEP)
    keep_n++;
  else
  {
    int worst = 0;

    for (int i = 1; i < INS_KEEP; i++)
      if (keep[i].p < keep[worst].p) worst = i;

    if (keep[worst].p >= p) return;

    at = worst;
  }

  snprintf (keep[at].text, sizeof (keep[at].text), "%s", text);

  keep[at].p      = p;
  keep[at].len    = len;
  keep[at].usable = usable;
}

static int keep_cmp (const void *a, const void *b)
{
  const ins_struct_t *x = (const ins_struct_t *) a;
  const ins_struct_t *y = (const ins_struct_t *) b;

  return (y->p > x->p) ? 1 : ((y->p < x->p) ? -1 : 0);
}

static void ins_config (const char *root, char *file, size_t fn, char *enc, size_t en,
                        char *prog, size_t pn, char *pver, size_t pvn, int64_t *pw)
{
  char path[1024];

  snprintf (file, fn, "%s", "?");
  snprintf (enc, en, "%s", "?");
  snprintf (prog, pn, "%s", "?");
  snprintf (pver, pvn, "%s", "");

  /* Not the same as zero. A ruleset without a config.ini has no count to report,
   * and printing "0 passwords" states a fact about the training nobody put there. */
  *pw = -1;

  snprintf (path, sizeof (path), "%s/config.ini", root);

  FILE *f = fopen (path, "rb");

  if (f == NULL) return;

  char line[1024];

  while (fgets (line, sizeof (line), f) != NULL)
  {
    char *eq = strchr (line, '=');

    if (eq == NULL) continue;

    char *v = eq + 1;

    while ((*v == ' ') || (*v == '\t')) v++;

    size_t len = strlen (v);

    while ((len > 0) && ((v[len - 1] == '\n') || (v[len - 1] == '\r') || (v[len - 1] == ' '))) v[--len] = 0;

    /* "filename" and not "filenames", which every section carries. */
    if ((strncmp (line, "filename", 8) == 0) && ((line[8] == ' ') || (line[8] == '=')))
      snprintf (file, fn, "%s", v);
    else if (strncmp (line, "encoding", 8) == 0)
      snprintf (enc, en, "%s", v);
    /* "program" and not "program_version": the prefix test took one for the other. */
    else if ((strncmp (line, "program", 7) == 0) && ((line[7] == ' ') || (line[7] == '=')))
      snprintf (prog, pn, "%s", v);
    /* The format's version, a claim about the layout rather than the trainer. */
    else if ((strncmp (line, "version", 7) == 0) && ((line[7] == ' ') || (line[7] == '=')))
      snprintf (pver, pvn, "%s", v);
    else if (strncmp (line, "number_of_passwords_in_set", 26) == 0)
      *pw = strtoll (v, NULL, 10);
  }

  fclose (f);
}

int hp_inspect (const char *root)
{
  char path[1024];

  ins_pg_begin (ins_bytes_of (root));

  snprintf (path, sizeof (path), "%s/Grammar/grammar.txt", root);

  FILE *f = fopen (path, "rb");

  if (f == NULL)
  {
    fprintf (stderr, "hpcfg: cannot read \"%s\"\n", path);
    return 1;
  }

  long structs = 0, unusable = 0;
  double mass = 0.0, mass_unusable = 0.0, mass_omen = 0.0;

  double bylen[64];

  memset (bylen, 0, sizeof (bylen));

  char worst[PCFG_MAXLINE] = "";
  double worst_mass        = 0.0;

  char line[PCFG_MAXLINE];

  while (fgets (line, sizeof (line), f) != NULL)
  {
    char *tab = strrchr (line, '\t');

    if (tab == NULL) continue;

    *tab = 0;

    const double p = strtod (tab + 1, NULL);

    structs++;
    mass += p;

    /* The M line is the OMEN escape: hashcat handles it apart, it is no token. */
    if ((line[0] == 'M') && (line[1] == 0))
    {
      mass_omen += p;

      keep_add (line, p, -2, 1); /* -2: the escape, which has no length */

      continue;
    }

    int bad  = 0;
    int glen = 0; /* characters this structure generates */

    for (const char *c = line; *c != 0;)
    {
      const char t = *c++;

      int len = 0;

      while ((*c >= '0') && (*c <= '9')) len = (len * 10) + (*c++ - '0');

      if ((len <= 0) || (dir_of (t) == NULL))
      {
        bad = 1;
        break;
      }

      ins_list_t *L = list_get (root, t, len);

      if ((L == NULL) || (L->entries == 0))
      {
        bad = 1;
        break;
      }

      /* How much of the grammar passes through this list. */
      L->used += p;

      /* Context and Years are one file, so a structure naming them says no length. */
      if (is_flat (t) != 0)
        glen = -1;
      else if (glen >= 0)
        glen += len;

      if (t == 'A')
      {
        ins_list_t *M = list_get (root, 'C', len);

        if ((M == NULL) || (M->entries == 0))
        {
          bad = 1;
          break;
        }

        M->used += p;
      }
    }

    keep_add (line, p, glen, (bad == 0) ? 1 : 0);

    if ((glen > 0) && (glen < 64) && (bad == 0)) bylen[glen] += p;

    if (bad != 0)
    {
      unusable++;
      mass_unusable += p;

      if (p > worst_mass)
      {
        worst_mass = p;
        snprintf (worst, sizeof (worst), "%s", line);
      }
    }
  }

  fclose (f);

  {
    char file[256], enc[64], prog[64], n1[32], n2[32];

    int64_t pw = 0;

    char pver[64];

    ins_config (root, file, sizeof (file), enc, sizeof (enc), prog, sizeof (prog),
                pver, sizeof (pver), &pw);

    long terms = 0, nlists = 0;

    for (int t = 0; t < 128; t++)
    {
      for (int l = 0; l < INS_MAXLIST; l++)
      {
        if (lists[t][l].entries == 0) continue;

        terms += lists[t][l].entries;
        nlists++;
      }
    }

    printf ("\n\n");
    ins_pg_end ();

    printf ("=== PCFG RULESET INSPECTOR ===\n");
    printf ("\n");
    printf ("  Ruleset     : %s\n", root);
    printf ("  Program     : %s%s%s\n", prog, (pver[0] != 0) ? " " : "", pver);
    if (pw < 0)
      printf ("  Trained     : not recorded, this ruleset has no config.ini\n");
    else
      printf ("  Trained     : %s passwords (%s)\n", hp_group (pw, n1, sizeof (n1)), file);
    printf ("  Encoding    : %s\n", enc);
    printf ("  Structures  : %s, escape takes %.3f%% of the mass\n",
            hp_group (structs, n1, sizeof (n1)), mass_omen * 100.0);
    printf ("  Terminals   : %s in %ld lists the structures reach\n",
            hp_group (terms, n2, sizeof (n2)), nlists);

    qsort (keep, (size_t) keep_n, sizeof (ins_struct_t), keep_cmp);

    const int top_n = (keep_n < 20) ? keep_n : 20;

    printf ("\n--- TOP %d STRUCTURES ---\n\n", top_n);
    printf ("    # | Pattern                      |     Length |       Prob |   Covered\n");
    printf ("  ----+------------------------------+------------+------------+----------\n");

    double cum = 0.0;

    for (int i = 0; i < top_n; i++)
    {
      cum += keep[i].p;

      char lb[16];

      if (keep[i].len == -2)
        snprintf (lb, sizeof (lb), "%s", "omen");
      else if (keep[i].len > 0)
        snprintf (lb, sizeof (lb), "%d", keep[i].len);
      else
        snprintf (lb, sizeof (lb), "%s", "varies");

      printf ("  %3d | %-28.28s | %10s | %9.3f%% |%9.3f%%%s\n", i + 1, keep[i].text, lb,
              keep[i].p * 100.0, cum * 100.0, (keep[i].usable == 0) ? "  <- unusable" : "");
    }

    printf ("  ----+------------------------------+------------+------------+----------\n");
    printf ("  Top %d coverage: %.3f%%\n", top_n, cum * 100.0);

    double lmass = 0.0;
    double peak  = 0.0;

    for (int i = 0; i < 64; i++)
    {
      lmass += bylen[i];

      if (bylen[i] > peak) peak = bylen[i];
    }

    if (lmass > 0.0)
    {
      printf ("\n--- GUESS LENGTH DISTRIBUTION ---\n\n");
      /* The bar ends where the length column above ends, so the shares line up. */
      printf ("  Len |###########################################|       Prob |\n");
      printf ("  ----+-------------------------------------------+------------+----------\n");

      for (int i = 1; i < 64; i++)
      {
        const double share = bylen[i] / lmass;

        if (share < 0.005) continue;

        char bar[256]; /* three bytes a block, plus the two pipes */

        hp_bar_block (bar, sizeof (bar), (bylen[i] / peak) * 100.0, 43);

        printf ("  %3d %s %9.3f%% |%s\n", i, bar, share * 100.0,
                (bylen[i] >= peak) ? " <- Peak" : "");
      }

      printf ("  ----+-------------------------------------------+------------+----------\n");
    }

    printf ("\n--- TERMINAL LISTS BY MASS ---\n\n");
    printf ("    # | List and its likeliest entry |    Entries |       Mass | Its share\n");
    printf ("  ----+------------------------------+------------+------------+----------\n");

    for (int shown = 0; shown < 12; shown++)
    {
      int bt = -1, bl = -1;

      double best = 0.0;

      for (int t = 0; t < 128; t++)
      {
        for (int l = 0; l < INS_MAXLIST; l++)
        {
          if (lists[t][l].entries == 0) continue;
          if (t == 'C') continue; /* a mask list carries its alpha list's mass, exactly */
          if (lists[t][l].used <= best) continue;

          best = lists[t][l].used;
          bt   = t;
          bl   = l;
        }
      }

      if (bt < 0) break;

      char name[32], ent[32];

      snprintf (name, sizeof (name), "%s/%d", dir_of ((char) bt), is_flat ((char) bt) ? 1 : bl);

      printf ("  %3d | %-18s %-9.9s | %10s | %9.3f%% |%9.3f%%\n", shown + 1, name,
              lists[bt][bl].top, hp_group (lists[bt][bl].entries, ent, sizeof (ent)),
              lists[bt][bl].used * 100.0, lists[bt][bl].top_p * 100.0);

      lists[bt][bl].used = 0.0; /* shown, take the next */
    }

    printf ("  ----+------------------------------+------------+------------+----------\n");

    /* The masks are a list per length like any other, but their mass is the
     * alpha mass by construction, so what matters is how skewed they are. */
    {
      printf ("  Case masks:");

      for (int l = 1, shown = 0; (l < INS_MAXLIST) && (shown < 4); l++)
      {
        if (lists[(unsigned char) 'C'][l].entries == 0) continue;

        printf ("%s %s %.3f%%", (shown > 0) ? "," : "",
                lists[(unsigned char) 'C'][l].top, lists[(unsigned char) 'C'][l].top_p * 100.0);

        shown++;
      }

      printf ("\n");
    }

    /* One per structure: the likeliest terminal in every slot. The true order
     * interleaves structures, but this is what each of them opens with. */
    typedef struct
    {
      char g[256];
      char from[128];
      double p;
    } ins_guess_t;

    ins_guess_t gl[INS_KEEP];

    int gn = 0;

    for (int i = 0; (i < keep_n) && (gn < INS_KEEP); i++)
    {
      if (keep[i].usable == 0) continue;
      if (keep[i].len == -2) continue;

      char guess[256];

      size_t at = 0;

      double p = keep[i].p;

      int ok = 1;

      for (const char *c = keep[i].text; (*c != 0) && (ok != 0);)
      {
        const char t = *c++;

        int len = 0;

        while ((*c >= '0') && (*c <= '9')) len = (len * 10) + (*c++ - '0');

        const ins_list_t *L = list_get (root, t, len);

        if ((L == NULL) || (L->top[0] == 0))
        {
          ok = 0;
          break;
        }

        p *= L->top_p;

        /* An alpha run is written lowered and the mask says the case. */
        if (t == 'A')
        {
          const ins_list_t *M = list_get (root, 'C', len);

          if ((M == NULL) || (M->top[0] == 0))
          {
            ok = 0;
            break;
          }

          p *= M->top_p;

          const char *w = L->top;

          for (int j = 0; (w[j] != 0) && (at + 1 < sizeof (guess)); j++)
          {
            const char m = (M->top[j] != 0) ? M->top[j] : 'L';

            guess[at++] = ((m == 'U') && (w[j] >= 'a') && (w[j] <= 'z')) ? (char) (w[j] - 32) : w[j];
          }
        }
        else
        {
          for (int j = 0; (L->top[j] != 0) && (at + 1 < sizeof (guess)); j++) guess[at++] = L->top[j];
        }
      }

      if (ok == 0) continue;

      guess[at] = 0;

      snprintf (gl[gn].g, sizeof (gl[gn].g), "%s", guess);
      snprintf (gl[gn].from, sizeof (gl[gn].from), "%s", keep[i].text);

      gl[gn].p = p;

      gn++;
    }

    for (int i = 0; i < gn; i++)
    {
      for (int j = i + 1; j < gn; j++)
      {
        if (gl[j].p > gl[i].p)
        {
          const ins_guess_t t = gl[i];

          gl[i] = gl[j];
          gl[j] = t;
        }
      }
    }

    if (gn > 0)
    {
      const int gshow = (gn < 12) ? gn : 12;

      printf ("\n--- MOST PROBABLE GUESSES ---\n\n");
      printf ("    # | Guess                        |       Prob |       From |    Length\n");
      printf ("  ----+------------------------------+------------+------------+----------\n");

      for (int i = 0; i < gshow; i++)
        printf ("  %3d | %-28.28s | %9.4f%% | %10.10s |%10d\n", i + 1, gl[i].g, gl[i].p * 100.0,
                gl[i].from, (int) strlen (gl[i].g));

      printf ("  ----+------------------------------+------------+------------+----------\n");
    }

    {
      char op[1024];

      snprintf (op, sizeof (op), "%s/Omen/config.txt", root);

      FILE *of = fopen (op, "rb");

      if (of != NULL)
      {
        char l2[256];

        int ngram = 0;

        char oenc[64] = "?";

        while (fgets (l2, sizeof (l2), of) != NULL)
        {
          char *eq = strchr (l2, '=');

          if (eq == NULL) continue;

          if (strstr (l2, "ngram") == l2)
            ngram = atoi (eq + 1);
          else if (strstr (l2, "encoding") == l2)
          {
            char *v = eq + 1;

            while ((*v == ' ') || (*v == '\t')) v++;

            snprintf (oenc, sizeof (oenc), "%s", v);

            size_t n = strlen (oenc);

            while ((n > 0) && ((oenc[n - 1] == '\n') || (oenc[n - 1] == '\r') || (oenc[n - 1] == ' '))) oenc[--n] = 0;
          }
        }

        fclose (of);

        long ip = 0, cp = 0;

        snprintf (op, sizeof (op), "%s/Omen/IP.level", root);
        of = fopen (op, "rb");
        if (of != NULL)
        {
          while (fgets (l2, sizeof (l2), of) != NULL) ip++;
          fclose (of);
        }

        snprintf (op, sizeof (op), "%s/Omen/CP.level", root);
        of = fopen (op, "rb");
        if (of != NULL)
        {
          while (fgets (l2, sizeof (l2), of) != NULL) cp++;
          fclose (of);
        }

        char n3[32], n4[32];

        printf ("\n--- OMEN ESCAPE ---\n\n");
        printf ("  Ngram       : %d\n", ngram);
        printf ("  Encoding    : %s\n", oenc);
        printf ("  Contexts    : %s\n", hp_group (ip, n3, sizeof (n3)));
        printf ("  Transitions : %s\n", hp_group (cp, n4, sizeof (n4)));

        /* Only the compat format writes the keyspace, so the table is driven by
         * what a level was trained on where it is missing. Both are shares of
         * their own total, and the header says which one is on show. */
        double pg[64];
        int64_t ks[64], tr[64];

        for (int i = 0; i < 64; i++)
        {
          pg[i] = 0.0;
          ks[i] = 0;
          tr[i] = 0;
        }

        snprintf (op, sizeof (op), "%s/Omen/pcfg_omen_prob.txt", root);
        of = fopen (op, "rb");

        const bool have_pg = (of != NULL);

        if (of != NULL)
        {
          while (fgets (l2, sizeof (l2), of) != NULL)
          {
            char *t3 = strchr (l2, '\t');

            if (t3 == NULL) continue;

            *t3 = 0;

            const int lv = atoi (l2);

            if ((lv >= 0) && (lv < 64)) pg[lv] = strtod (t3 + 1, NULL);
          }

          fclose (of);
        }

        snprintf (op, sizeof (op), "%s/Omen/omen_keyspace.txt", root);
        of = fopen (op, "rb");

        const bool have_ks = (of != NULL);

        if (of != NULL)
        {
          while (fgets (l2, sizeof (l2), of) != NULL)
          {
            char *tab = strchr (l2, '\t');

            if (tab == NULL) continue;

            *tab = 0;

            const int lv = atoi (l2);

            if ((lv >= 0) && (lv < 64)) ks[lv] = strtoll (tab + 1, NULL, 10);
          }

          fclose (of);
        }

        snprintf (op, sizeof (op), "%s/Omen/omen_pws_per_level.txt", root);
        of = fopen (op, "rb");

        if (of != NULL)
        {
          while (fgets (l2, sizeof (l2), of) != NULL)
          {
            char *tab = strchr (l2, '\t');

            if (tab == NULL) continue;

            *tab = 0;

            const int lv = atoi (l2);

            if ((lv >= 0) && (lv < 64)) tr[lv] = strtoll (tab + 1, NULL, 10);
          }

          fclose (of);
        }

        const int64_t *col = (have_ks == true) ? ks : tr;

        double col_total = 0.0, col_peak = 0.0;

        for (int i = 0; i < 64; i++)
        {
          col_total += (double) col[i];

          if ((double) col[i] > col_peak) col_peak = (double) col[i];
        }

        if ((have_pg == true) && (col_total > 0.0))
        {
          printf ("\n  Lvl | %28s |  Per guess |############|     Share\n",
                  (have_ks == true) ? "Guesses" : "Trained");
          printf ("  ----+------------------------------+------------+------------+----------\n");

          /* The escape stops at the level the keyspace was cut at, so above that
           * every guess is worth nothing and the rows carry no information. What
           * the corpus put up there is one line, because it is mass the escape
           * cannot reach and that is worth knowing. */
          int last = 0;

          for (int lv = 0; lv < 64; lv++)
            if (pg[lv] > 0.0) last = lv;

          char kb[64];

          for (int lv = 0; lv <= last; lv++)
          {
            if (col[lv] == 0) continue;

            char bar[256];

            hp_bar_block (bar, sizeof (bar),
                          (col_peak > 0.0) ? (((double) col[lv] / col_peak) * 100.0) : 0.0, 12);

            printf ("  %3d | %28s | %10.2e %s%9.3f%%\n", lv, hp_group (col[lv], kb, sizeof (kb)),
                    pg[lv], bar, ((double) col[lv] / col_total) * 100.0);
          }

          printf ("  ----+------------------------------+------------+------------+----------\n");

          double tail = 0.0;

          int tail_hi = last;

          for (int lv = last + 1; lv < 64; lv++)
          {
            if (col[lv] == 0) continue;

            tail += (double) col[lv];

            tail_hi = lv;
          }

          if (tail > 0.0)
            printf ("  Levels %d to %d hold %.3f%% more, past where the escape generates "
                    "(--omen-level-max)\n",
                    last + 1, tail_hi, (tail / col_total) * 100.0);
        }
      }
    }
  }

  long tot_badlen = 0, tot_badbyte = 0, empty_used = 0;

  int shown_bad = 0; /* the table's header, printed only if it has a row */

  int bad_rank = 0;

  for (int t = 0; t < 128; t++)
  {
    if (dir_of ((char) t) == NULL) continue;

    for (int l = 0; l < INS_MAXLIST; l++)
    {
      const ins_list_t *L = &lists[t][l];

      if (L->loaded == 0) continue;

      tot_badlen += L->bad_len;
      tot_badbyte += L->bad_byte;

      if (L->entries == 0)
      {
        empty_used++;
        continue;
      }

      const int odd = ((L->prob_sum < 0.99) || (L->prob_sum > 1.01) ||
                       (L->bad_len > 0) || (L->bad_byte > 0))
                          ? 1
                          : 0;

      if ((odd != 0) || (l == 0) || (((char) t == 'K') && (l < 4)))
      {
        char name[32];

        snprintf (name, sizeof (name), "%s/%d", dir_of ((char) t), l);

        if (shown_bad == 0)
        {
          printf ("\n--- LISTS WITH ANOMALIES ---\n\n");
          printf ("    # | List                         |    Entries |        Sum |Len / byte\n");
          printf ("  ----+------------------------------+------------+------------+----------\n");

          shown_bad = 1;
        }

        printf ("  %3d | %-28.28s | %10ld | %10.6f |%5d /%4d%s\n", ++bad_rank, name, L->entries,
                L->prob_sum, L->bad_len, L->bad_byte,
                (l == 0) ? "   <-- zero length" : ((((char) t == 'K') && (l < 4)) ? "   <-- walk shorter than 4" : ""));
      }
    }
  }

  /* A last field that is a count rather than a share reads as an enormous
   * probability, and every product across sections then ranks nothing. */
  long notprob = 0;

  double worst_sum = 1.0;

  char worst_list[64] = "";

  for (int t = 0; t < 128; t++)
  {
    for (int l = 0; l < INS_MAXLIST; l++)
    {
      const ins_list_t *L = &lists[t][l];

      if (L->entries == 0) continue;

      const int off = ((L->prob_sum < 0.99) || (L->prob_sum > 1.01) || (L->top_p > 1.0)) ? 1 : 0;

      if (off == 0) continue;

      notprob++;

      if (((L->prob_sum > 1.0) ? L->prob_sum : (1.0 / L->prob_sum)) >
          ((worst_sum > 1.0) ? worst_sum : (1.0 / worst_sum)))
      {
        worst_sum = L->prob_sum;

        snprintf (worst_list, sizeof (worst_list), "%s/%d", dir_of ((char) t), is_flat ((char) t) ? 1 : l);
      }
    }
  }

  const int grammar_off = ((mass < 0.99) || (mass > 1.01)) ? 1 : 0;

  if (shown_bad != 0)
    printf ("  ----+------------------------------+------------+------------+----------\n");

  printf ("\n--- CHECKS ---\n\n");
  printf ("  %-60s | %9s\n", "Check", "Count");
  printf ("  -------------------------------------------------------------+----------\n");
  printf ("  %-60s | %9ld\n", "Structures a reader cannot use", unusable);

  if (unusable > 0)
    printf ("  %-60s | %.3f%% of the mass, heaviest %s\n", "", mass_unusable * 100.0, worst);

  printf ("  %-60s | %9ld\n", "Lists named but empty or absent", empty_used);
  printf ("  %-60s | %9ld\n", "Entries of the wrong length", tot_badlen);
  printf ("  %-60s | %9ld\n", "Entries the format cannot carry", tot_badbyte);
  printf ("  %-60s | %9ld\n", "Lists whose shares are not shares", notprob);

  if (notprob > 0)
    printf ("  %-60s | heaviest %s, summing to %.6g\n", "", worst_list, worst_sum);

  if ((mass < 0.99) || (mass > 1.01))
    printf ("  %-60s | %9.6g   <- should be 1\n", "The grammar sums to", mass);
  else
    printf ("  %-60s | %9.6f\n", "The grammar sums to", mass);

  printf ("  -------------------------------------------------------------+----------\n");

  const int ok = ((unusable == 0) && (empty_used == 0) && (tot_badlen == 0) && (tot_badbyte == 0) && (notprob == 0) && (grammar_off == 0)) ? 1 : 0;

  printf ("  %s\n\n", (ok != 0) ? "No anomalies" : "Anomalies above");

  return (ok != 0) ? 0 : 1;
}

typedef struct
{
  char *val;
  double p;
} ins_ent_t;

typedef struct
{
  ins_ent_t *v;
  long n;
  char *arena;
  size_t used, cap;
} ins_file_t;

static int ins_ent_cmp (const void *a, const void *b)
{
  return strcmp (((const ins_ent_t *) a)->val, ((const ins_ent_t *) b)->val);
}

static void ins_file_free (ins_file_t *f)
{
  free (f->v);
  free (f->arena);

  f->v     = NULL;
  f->arena = NULL;
  f->n     = 0;
}

/* A value/probability file, sorted so two of them can be walked together. */
static int ins_file_load (const char *path, ins_file_t *f)
{
  memset (f, 0, sizeof (*f));

  FILE *fp = fopen (path, "rb");

  if (fp == NULL) return 1;

  char line[PCFG_MAXLINE];

  int64_t seen = 0, sent = 0;

  long cap = 1024;

  f->v = (ins_ent_t *) malloc ((size_t) cap * sizeof (ins_ent_t));

  if (f->v == NULL)
  {
    fclose (fp);

    return 1;
  }

  while (fgets (line, sizeof (line), fp) != NULL)
  {
    seen += (int64_t) strlen (line);

    if ((seen - sent) >= (4 << 20))
    {
      ins_pg_add (seen - sent, "grammar");

      sent = seen;
    }

    char *tab = strrchr (line, '\t');

    if (tab == NULL) continue;

    *tab = 0;

    const double p    = strtod (tab + 1, NULL);
    const size_t vlen = strlen (line);

    if (p <= 0.0) continue;

    if ((f->used + vlen + 1) > f->cap)
    {
      size_t want = (f->cap == 0) ? (1u << 20) : (f->cap * 2);

      while (want < (f->used + vlen + 1)) want *= 2;

      char *na = (char *) realloc (f->arena, want);

      if (na == NULL) break;

      /* The arena moved, so the pointers into it move with it. */
      for (long i = 0; i < f->n; i++) f->v[i].val = na + (f->v[i].val - f->arena);

      f->arena = na;
      f->cap   = want;
    }

    if (f->n == cap)
    {
      cap *= 2;

      ins_ent_t *nv = (ins_ent_t *) realloc (f->v, (size_t) cap * sizeof (ins_ent_t));

      if (nv == NULL) break;

      f->v = nv;
    }

    memcpy (f->arena + f->used, line, vlen + 1);

    f->v[f->n].val = f->arena + f->used;
    f->v[f->n].p   = p;

    f->used += vlen + 1;
    f->n++;
  }

  ins_pg_add (seen - sent, "grammar");

  fclose (fp);

  qsort (f->v, (size_t) f->n, sizeof (ins_ent_t), ins_ent_cmp);

  return 0;
}

/* Returns the shared mass and fills in what only one of the two files has. */
static double ins_shared (const ins_file_t *a, const ins_file_t *b,
                          long *only_a, long *only_b, double *mass_a, double *mass_b)
{
  double shared = 0.0;

  long i = 0, j = 0;

  if (only_a != NULL) *only_a = 0;
  if (only_b != NULL) *only_b = 0;
  if (mass_a != NULL) *mass_a = 0.0;
  if (mass_b != NULL) *mass_b = 0.0;

  while ((i < a->n) && (j < b->n))
  {
    const int c = strcmp (a->v[i].val, b->v[j].val);

    if (c == 0)
    {
      shared += (a->v[i].p < b->v[j].p) ? a->v[i].p : b->v[j].p;

      i++;
      j++;
    }
    else if (c < 0)
    {
      if (only_a != NULL) (*only_a)++;
      if (mass_a != NULL) *mass_a += a->v[i].p;

      i++;
    }
    else
    {
      if (only_b != NULL) (*only_b)++;
      if (mass_b != NULL) *mass_b += b->v[j].p;

      j++;
    }
  }

  for (; i < a->n; i++)
  {
    if (only_a != NULL) (*only_a)++;
    if (mass_a != NULL) *mass_a += a->v[i].p;
  }

  for (; j < b->n; j++)
  {
    if (only_b != NULL) (*only_b)++;
    if (mass_b != NULL) *mass_b += b->v[j].p;
  }

  return shared;
}

static void ins_moves (const ins_file_t *a, const ins_file_t *b, int top, const char *what)
{
  typedef struct
  {
    const char *v;
    double pa, pb, d;
  } mv_t;

  mv_t best[24];

  int n = 0;

  long i = 0, j = 0;

  while ((i < a->n) || (j < b->n))
  {
    const char *v;

    double pa = 0.0, pb = 0.0;

    if ((i < a->n) && (j < b->n))
    {
      const int c = strcmp (a->v[i].val, b->v[j].val);

      if (c == 0)
      {
        v  = a->v[i].val;
        pa = a->v[i].p;
        pb = b->v[j].p;
        i++;
        j++;
      }
      else if (c < 0)
      {
        v  = a->v[i].val;
        pa = a->v[i].p;
        i++;
      }
      else
      {
        v  = b->v[j].val;
        pb = b->v[j].p;
        j++;
      }
    }
    else if (i < a->n)
    {
      v  = a->v[i].val;
      pa = a->v[i].p;
      i++;
    }
    else
    {
      v  = b->v[j].val;
      pb = b->v[j].p;
      j++;
    }

    const double d = (pa > pb) ? (pa - pb) : (pb - pa);

    int at = n;

    if (n < top)
      n++;
    else
    {
      int worst = 0;

      for (int k = 1; k < n; k++)
        if (best[k].d < best[worst].d) worst = k;

      if (best[worst].d >= d) continue;

      at = worst;
    }

    best[at].v  = v;
    best[at].pa = pa;
    best[at].pb = pb;
    best[at].d  = d;
  }

  if (n == 0) return;

  for (int x = 0; x < n; x++)
    for (int y = x + 1; y < n; y++)
      if (best[y].d > best[x].d)
      {
        const mv_t t = best[x];

        best[x] = best[y];
        best[y] = t;
      }

  printf ("\n    # | %-28s |          A |          B |      Move\n", what);
  printf ("  ----+------------------------------+------------+------------+----------\n");

  for (int x = 0; x < n; x++)
    printf ("  %3d | %-28.28s | %9.3f%% | %9.3f%% |%+10.3f\n", x + 1, best[x].v,
            best[x].pa * 100.0, best[x].pb * 100.0, (best[x].pb - best[x].pa) * 100.0);

  printf ("  ----+------------------------------+------------+------------+----------\n");
}

int hp_diff (const char *a, const char *b)
{
  char pa[1024], pb[1024];

  ins_pg_begin (ins_grammar_bytes (a) + ins_grammar_bytes (b));

  ins_file_t ga, gb;

  snprintf (pa, sizeof (pa), "%s/Grammar/grammar.txt", a);
  snprintf (pb, sizeof (pb), "%s/Grammar/grammar.txt", b);

  if ((ins_file_load (pa, &ga) != 0) || (ins_file_load (pb, &gb) != 0))
  {
    fprintf (stderr, "hpcfg: cannot read both grammars\n");

    return 1;
  }

  char fa[256], ea[64], wa[64], va[64], fb[256], eb[64], wb[64], vb[64], n1[32], n2[32], n3[32], n4[32];

  int64_t pwa = 0, pwb = 0;

  ins_config (a, fa, sizeof (fa), ea, sizeof (ea), wa, sizeof (wa), va, sizeof (va), &pwa);
  ins_config (b, fb, sizeof (fb), eb, sizeof (eb), wb, sizeof (wb), vb, sizeof (vb), &pwb);

  printf ("\n\n");
  ins_pg_end ();

  printf ("=== PCFG RULESET DIFF ===\n");
  printf ("\n");
  printf ("  A : %s\n", a);
  printf ("      %s, %s passwords, %s structures, %s\n", wa,
          (pwa < 0) ? "an unrecorded number of" : hp_group (pwa, n1, sizeof (n1)),
          hp_group (ga.n, n3, sizeof (n3)), fa);
  printf ("  B : %s\n", b);
  printf ("      %s, %s passwords, %s structures, %s\n", wb,
          (pwb < 0) ? "an unrecorded number of" : hp_group (pwb, n2, sizeof (n2)),
          hp_group (gb.n, n4, sizeof (n4)), fb);

  long oa = 0, ob = 0;

  double ma = 0.0, mb = 0.0;

  const double shared = ins_shared (&ga, &gb, &oa, &ob, &ma, &mb);

  printf ("\n--- STRUCTURES ---\n\n");
  printf ("  Shared mass : %7.3f%%\n", shared * 100.0);
  printf ("  Only in A   : %s structures, %.3f%% of the mass\n",
          hp_group (oa, n3, sizeof (n3)), ma * 100.0);
  printf ("  Only in B   : %s structures, %.3f%% of the mass\n",
          hp_group (ob, n4, sizeof (n4)), mb * 100.0);

  ins_moves (&ga, &gb, 15, "Pattern");

  ins_file_free (&ga);
  ins_file_free (&gb);

  printf ("\n--- TERMINAL LISTS ---\n\n");
  printf ("    # | List                         |  A entries |  B entries |    Shared\n");
  printf ("  ----+------------------------------+------------+------------+----------\n");

  static const char types[] = "ACDOKXY";

  double worst_shared = 1.0;

  int rank = 0;

  char worst_name[64] = "";

  long worst_a = 0, worst_b = 0;

  for (int t = 0; types[t] != 0; t++)
  {
    for (int l = 0; l < INS_MAXLIST; l++)
    {
      ins_file_t la, lb;

      snprintf (pa, sizeof (pa), "%s/%s/%d.txt", a, dir_of (types[t]), is_flat (types[t]) ? 1 : l);
      snprintf (pb, sizeof (pb), "%s/%s/%d.txt", b, dir_of (types[t]), is_flat (types[t]) ? 1 : l);

      const int ra = ins_file_load (pa, &la);
      const int rb = ins_file_load (pb, &lb);

      if ((ra != 0) && (rb != 0))
      {
        ins_file_free (&la);
        ins_file_free (&lb);
        continue;
      }

      if ((la.n > 0) || (lb.n > 0))
      {
        const double sh = ins_shared (&la, &lb, NULL, NULL, NULL, NULL);

        char name[32], ca[32], cb[32];

        snprintf (name, sizeof (name), "%s/%d", dir_of (types[t]), is_flat (types[t]) ? 1 : l);

        printf ("  %3d | %-28.28s | %10s | %10s |%9.3f%%\n", ++rank, name,
                hp_group (la.n, ca, sizeof (ca)), hp_group (lb.n, cb, sizeof (cb)), sh * 100.0);

        if (sh < worst_shared)
        {
          worst_shared = sh;
          worst_a      = la.n;
          worst_b      = lb.n;

          snprintf (worst_name, sizeof (worst_name), "%s", name);
        }
      }

      ins_file_free (&la);
      ins_file_free (&lb);

      if (is_flat (types[t]) != 0) break; /* one file for every length */
    }
  }

  printf ("  ----+------------------------------+------------+------------+----------\n");

  /* With the entry counts: the least agreement is usually one or two rare things. */
  if (worst_name[0] != 0)
  {
    char ca[32], cb[32];

    printf ("  Least agreement: %s at %.3f%%, %s %s against %s\n", worst_name,
            worst_shared * 100.0, hp_group (worst_a, ca, sizeof (ca)),
            (worst_a == 1) ? "entry" : "entries", hp_group (worst_b, cb, sizeof (cb)));
  }

  {
    ins_file_t ka, kb;

    snprintf (pa, sizeof (pa), "%s/Omen/pcfg_omen_prob.txt", a);
    snprintf (pb, sizeof (pb), "%s/Omen/pcfg_omen_prob.txt", b);

    if ((ins_file_load (pa, &ka) == 0) && (ins_file_load (pb, &kb) == 0) && (ka.n > 0) && (kb.n > 0))
    {
      printf ("\n--- OMEN ESCAPE ---\n\n");
      printf ("  Lvl |##############################|          A |          B |     B / A\n");
      printf ("  ----+------------------------------+------------+------------+----------\n");

      for (int lv = 0; lv < 64; lv++)
      {
        char key[16];

        snprintf (key, sizeof (key), "%d", lv);

        double va = 0.0, vb = 0.0;

        for (long i = 0; i < ka.n; i++)
          if (strcmp (ka.v[i].val, key) == 0) va = ka.v[i].p;
        for (long i = 0; i < kb.n; i++)
          if (strcmp (kb.v[i].val, key) == 0) vb = kb.v[i].p;

        if ((va == 0.0) && (vb == 0.0)) continue;

        /* In decades: down the levels both probabilities fall by orders of
         * magnitude, so their ratio says what their difference cannot. */
        char ratio[16] = "-";

        double apart = 100.0;

        if ((va > 0.0) && (vb > 0.0))
        {
          const double r = vb / va;

          if ((r >= 1000.0) || (r < 0.001))
            snprintf (ratio, sizeof (ratio), "%.1ex", r);
          else
            snprintf (ratio, sizeof (ratio), "%.2fx", r);

          double x = (r >= 1.0) ? r : (1.0 / r);

          int dec = 0;

          while ((x >= 10.0) && (dec < 6))
          {
            x /= 10.0;
            dec++;
          }

          apart = (((double) dec + ((x - 1.0) / 9.0)) / 6.0) * 100.0;
        }

        char bar[256];

        hp_bar_block (bar, sizeof (bar), apart, 30);

        printf ("  %3d %s %10.2e | %10.2e |%10s\n", lv, bar, va, vb, ratio);
      }

      printf ("  ----+------------------------------+------------+------------+----------\n");
    }

    ins_file_free (&ka);
    ins_file_free (&kb);
  }

  printf ("\n");

  return 0;
}
