/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * Hpcfg, a high-performance PCFG trainer.
 */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pcfg_platform.h"
#include "pcfg_common.h"
#include "pcfg_ruleset.h"
#include "pcfg_ruleset_inspect.h"
#include "pcfg_trainer.h"

/* Both spellings of every option. */
static const struct option hp_long[] = {
  /* The names follow hashcat-pcfg-dev's: a domain, the subject, then a qualifier
   * from a closed set. The noun is "ruleset", what all three readers call it. */
  { "train",                  required_argument, NULL, 't' },
  { "ruleset-save",           required_argument, NULL, 'g' },
  { "ruleset-info",           required_argument, NULL, 'i' },
  { "ruleset-diff",           required_argument, NULL, '5' },
  { "ruleset-format",         required_argument, NULL, '9' },
  { "rulesets-merge",         required_argument, NULL, 'R' },
  { "rulesets-merge-weights", required_argument, NULL, 'W' },

  { "weighted",               no_argument,       NULL, 'w' },
  { "sep",                    required_argument, NULL, 's' },
  { "count-min",              required_argument, NULL, 'L' },
  { "admission-min",          required_argument, NULL, 'A' },
  { "df-disable",             no_argument,       NULL, 'J' },
  { "sensitive-enable",       no_argument,       NULL, 'S' },
  { "multiword-disable",      no_argument,       NULL, '4' },
  { "mw-file",                required_argument, NULL, 'm' },
  { "mw-save",                required_argument, NULL, 'D' },
  { "mw-threshold",           required_argument, NULL, '1' },
  { "mw-len-min",             required_argument, NULL, '2' },
  { "mw-len-max",             required_argument, NULL, '3' },

  { "terminal-count-min",     required_argument, NULL, 'f' },

  { "omen-ngram",             required_argument, NULL, 'n' },
  { "omen-alphabet",          required_argument, NULL, 'a' },
  { "omen-alphabet-save",     required_argument, NULL, 'B' },
  { "omen-alphabet-file",     required_argument, NULL, 'U' },
  { "omen-level-max",         required_argument, NULL, '7' },

  { "coverage",               required_argument, NULL, 'c' },
  { "memory-max",             required_argument, NULL, 'M' },
  { "threads",                required_argument, NULL, 'T' },
  { "comments",               required_argument, NULL, 'C' },
  { "encoding",               required_argument, NULL, 'e' },
  { "verbose",                no_argument,       NULL, 'v' },
  { "version",                no_argument,       NULL, '8' },
  { "help",                   no_argument,       NULL, 'h' },

  { "training",               required_argument, NULL, 't' },
  { "ruleset",                required_argument, NULL, 'g' },
  { "inspect",                required_argument, NULL, 'i' },
  { "diff",                   required_argument, NULL, '5' },
  { "format",                 required_argument, NULL, '9' },
  { "merge",                  required_argument, NULL, 'R' },
  { "weights",                required_argument, NULL, 'W' },
  { "min",                    required_argument, NULL, 'L' },
  { "admit",                  required_argument, NULL, 'A' },
  { "af-threshold",           required_argument, NULL, 'A' },
  { "keep-junk",              no_argument,       NULL, 'J' },
  { "save-sensitive",         no_argument,       NULL, 'S' },
  { "no-multiword",           no_argument,       NULL, '4' },
  { "multiword",              required_argument, NULL, 'm' },
  { "save-multiword",         required_argument, NULL, 'D' },
  { "mw-min-len",             required_argument, NULL, '2' },
  { "mw-max-len",             required_argument, NULL, '3' },
  { "min-count",              required_argument, NULL, 'f' },
  { "ngram",                  required_argument, NULL, 'n' },
  { "alphabet",               required_argument, NULL, 'a' },
  { "save-alphabet",          required_argument, NULL, 'B' },
  { "use-alphabet",           required_argument, NULL, 'U' },
  { "memory",                 required_argument, NULL, 'M' },
  { NULL,                     0,                 NULL, 0   }
};

static void usage (FILE *out)
{
  fprintf (out,
           "hpcfg " HP_VERSION " - High-Performance PCFG trainer\n"
           "\n"
           "Usage: hpcfg --train <wordlist> --ruleset-save <dir> [options]...\n"
           "\n"
           "- [ Training ] -\n"
           "\n"
           " Options Short / Long           | Type | Description                                          | Example\n"
           "================================+======+======================================================+=======================\n"
           " -t, --train                    | File | Wordlist to train on, or - for stdin                 | -t rockyou.txt\n"
           " -w, --weighted                 |      | Every line is <count><sep><password>                 |\n"
           " -s, --sep                      | Char | Bytes between the count and the password (default :) | --sep=\" \"\n"
           "     --count-min                | Num  | With --weighted, skip a line counted below X         | --count-min=5\n"
           "     --admission-min            | Num  | A terminal earns a slot only once seen X times       | --admission-min=3\n"
           " -J, --df-disable               |      | Keep the lines the filters take for hashes and keys  |\n"
           " -S, --sensitive-enable         |      | Also write the addresses and the URLs themselves     |\n"
           "\n"
           "- [ Multiword ] -\n"
           "\n"
           " Options Short / Long           | Type | Description                                          | Example\n"
           "================================+======+======================================================+=======================\n"
           " -m, --mw-file                  | File | Words to know before the corpus is read              | -m words.txt\n"
           "     --mw-save                  | File | Write the words this run found, for a split run      | --mw-save=words.txt\n"
           "     --mw-threshold             | Num  | Times a word must be seen to split a run on it (5)   | --mw-threshold=5\n"
           "     --mw-len-min               | Num  | Shortest run the splitting applies to (4)            | --mw-len-min=4\n"
           "     --mw-len-max               | Num  | Longest run the splitting applies to (21)            | --mw-len-max=21\n"
           "     --multiword-disable        |      | Do not split compound runs at all                    |\n"
           "\n"
           "- [ Model ] -\n"
           "\n"
           " Options Short / Long           | Type | Description                                          | Example\n"
           "================================+======+======================================================+=======================\n"
           " -c, --coverage                 | Num  | Share of the guessing the grammar takes (0.6)        | -c 0.6\n"
           " -f, --terminal-count-min       | Num  | Drop terminals seen fewer than X times               | -f 5\n"
           " -n, --omen-ngram               | Num  | OMEN n-gram size, 2 to 5 (default 4)                 | -n 4\n"
           " -a, --omen-alphabet            | Num  | OMEN alphabet size (default 100)                     | -a 100\n"
           "     --omen-alphabet-save       | File | The byte frequencies the alphabet is chosen from     | --omen-alphabet-save=a.txt\n"
           "     --omen-alphabet-file       | File | Use those frequencies rather than this corpus own    | --omen-alphabet-file=a.txt\n"
           "     --omen-level-max           | Num  | Deepest OMEN keyspace level, 1 to 40 (default 18)    | --omen-level-max=40\n"
           "\n"
           "- [ Ruleset ] -\n"
           "\n"
           " Options Short / Long           | Type | Description                                          | Example\n"
           "================================+======+======================================================+=======================\n"
           " -g, --ruleset-save             | Dir  | Where to write it                                    | -g rules/rockyou\n"
           "     --ruleset-format           | Str  | Who it is for: hashcat (default) or pcfg-cracker     | --ruleset-format=pcfg-cracker\n"
           " -i, --ruleset-info             | Dir  | Read one back: what it holds and what is wrong       | -i rules/rockyou\n"
           "     --ruleset-diff             | Dir  | With --ruleset-info, the mass two of them share      | --ruleset-diff=rules/other\n"
           "     --rulesets-merge           | Dir  | Fold it into the one --ruleset-save names            | --rulesets-merge=rules/a\n"
           "     --rulesets-merge-weights   | Str  | The share each merged ruleset takes, not its size    | --rulesets-merge-weights=1:2\n"
           " -C, --comments                 | Str  | A note to carry in config.ini                        | -C \"hibp full\"\n"
           " -e, --encoding                 | Str  | What to tell a reader the values are in              | -e utf-8\n"
           "\n"
           "- [ Run ] -\n"
           "\n"
           " Options Short / Long           | Type | Description                                          | Example\n"
           "================================+======+======================================================+=======================\n"
           " -M, --memory-max               | Num  | A ceiling on all that grows with the corpus          | -M 8G\n"
           " -T, --threads                  | Num  | Threads counting (default: the machine cores)        | -T 20\n"
           " -v, --verbose                  |      | Report what each pass costs                          |\n"
           "     --version                  |      | Print version and the ruleset format it writes       |\n"
           " -h, --help                     |      | Print help                                           |\n"
           "\n"
           "- [ Notes ] -\n"
           "\n"
           "The ruleset is the directory hashcat, pcfg_cracker and pcfg-go all read: the grammar,\n"
           "its terminals, and the OMEN escape that covers whatever the grammar does not.\n"
           "\n"
           "Without --memory-max, a figure taken from free memory decides only when the counters\n"
           "spill to disk, which loses nothing. Given, it is a ceiling: past it the tables that\n"
           "cannot spill refuse new keys, and the run says what that cost.\n");
}

/* atoi and atof answer 0 for a string that is no number at all. For --coverage
 * that was silent: 0 means "OMEN alone", so a mistyped 0.6 threw the grammar out. */
static bool hp_read_int (const char *s, const char *opt, long long *out)
{
  char *end = NULL;

  errno = 0;

  const long long v = strtoll (s, &end, 10);

  if ((end == s) || (*end != '\0') || (errno == ERANGE))
  {
    fprintf (stderr, "hpcfg: %s %s is not a number\n", opt, s);

    return false;
  }

  *out = v;

  return true;
}

static bool hp_read_dbl (const char *s, const char *opt, double *out)
{
  char *end = NULL;

  errno = 0;

  const double v = strtod (s, &end);

  if ((end == s) || (*end != '\0'))
  {
    fprintf (stderr, "hpcfg: %s %s is not a number\n", opt, s);

    return false;
  }

  *out = v;

  return true;
}

int main (int argc, char **argv)
{
  hp_opts_t o;

  memset (&o, 0, sizeof (o));

  o.sep        = ":";
  o.ngram      = 4;
  o.alpha      = 100;
  o.coverage   = 0.6;
  o.format     = HP_FMT_HASHCAT;
  o.budget_set = false;

  const char *inspect = NULL;
  const char *diff    = NULL;
  const char *wspec   = NULL;

  char *merge[64];
  int nmerge = 0;

  int c;

  long long nv = 0;
  double dv    = 0.0;

  while ((c = getopt_long (argc, argv, "t:g:i:m:ws:f:n:a:c:C:M:T:e:vSJh", hp_long, NULL)) != -1)
  {
    switch (c)
    {
      case 't': o.infile = optarg; break;
      case 'g': o.outdir = optarg; break;
      case 'w': o.weighted = true; break;
      case 's': o.sep = optarg; break;
      case 'f':
        if (hp_read_int (optarg, "--terminal-count-min", &nv) == false) return 1;
        o.admit = nv;
        break;
      case 'n':
        if (hp_read_int (optarg, "--omen-ngram", &nv) == false) return 1;
        o.ngram = (int) nv;
        if ((o.ngram < 2) || (o.ngram > 5))
        {
          fprintf (stderr, "hpcfg: --omen-ngram %s is outside 2 to 5\n", optarg);

          return 1;
        }
        break;
      case 'a':
        if (hp_read_int (optarg, "--omen-alphabet", &nv) == false) return 1;
        o.alpha = (int) nv;
        break;
      case '7':
        if (hp_read_int (optarg, "--omen-level-max", &nv) == false) return 1;
        if ((nv < 1) || (nv > 40))
        {
          fprintf (stderr, "hpcfg: --omen-level-max %s is outside 1 to 40\n", optarg);

          return 1;
        }
        o.ks_max = (int) nv;
        break;
      case 'c':
        if (hp_read_dbl (optarg, "--coverage", &dv) == false) return 1;
        o.coverage = dv;
        break;
      case '9':
        if (strcmp (optarg, "hashcat") == 0)
          o.format = HP_FMT_HASHCAT;
        else if ((strcmp (optarg, "pcfg-cracker") == 0) || (strcmp (optarg, "pcfg_cracker") == 0))
          o.format = HP_FMT_CRACKER;
        else
        {
          fprintf (stderr, "hpcfg: --ruleset-format %s is neither \"hashcat\" nor \"pcfg-cracker\"\n", optarg);

          return 1;
        }
        break;
      case 'M':
      {
        char *end = NULL;

        const double v = strtod (optarg, &end);

        /* A size that cannot be read is not a size. It used to fall through as
         * zero, so "-M abc" quietly trained with whatever the machine had. */
        if ((end == optarg) || (v < 0.0))
        {
          fprintf (stderr, "hpcfg: --memory-max %s is not a size; give bytes, or a number with K, M or G\n", optarg);

          return 1;
        }

        double bytes = v;

        if ((*end == 'G') || (*end == 'g'))
          bytes *= 1024.0 * 1024.0 * 1024.0;
        else if ((*end == 'M') || (*end == 'm'))
          bytes *= 1024.0 * 1024.0;
        else if ((*end == 'K') || (*end == 'k'))
          bytes *= 1024.0;
        else if (*end != 0)
        {
          fprintf (stderr, "hpcfg: --memory-max %s ends in \"%s\", which is not K, M or G\n", optarg, end);

          return 1;
        }

        o.budget     = (size_t) bytes;
        o.budget_set = true;

        break;
      }
      case 'A':
        if (hp_read_int (optarg, "--admission-min", &nv) == false) return 1;
        o.seen = (int) nv;
        break;
      case 'T':
        if (hp_read_int (optarg, "--threads", &nv) == false) return 1;
        o.threads = (int) nv;
        break;
      case 'v': o.verbose = true; break;
      case 'i': inspect = optarg; break;
      case 'm': o.dict = optarg; break;
      case 'C': o.comments = optarg; break;
      case 'D': o.dict_out = optarg; break;
      case 'B': o.freq_out = optarg; break;
      case '1':
        if (hp_read_int (optarg, "--mw-threshold", &nv) == false) return 1;
        o.mw_thr = (int) nv;
        break;
      case '2':
        if (hp_read_int (optarg, "--mw-len-min", &nv) == false) return 1;
        o.mw_min = (int) nv;
        break;
      case '3':
        if (hp_read_int (optarg, "--mw-len-max", &nv) == false) return 1;
        o.mw_max = (int) nv;
        break;
      case '4': o.mw_off = true; break;
      case '5': diff = optarg; break;
      case '6': o.comments = optarg; break;
      case 'e': o.encoding = optarg; break;

      case '8':
        /* The layout is the 4.x one whatever the format; only config.ini differs. */
        printf ("hpcfg %s - High-Performance PCFG trainer\n", HP_VERSION);
        printf ("writes the Weir 4.x ruleset layout; --ruleset-format pcfg-cracker "
                "declares version 4.7 in config.ini\n");
        return 0;
      case 'U': o.freq_in = optarg; break;
      case 'L':
        if (hp_read_int (optarg, "--count-min", &nv) == false) return 1;
        o.mincount = nv;
        break;
      case 'S': o.sensitive = true; break;

      case 'R':
        if (nmerge < 64)
          merge[nmerge++] = optarg;
        else
        {
          fprintf (stderr, "hpcfg: at most 64 rulesets can be merged at once\n");

          return 1;
        }
        break;

      case 'W': wspec = optarg; break;
      case 'J': o.keep_junk = true; break;
      case 'h': usage (stdout); return 0;
      default: usage (stderr); return 1;
    }
  }

  /* Reading a ruleset back needs no corpus and trains nothing, so it ends here. */
  if ((inspect != NULL) && (diff != NULL)) return hp_diff (inspect, diff);

  if (inspect != NULL) return hp_inspect (inspect);

  if (diff != NULL)
  {
    fprintf (stderr, "hpcfg: --ruleset-diff says what to compare against; -i says what to compare\n");

    return 1;
  }

  if (nmerge > 0) return pcfg_merge (merge, nmerge, wspec, &o);

  /* Zero is a coverage like any other: every guess then comes from OMEN. */
  if ((o.coverage < 0.0) || (o.coverage > 1.0))
  {
    fprintf (stderr, "hpcfg: coverage %g is outside 0 to 1, training at 0.6\n", o.coverage);

    o.coverage = 0.6;
  }

  if ((o.mw_min > 0) && (o.mw_max > 0) && (o.mw_min > o.mw_max))
  {
    fprintf (stderr, "hpcfg: --mw-len-min %d is above --mw-len-max %d\n", o.mw_min, o.mw_max);

    return 1;
  }

  /* Without a count there is nothing to compare, so the option would silently do
   * nothing. Say so rather than train something the caller did not ask for. */
  if ((o.mincount > 1) && (o.weighted == false))
  {
    fprintf (stderr, "hpcfg: --count-min needs --weighted, there is no count to compare without it\n");

    return 1;
  }

  if ((nmerge == 0) && ((o.infile == NULL) || ((o.outdir == NULL) && (o.dict_out == NULL) && (o.freq_out == NULL))))
  {
    usage (stderr);
    return 1;
  }

  return pcfg_train (&o);
}
