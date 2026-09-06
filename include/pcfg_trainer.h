/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * What the trainer is asked for, and the two jobs it does with it.
 */

#ifndef PCFG_TRAINER_H
#define PCFG_TRAINER_H

#include "pcfg_common.h"

/* Who the ruleset is written for. */
#define HP_FMT_HASHCAT 0
#define HP_FMT_CRACKER 1

typedef struct
{
  const char *infile;
  const char *outdir;
  const char *sep;
  bool weighted;
  int64_t admit;
  int ngram;
  int alpha;
  size_t budget; /* bytes the counters may take, 0 = no limit */
  int ks_max;    /* --omen-level-max, 0 = the default depth */
  int seen;      /* times a terminal must be seen before it earns a slot */
  int threads;
  double coverage; /* the grammar's share against OMEN's */
  bool keep_junk;
  const char *dict;     /* words to know before the corpus is read */
  const char *dict_out; /* and where to write the ones this run found */
  const char *freq_out; /* the byte frequencies the alphabet is chosen from */
  const char *freq_in;  /* or the ones a shared pass already established */
  int64_t mincount;     /* weighted lines below this are not read at all */
  bool sensitive;       /* keep the addresses and the URLs themselves */

  const char *comments; /* free text the format carries in config.ini */
  const char *encoding; /* forced, where the data would have decided */

  /* How often a word has to be seen before a run may be split on it, and the
   * shortest and longest run it applies to. Weir's numbers are 5, 4 and 21. */
  int mw_thr;
  int mw_min;
  int mw_max;
  bool mw_off;
  bool verbose;    /* report what each pass costs */
  int format;      /* HP_FMT_HASHCAT or HP_FMT_CRACKER */
  bool budget_set; /* -M was typed: the ceiling is meant, not inferred */
} hp_opts_t;

/* Read the corpus and write the ruleset. */
int pcfg_train (hp_opts_t *o);

/* Fold rulesets together instead, with the shares given or the trained ones. */
int pcfg_merge (char **in, int nin, const char *weights, hp_opts_t *o);

#endif /* PCFG_TRAINER_H */
