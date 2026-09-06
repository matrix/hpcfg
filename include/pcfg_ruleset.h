/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * Writing a ruleset, and folding finished ones together.
 */

#ifndef PCFG_RULESET_H
#define PCFG_RULESET_H

#include "pcfg_common.h"

typedef struct
{
  char ty;
  const char *dir;
  bool flat;        /* one file for every length, the reader looks in 1.txt */
  const char *file; /* the reader wants this name rather than "<len>.txt" */
} hp_dir_t;

/* Where one (type, length) list goes, or the name the reader insists on. */
void hp_dir_path (char *out, size_t n, const char *outdir, const hp_dir_t *d, int len);

/* Which encoding names the values written; only meaningful after the writing. */
const char *hp_encoding_name (void);

/* The denominator of every list written, so a merge never has to work one out.
 * Written after the lists, off the finished directory. */
int hp_write_totals (const char *outdir);
int64_t hp_read_total (const char *dir, uint8_t ty, uint8_t len);

int hp_write_config (const char *outdir, const char *infile, const char *version, bool compat,
                     int64_t pw_cnt, int64_t enc_err, const char *comments, const char *encoding);

int hp_write_ruleset (const hp_store_t *st, const char *outdir, const hp_dir_t *dirs, int64_t admit, int nthread);
int hp_write_counts (const hp_store_t *st, const char *outdir, const hp_dir_t *dirs);
/* The corpus, when the caller still has it. */
typedef struct
{
  const char *corpus;
  bool weighted;
  const char *sep;
  bool keep_junk;
  int64_t mincount;
  bool compat; /* write what only pcfg_cracker and pcfg-go read */
} hp_merge_src_t;

/* Two or more finished rulesets into one. The counts are put back from the
 * probabilities before they are summed. Pass weight NULL to take each ruleset's
 * share from what it was trained on. */
int hp_merge_rulesets (char **in, const double *weight, int nin, const char *outdir,
                       const hp_dir_t *dirs, const hp_dir_t *gdirs, int64_t admit,
                       const hp_merge_src_t *src);

int hp_merge_counts (char **parts, int nparts, const char *outdir, const hp_dir_t *dirs, int64_t admit);

#endif /* PCFG_RULESET_H */
