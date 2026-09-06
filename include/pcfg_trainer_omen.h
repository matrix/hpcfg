/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * The OMEN escape: the Markov model that covers whatever the grammar does not.
 */

#ifndef PCFG_TRAINER_OMEN_H
#define PCFG_TRAINER_OMEN_H

#include "pcfg_common.h"

#define OMEN_LVL_CNT 512

typedef struct omen omen_t;

/* What the contexts and their index take, which the budget has to include. */
size_t omen_bytes (const omen_t *o);

omen_t *omen_new (int ngram, int alpha_size);
void omen_free (omen_t *o);
int omen_build_alphabet (omen_t *o, const int64_t *byte_freq);

/* Record the frequencies this corpus had, when the alphabet came from another. */
void omen_note_freq (omen_t *o, const int64_t *byte_freq);
void omen_train (omen_t *o, const char *pw, int pwlen, int64_t n);
void omen_threaded (omen_t *o, bool on);
void omen_workers (omen_t *o, int nw);
void omen_ks_max (omen_t *o, int m);
void omen_compat (omen_t *o, bool on);
void omen_account (omen_t *o, hp_mem_t *m);
int64_t omen_refused (const omen_t *o);
void omen_smooth (omen_t *o);
int omen_level (omen_t *o, const char *pw, int pwlen);
int64_t omen_contexts (const omen_t *o);
/* The counts the levels were made from, written beside them so two models add. */
int omen_write_counts (const omen_t *o, const char *dir);

/* The model several rulesets add up to, or NULL if the counts cannot be summed. */
omen_t *omen_merge_counts (char **dirs, const double *weight, int nin, bool compat);

/* The level files, the keyspace, and what one guess at each level is worth. */
int omen_save (omen_t *o, const char *dir, const int64_t *lvl_counts, int nlevels, int64_t pw_total);

#endif /* PCFG_TRAINER_OMEN_H */
