/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * Small helpers the trainer and the writer both use.
 */

#ifndef PCFG_TRAINER_UTILS_H
#define PCFG_TRAINER_UTILS_H

#include "pcfg_common.h"

/* $HEX[...] back to the bytes it stands for. */
int hp_unhex (const char *s, int len, char *out, int outmax);

/* A line mangled by a wrong decoding put back, where that can be told. */
int hp_recover (char *buf, int len, int outmax);

/* Whether a line is a password at all, and whether it is a hash or a key. */
bool hp_is_password (const char *s, int len);
bool hp_is_junk (const char *s, int len);

/* What the counters may take when -M was not given, read off the free memory. */
size_t hp_default_budget (void);

#endif /* PCFG_TRAINER_UTILS_H */
