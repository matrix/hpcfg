/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * Reading a finished ruleset back and reporting on it.
 */

#ifndef PCFG_RULESET_INSPECT_H
#define PCFG_RULESET_INSPECT_H

/* What one ruleset holds, and what is wrong with it: the structures by mass, the
 * terminal lists, the first guesses, and the checks a reader would fail on. */
int hp_inspect (const char *root);

/* Two rulesets side by side: how much of the mass they agree on, and where not. */
int hp_diff (const char *a, const char *b);

#endif /* PCFG_RULESET_INSPECT_H */
