/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * The handful of things that differ between the systems hpcfg
 * builds on.
 */

#ifndef PCFG_PLATFORM_H
#define PCFG_PLATFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#if defined(_WIN32) || defined(_WIN64)
#define HP_WINDOWS 1
#endif

typedef struct hp_thread hp_thread_t;
typedef struct hp_mutex hp_mutex_t;

/* Both return NULL on failure, and a caller that gets one runs the work itself. */
hp_thread_t *hp_thread_start (void *(*fn) (void *), void *arg);
void hp_thread_join (hp_thread_t *t);

void hp_mutex_init (hp_mutex_t **m);
void hp_mutex_destroy (hp_mutex_t *m);
void hp_mutex_lock (hp_mutex_t *m);
void hp_mutex_unlock (hp_mutex_t *m);

/* Run fn once for the process, whichever thread gets there first. */
typedef struct
{
  int state; /* 0 nobody yet, 1 one thread is in fn, 2 fn has returned */
} hp_once_t;

#define HP_ONCE_INIT { 0 }

void hp_once (hp_once_t *o, void (*fn) (void));

int hp_fseek64 (FILE *f, int64_t off, int whence);
int64_t hp_ftell64 (FILE *f);

int hp_pid (void);
void hp_mem_release (void);
void *hp_map (size_t bytes);
void hp_unmap (void *p, size_t bytes);
int hp_mkdir (const char *path);
int hp_rmtree (const char *path);
int hp_tmpname (char *out, size_t outsz, const char *tag);

void hp_sleep_ms (int ms);
bool hp_stderr_is_tty (void); /* a log file does not want carriage returns */

double hp_now (void); /* seconds, monotonic */
int hp_cpu_count (void);
size_t hp_available_ram (void); /* 0 when it cannot be told */
bool hp_is_desktop (void);

#endif /* PCFG_PLATFORM_H */
