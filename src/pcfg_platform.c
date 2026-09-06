/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * The handful of things that differ between the systems hpcfg builds on.
 */

#include "pcfg_platform.h"

#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

/* mmap and sched_yield have no header on Windows, where the two functions that
 * want them take the VirtualAlloc and the SwitchToThread branch instead. */
#if !defined(HP_WINDOWS)
#include <sys/mman.h>
#include <sched.h>
#endif

#if defined(__APPLE__)
#include <malloc/malloc.h>
#elif defined(__GLIBC__)
#include <malloc.h>
#endif

#if defined(HP_WINDOWS)
#include <windows.h>
#include <direct.h>
#include <io.h>
#else
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>
#include <mach/mach.h>
#endif

struct hp_thread
{
#if defined(HP_WINDOWS)
  HANDLE h;
#else
  pthread_t t;
#endif
};

/* A spin lock rather than the system's mutex. */
struct hp_mutex
{
#if defined(HP_WINDOWS)
  CRITICAL_SECTION cs;
#elif defined(__APPLE__)
  volatile int flag;
#else
  pthread_mutex_t m;
#endif
};

#if defined(HP_WINDOWS)
typedef struct
{
  void *(*fn) (void *);
  void *arg;
} hp_trampoline_t;

/* Windows wants a DWORD-returning entry point, so the real one is wrapped. */
static DWORD WINAPI hp_win_entry (LPVOID p)
{
  hp_trampoline_t *tr = (hp_trampoline_t *) p;

  tr->fn (tr->arg);

  free (tr);

  return 0;
}
#endif

hp_thread_t *hp_thread_start (void *(*fn) (void *), void *arg)
{
  hp_thread_t *t = (hp_thread_t *) calloc (1, sizeof (hp_thread_t));

  if (t == NULL) return NULL;

#if defined(HP_WINDOWS)
  hp_trampoline_t *tr = (hp_trampoline_t *) malloc (sizeof (hp_trampoline_t));

  if (tr == NULL)
  {
    free (t);
    return NULL;
  }

  tr->fn  = fn;
  tr->arg = arg;

  t->h = CreateThread (NULL, 0, hp_win_entry, tr, 0, NULL);

  if (t->h == NULL)
  {
    free (tr);
    free (t);
    return NULL;
  }
#else
  if (pthread_create (&t->t, NULL, fn, arg) != 0)
  {
    free (t);
    return NULL;
  }
#endif

  return t;
}

void hp_thread_join (hp_thread_t *t)
{
  if (t == NULL) return;

#if defined(HP_WINDOWS)
  WaitForSingleObject (t->h, INFINITE);
  CloseHandle (t->h);
#else
  pthread_join (t->t, NULL);
#endif

  free (t);
}

void hp_mutex_init (hp_mutex_t **m)
{
  *m = (hp_mutex_t *) calloc (1, sizeof (hp_mutex_t));

  if (*m == NULL) return;

#if defined(HP_WINDOWS)
  InitializeCriticalSection (&(*m)->cs);
#else
#if defined(__APPLE__)
  (*m)->flag = 0;
#else
  pthread_mutex_init (&(*m)->m, NULL);
#endif
#endif
}

void hp_mutex_destroy (hp_mutex_t *m)
{
  if (m == NULL) return;

#if defined(HP_WINDOWS)
  DeleteCriticalSection (&m->cs);
#else
  (void) m;
#endif

  free (m);
}

void hp_mutex_lock (hp_mutex_t *m)
{
#if defined(HP_WINDOWS)
  EnterCriticalSection (&m->cs);
#elif !defined(__APPLE__)
  pthread_mutex_lock (&m->m);
#else
  int spins = 0;

  while (__atomic_exchange_n (&m->flag, 1, __ATOMIC_ACQUIRE) != 0)
  {
    if (++spins < 64)
    {
#if defined(__aarch64__) || defined(__arm64__)
      __asm__ __volatile__ ("yield");
#elif defined(__x86_64__) || defined(__i386__)
      __asm__ __volatile__ ("pause");
#endif
      continue;
    }

    spins = 0;

    sched_yield ();
  }
#endif
}

void hp_mutex_unlock (hp_mutex_t *m)
{
#if defined(HP_WINDOWS)
  LeaveCriticalSection (&m->cs);
#elif !defined(__APPLE__)
  pthread_mutex_unlock (&m->m);
#else
  __atomic_store_n (&m->flag, 0, __ATOMIC_RELEASE);
#endif
}

/* Once for the process. */
struct hp_once
{
#if defined(HP_WINDOWS)
  INIT_ONCE o;
#else
  pthread_once_t o;
#endif
};

/* The winner runs fn and everybody else waits, rather than walking into a table
 * still being laid out. The loop is entered at most once per thread. */
void hp_once (hp_once_t *o, void (*fn) (void))
{
  if (__atomic_load_n (&o->state, __ATOMIC_ACQUIRE) == 2) return;

  int nobody = 0;

  if (__atomic_compare_exchange_n (&o->state, &nobody, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) == true)
  {
    fn ();

    __atomic_store_n (&o->state, 2, __ATOMIC_RELEASE);

    return;
  }

  while (__atomic_load_n (&o->state, __ATOMIC_ACQUIRE) != 2) hp_sleep_ms (1);
}

int hp_fseek64 (FILE *f, int64_t off, int whence)
{
#if defined(HP_WINDOWS)
  return _fseeki64 (f, off, whence);
#else
  return fseeko (f, (off_t) off, whence);
#endif
}

int64_t hp_ftell64 (FILE *f)
{
#if defined(HP_WINDOWS)
  return _ftelli64 (f);
#else
  return (int64_t) ftello (f);
#endif
}

/* Memory the process can actually give back. */
void *hp_map (size_t bytes)
{
#if defined(HP_WINDOWS)
  return VirtualAlloc (NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
  void *p = mmap (NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  return (p == MAP_FAILED) ? NULL : p;
#endif
}

void hp_unmap (void *p, size_t bytes)
{
  if (p == NULL) return;

#if defined(HP_WINDOWS)
  (void) bytes;
  VirtualFree (p, 0, MEM_RELEASE);
#else
  munmap (p, bytes);
#endif
}

/* Asking the allocator to hand back what it is holding. */
void hp_mem_release (void)
{
#if defined(HP_WINDOWS)
  /* nothing to ask: the heap returns its own */
#elif defined(__APPLE__)
  malloc_zone_pressure_relief (NULL, 0);
#elif defined(__GLIBC__)
  malloc_trim (0);
#endif
}

/* This run, told apart from any other that shares the same output name. */
int hp_pid (void)
{
#if defined(HP_WINDOWS)
  return (int) GetCurrentProcessId ();
#else
  return (int) getpid ();
#endif
}

int hp_mkdir (const char *path)
{
#if defined(HP_WINDOWS)
  if ((_mkdir (path) != 0) && (errno != EEXIST))
#else
  if ((mkdir (path, 0755) != 0) && (errno != EEXIST))
#endif
  {
    fprintf (stderr, "hpcfg: cannot create \"%s\": %s\n", path, strerror (errno));

    return 1;
  }

  return 0;
}

/* Delete a directory tree, written out rather than handed to a shell. */
int hp_rmtree (const char *path)
{
#if defined(HP_WINDOWS)
  WIN32_FIND_DATA fd;
  char pattern[4096];

  snprintf (pattern, sizeof (pattern), "%s\\*", path);

  HANDLE h = FindFirstFile (pattern, &fd);

  if (h != INVALID_HANDLE_VALUE)
  {
    do
    {
      if ((strcmp (fd.cFileName, ".") == 0) || (strcmp (fd.cFileName, "..") == 0)) continue;

      char sub[4096];

      snprintf (sub, sizeof (sub), "%s\\%s", path, fd.cFileName);

      if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        hp_rmtree (sub);
      else
        DeleteFile (sub);
    } while (FindNextFile (h, &fd) != 0);

    FindClose (h);
  }

  return (RemoveDirectory (path) != 0) ? 0 : 1;
#else
  DIR *d = opendir (path);

  if (d != NULL)
  {
    struct dirent *e;

    while ((e = readdir (d)) != NULL)
    {
      if ((strcmp (e->d_name, ".") == 0) || (strcmp (e->d_name, "..") == 0)) continue;

      char sub[4096];

      snprintf (sub, sizeof (sub), "%s/%s", path, e->d_name);

      struct stat sb;

      if ((stat (sub, &sb) == 0) && S_ISDIR (sb.st_mode))
        hp_rmtree (sub);
      else
        remove (sub);
    }

    closedir (d);
  }

  return rmdir (path);
#endif
}

int hp_tmpname (char *out, size_t outsz, const char *tag)
{
#if defined(HP_WINDOWS)
  char dir[MAX_PATH];

  if (GetTempPath (sizeof (dir), dir) == 0) return 1;

  snprintf (out, outsz, "%s%s.%lu", dir, tag, (unsigned long) GetCurrentProcessId ());
#else
  const char *dir = getenv ("TMPDIR");

  if (dir == NULL) dir = "/tmp";

  snprintf (out, outsz, "%s/%s.%d", dir, tag, (int) getpid ());
#endif

  return 0;
}

void hp_sleep_ms (int ms)
{
#ifdef HP_WINDOWS
  Sleep ((DWORD) ms);
#else
  struct timespec ts;

  ts.tv_sec  = (time_t) (ms / 1000);
  ts.tv_nsec = (long) (ms % 1000) * 1000000L;

  nanosleep (&ts, NULL);
#endif
}

bool hp_stderr_is_tty (void)
{
#ifdef HP_WINDOWS
  return (_isatty (_fileno (stderr)) != 0) ? true : false;
#else
  return (isatty (fileno (stderr)) != 0) ? true : false;
#endif
}

/* clock_gettime is not in the Windows C runtime: on MinGW it comes from
 * winpthread, which is a DLL to ship for a timer. */
double hp_now (void)
{
#if defined(HP_WINDOWS)
  static LARGE_INTEGER freq;

  if (freq.QuadPart == 0) QueryPerformanceFrequency (&freq);

  LARGE_INTEGER now;

  QueryPerformanceCounter (&now);

  return (double) now.QuadPart / (double) freq.QuadPart;
#else
  struct timespec t;

  clock_gettime (CLOCK_MONOTONIC, &t);

  return (double) t.tv_sec + ((double) t.tv_nsec / 1e9);
#endif
}

int hp_cpu_count (void)
{
#if defined(HP_WINDOWS)
  SYSTEM_INFO si;

  GetSystemInfo (&si);

  return (int) si.dwNumberOfProcessors;
#else
  const long n = sysconf (_SC_NPROCESSORS_ONLN);

  return (n > 0) ? (int) n : 1;
#endif
}

size_t hp_available_ram (void)
{
#if defined(HP_WINDOWS)
  MEMORYSTATUSEX ms;

  ms.dwLength = sizeof (ms);

  if (GlobalMemoryStatusEx (&ms) == 0) return 0;

  return (size_t) ms.ullAvailPhys;

#elif defined(__APPLE__)

  /* Free plus inactive: inactive pages are reclaimable, and free alone is ~0. */
  vm_size_t page   = 0;
  mach_port_t host = mach_host_self ();
  vm_statistics64_data_t vm;
  mach_msg_type_number_t cnt = HOST_VM_INFO64_COUNT;

  if (host_page_size (host, &page) != KERN_SUCCESS) return 0;
  if (host_statistics64 (host, HOST_VM_INFO64, (host_info64_t) &vm, &cnt) != KERN_SUCCESS) return 0;

  return (size_t) (vm.free_count + vm.inactive_count) * (size_t) page;

#else

  FILE *f = fopen ("/proc/meminfo", "r");

  if (f == NULL) return 0;

  char line[256];
  size_t avail = 0;

  while (fgets (line, sizeof (line), f) != NULL)
  {
    unsigned long kb = 0;

    if (sscanf (line, "MemAvailable: %lu kB", &kb) == 1)
    {
      avail = (size_t) kb * 1024;
      break;
    }
  }

  fclose (f);

  return avail;
#endif
}

bool hp_is_desktop (void)
{
#if defined(__APPLE__)
  return true;
#elif defined(HP_WINDOWS)
  return true;
#else
  if (getenv ("DISPLAY") != NULL) return true;
  if (getenv ("WAYLAND_DISPLAY") != NULL) return true;
  if (getenv ("XDG_CURRENT_DESKTOP") != NULL) return true;

  return false;
#endif
}
