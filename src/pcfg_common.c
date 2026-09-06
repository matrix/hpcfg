/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * UTF-8 in and out, and what Unicode says a codepoint is.
 */

#include <errno.h>
#include <string.h>
#include "pcfg_common.h"

/* How many bytes the leading byte claims, 1 where it claims nothing. */
/* clang-format off */
static const unsigned char utf8_claims[256] =
{
  /* 0x00 - 0x7f: one byte, itself */
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,

  /* 0x80 - 0xbf: continuations, which lead nothing */
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,

  /* 0xc0 - 0xdf: two */
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,

  /* 0xe0 - 0xef: three */
  3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,

  /* 0xf0 - 0xf7: four; 0xf8 and up lead nothing */
  4,4,4,4,4,4,4,4, 1,1,1,1,1,1,1,1
};
/* clang-format on */

/* What the leading byte keeps of itself, by sequence length. */
static const unsigned char utf8_lead_mask[5] = { 0x00, 0xff, 0x1f, 0x0f, 0x07 };

int utf8_decode (const char *s, int len, uint32_t *cp)
{
  if (len <= 0) return 0;

  const unsigned char c = (unsigned char) s[0];

  const int want = utf8_claims[c];

  /* Claiming more than is left is claiming nothing: the byte stands for itself. */
  if ((want == 1) || (want > len))
  {
    *cp = c;

    return 1;
  }

  /* Nor does a lead byte whose continuations are not continuations. Masking them
   * in regardless is how "senor" lost its o: latin-1 puts an ASCII letter after
   * every accented one, and 0xF1 0x6F 0x72 came out a codepoint of its own. */
  for (int i = 1; i < want; i++)
  {
    if (((unsigned char) s[i] & 0xc0) != 0x80)
    {
      *cp = c;

      return 1;
    }
  }

  uint32_t v = c & utf8_lead_mask[want];

  for (int i = 1; i < want; i++) v = (v << 6) | ((unsigned char) s[i] & 0x3f);

  *cp = v;

  return want;
}

/* The lead byte of each length, and how far its payload is shifted. */
static const unsigned char utf8_lead_bits[5] = { 0, 0x00, 0xc0, 0xe0, 0xf0 };

int utf8_encode (char *buf, uint32_t cp)
{
  const int n = (cp < 0x80) ? 1 : ((cp < 0x800) ? 2 : ((cp < 0x10000) ? 3 : 4));

  /* Tail first, six bits at a time, then the lead over what is left. */
  for (int i = n - 1; i > 0; i--)
  {
    buf[i] = (char) (0x80 | (cp & 0x3f));

    cp >>= 6;
  }

  buf[0] = (char) (utf8_lead_bits[n] | cp);

  return n;
}

int utf8_cplen (const char *s, int bytelen)
{
  int at = 0, n = 0;

  while (at < bytelen)
  {
    uint32_t cp;

    const int adv = utf8_decode (s + at, bytelen - at, &cp);

    if (adv == 0) break;

    at += adv;
    n++;
  }

  return n;
}

static int in_ranges (const hp_range_t *r, size_t cnt, uint32_t cp)
{
  size_t lo = 0, hi = cnt;

  while (lo < hi)
  {
    const size_t mid = lo + ((hi - lo) / 2);

    if (cp < r[mid].lo)
      hi = mid;
    else if (cp > r[mid].hi)
      lo = mid + 1;
    else
      return 1;
  }

  return 0;
}

static uint32_t map_case (const hp_casemap_t *m, size_t cnt, uint32_t cp)
{
  size_t lo = 0, hi = cnt;

  while (lo < hi)
  {
    const size_t mid = lo + ((hi - lo) / 2);

    if (cp < m[mid].from)
      hi = mid;
    else if (cp > m[mid].from)
      lo = mid + 1;
    else
      return m[mid].to;
  }

  return cp;
}

int utf8_is_alpha (uint32_t cp)
{
  if (cp < 0x80) return (((cp | 0x20) >= 'a') && ((cp | 0x20) <= 'z')) ? 1 : 0;

  return in_ranges (hp_letter_ranges, hp_letter_ranges_cnt, cp);
}

int utf8_is_digit (uint32_t cp)
{
  if (cp < 0x80) return ((cp >= '0') && (cp <= '9')) ? 1 : 0;

  return in_ranges (hp_digit_ranges, hp_digit_ranges_cnt, cp);
}

int utf8_is_upper (uint32_t cp)
{
  if (cp < 0x80) return ((cp >= 'A') && (cp <= 'Z')) ? 1 : 0;

  return in_ranges (hp_upper_ranges, hp_upper_ranges_cnt, cp);
}

uint32_t utf8_to_lower (uint32_t cp)
{
  if (cp < 0x80) return ((cp >= 'A') && (cp <= 'Z')) ? cp + 32 : cp;

  return map_case (hp_tolower_map, hp_tolower_map_cnt, cp);
}

uint32_t utf8_to_upper (uint32_t cp)
{
  if (cp < 0x80) return ((cp >= 'a') && (cp <= 'z')) ? cp - 32 : cp;

  return map_case (hp_toupper_map, hp_toupper_map_cnt, cp);
}

void hp_mem_init (hp_mem_t *m, size_t budget)
{
  m->budget = (int64_t) budget;
  m->used   = 0;
  m->parent = NULL;
}

void hp_mem_share (hp_mem_t *m, hp_mem_t *parent, size_t cap)
{
  m->budget = (int64_t) cap;
  m->used   = 0;
  m->parent = parent;
}

/* Taking room, or being told there is none. */
static bool hp_mem_take_one (hp_mem_t *m, int64_t want)
{
  if (m->budget == 0) return true;

  int64_t now = __atomic_load_n (&m->used, __ATOMIC_RELAXED);

  for (;;)
  {
    if ((now + want) > m->budget) return false;

    if (__atomic_compare_exchange_n (&m->used, &now, now + want, true,
                                     __ATOMIC_RELAXED, __ATOMIC_RELAXED) == true) return true;
  }
}

bool hp_mem_take (hp_mem_t *m, size_t bytes)
{
  if (m == NULL) return true;

  const int64_t want = (int64_t) bytes;

  if (hp_mem_take_one (m, want) == false) return false;

  /* The share was there; the total has to be too, or the share goes back. */
  if ((m->parent != NULL) && (hp_mem_take_one (m->parent, want) == false))
  {
    __atomic_fetch_sub (&m->used, want, __ATOMIC_RELAXED);

    return false;
  }

  return true;
}

void hp_mem_give (hp_mem_t *m, size_t bytes)
{
  if (m == NULL) return;

  if (m->budget != 0) __atomic_fetch_sub (&m->used, (int64_t) bytes, __ATOMIC_RELAXED);

  if (m->parent != NULL) hp_mem_give (m->parent, bytes);
}

int64_t hp_mem_used (const hp_mem_t *m)
{
  if (m == NULL) return 0;

  return __atomic_load_n (&m->used, __ATOMIC_RELAXED);
}

/* Closing a file that was written, and saying whether it actually got there. */
int hp_fclose_w (FILE *f, const char *path)
{
  if (f == NULL) return 1;

  const bool bad = (ferror (f) != 0);
  const int rc   = fclose (f);

  if ((bad == false) && (rc == 0)) return 0;

  fprintf (stderr, "hpcfg: writing \"%s\" did not finish: %s\n", path,
           (errno != 0) ? strerror (errno) : "the file is short");

  return 1;
}

/* A count with the digits grouped, always by a dot: the locale would vary it. */
const char *hp_group (int64_t v, char *out, size_t n)
{
  char raw[32];

  const int len = snprintf (raw, sizeof (raw), "%" PRId64, v);

  size_t o = 0;

  for (int i = 0; i < len; i++)
  {
    if ((i > 0) && (((len - i) % 3) == 0) && ((o + 1) < n)) out[o++] = '.';

    if ((o + 1) < n) out[o++] = raw[i];
  }

  out[o] = 0;

  return out;
}

/* The report bar, in ASCII, between two pipes so the column has edges. */
void hp_bar_block (char *buf, size_t buf_size, double percentage, int width)
{
  if (percentage < 0.0) percentage = 0.0;
  if (percentage > 100.0) percentage = 100.0;

  int filled = (int) (((percentage / 100.0) * width) + 0.5);

  if (filled > width) filled = width;

  buf[0] = '|';

  size_t pos = 1;

  for (int i = 0; (i < width) && ((pos + 2) < buf_size); i++)
  {
    buf[pos++] = (i < filled) ? '#' : '-';
  }

  buf[pos++] = '|';
  buf[pos]   = 0;
}
