/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * Password decomposition into typed sections
 */

#include <stdbool.h>
#include <string.h>

#include "pcfg_common.h"

pcfg_words_t *hp_words = NULL;

static inline unsigned char fast_lower (unsigned char c)
{
  return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

/* Context-sensitive patterns (from Go source) - with precomputed lengths */
static const struct
{
  const char *pat;
  int len;
} context_pats[] = {
  { ";p",   2 },
  { ":p",   2 },
  { "*0*",  3 },
  { "#1",   2 },
  { "No.1", 4 },
  { "no.1", 4 },
  { "No.",  3 },
  { "i<3",  3 },
  { "I<3",  3 },
  { "<3",   2 },
  { "Mr.",  3 },
  { "mr.",  3 },
  { "MR.",  3 },
  { "MS.",  3 },
  { "Ms.",  3 },
  { "ms.",  3 },
  { "Mz.",  3 },
  { "mz.",  3 },
  { "MZ.",  3 },
  { "St.",  3 },
  { "st.",  3 },
  { "Dr.",  3 },
  { "dr.",  3 }
};

const char *context_patterns[] = {
  ";p", ":p", "*0*", "#1",
  "No.1", "no.1", "No.", "i<3", "I<3", "<3",
  "Mr.", "mr.", "MR.",
  "MS.", "Ms.", "ms.",
  "Mz.", "mz.", "MZ.",
  "St.", "st.",
  "Dr.", "dr."
};

int n_context_patterns = sizeof (context_patterns) / sizeof (context_patterns[0]);
#define N_CONTEXT_PATS (sizeof (context_pats) / sizeof (context_pats[0]))

/* TLD list - with precomputed lengths */
static const struct
{
  const char *tld;
  int len;
} tld_table[] = {
  { ".com",    4 },
  { ".org",    4 },
  { ".edu",    4 },
  { ".gov",    4 },
  { ".mil",    4 },
  { ".net",    4 },
  { ".us",     3 },
  { ".uk",     3 },
  { ".ca",     3 },
  { ".de",     3 },
  { ".jp",     3 },
  { ".fr",     3 },
  { ".au",     3 },
  { ".ru",     3 },
  { ".ch",     3 },
  { ".it",     3 },
  { ".nl",     3 },
  { ".se",     3 },
  { ".no",     3 },
  { ".es",     3 },
  { ".cn",     3 },
  { ".in",     3 },
  { ".br",     3 },
  { ".mx",     3 },
  { ".kr",     3 },
  { ".za",     3 },
  { ".pl",     3 },
  { ".tr",     3 },
  { ".ir",     3 },
  { ".id",     3 },
  { ".sg",     3 },
  { ".hk",     3 },
  { ".tw",     3 },
  { ".vn",     3 },
  { ".ar",     3 },
  { ".cl",     3 },
  { ".nz",     3 },
  { ".be",     3 },
  { ".fi",     3 },
  { ".dk",     3 },
  { ".info",   5 },
  { ".biz",    4 },
  { ".xyz",    4 },
  { ".online", 7 },
  { ".site",   5 },
  { ".top",    4 },
  { ".club",   5 },
  { ".live",   5 },
  { ".shop",   5 },
  { ".store",  6 },
  { ".tech",   5 },
  { ".app",    4 },
  { ".dev",    4 },
  { ".blog",   5 },
  { ".cloud",  6 },
  { ".co",     3 },
  { ".io",     3 },
  { ".ai",     3 },
  { ".me",     3 },
  { ".gg",     3 },
  { ".tv",     3 },
  { ".cc",     3 },
  { ".pw",     3 },
  { ".name",   5 },
  { ".pro",    4 },
  { ".win",    4 },
  { ".loan",   5 },
  { ".click",  6 }
};
#define N_TLDS (sizeof (tld_table) / sizeof (tld_table[0]))
const char *tld_list[] = {
  ".com", ".org", ".edu", ".gov", ".mil", ".net",
  ".us", ".uk", ".ca", ".de", ".jp", ".fr", ".au", ".ru",
  ".ch", ".it", ".nl", ".se", ".no", ".es", ".cn", ".in",
  ".br", ".mx", ".kr", ".za", ".pl", ".tr", ".ir", ".id",
  ".sg", ".hk", ".tw", ".vn", ".ar", ".cl", ".nz", ".be",
  ".fi", ".dk",
  ".info", ".biz", ".xyz", ".online", ".site", ".top",
  ".club", ".live", ".shop", ".store", ".tech", ".app",
  ".dev", ".blog", ".cloud",
  ".co", ".io", ".ai", ".me", ".gg", ".tv", ".cc", ".pw",
  ".name", ".pro", ".win", ".loan", ".click"
};

int n_tlds = sizeof (tld_list) / sizeof (tld_list[0]);

static inline int make_type (char *buf, char prefix, int num)
{
  buf[0] = prefix;
  if (num < 10)
  {
    buf[1] = '0' + num;
    buf[2] = '\0';
    return 2;
  }
  if (num < 100)
  {
    buf[1] = '0' + num / 10;
    buf[2] = '0' + num % 10;
    buf[3] = '\0';
    return 3;
  }
  buf[1] = '0' + num / 100;
  buf[2] = '0' + (num / 10) % 10;
  buf[3] = '0' + num % 10;
  buf[4] = '\0';
  return 4;
}

static inline void set_section (pcfg_token_t *s, char *value, int vlen,
                                char prefix, int num)
{
  s->value  = value;
  s->vlen   = vlen;
  s->cp_len = num;
  make_type (s->type, prefix, num);
}

static inline void set_section_str (pcfg_token_t *s, char *value, int vlen,
                                    const char *type, int cp_len)
{
  s->value  = value;
  s->vlen   = vlen;
  s->cp_len = cp_len;
  int i     = 0;
  while (type[i] && i < PCFG_MAXTYPE - 1)
  {
    s->type[i] = type[i];
    i++;
  }
  s->type[i] = '\0';
}

/* The case mask of an alpha section: one U/L per codepoint, not per byte. */
void build_case_mask (const char *alpha, int bytelen, char *mask)
{
  int mi = 0, i = 0;
  while (i < bytelen)
  {
    uint32_t cp;
    int n = utf8_decode (alpha + i, bytelen - i, &cp);
    if (n == 0) break;
    mask[mi++] = utf8_is_upper (cp) ? 'U' : 'L';
    i += n;
  }
  mask[mi] = '\0';
}

/* The reader's own walk over the tokens: one slot each, two for an A, and room
 * for two demanded before every one. A structure this accepts the reader does. */
bool hp_structure_fits (const pcfg_token_t *sects, int nsects)
{
  int nslot = 0, total = 0;

  for (int i = 0; i < nsects; i++)
  {
    if ((nslot + 2) > PCFG_MAXSLOT) return false;

    nslot++;

    const char ty = sects[i].type[0];

    if (ty == PCFG_ST_ALPHA) nslot++;

    /* X and Y say nothing about their entries, so the reader leaves them out too. */
    if ((ty != PCFG_ST_CONTEXT) && (ty != PCFG_ST_YEAR)) total += sects[i].cp_len;
  }

  return (total <= PCFG_MAXPWLEN);
}

/* No C entries, added at generation time, and no W or E, which are not guessable. */
void build_base_structure (pcfg_token_t *sects, int nsects, char *out, int outlen)
{
  int pos = 0;
  for (int i = 0; i < nsects && pos < outlen - PCFG_MAXTYPE; i++)
  {
    if (sects[i].type[0] == PCFG_ST_EMAIL || sects[i].type[0] == PCFG_ST_WEBSITE)
    {
      out[0] = '\0';
      return;
    }

    int len = strlen (sects[i].type);
    memcpy (out + pos, sects[i].type, len);
    pos += len;
  }
  out[pos] = '\0';
}

/* The same walk, keeping the E and W a base structure may not have. */
void build_raw_structure (pcfg_token_t *sects, int nsects, char *out, int outlen)
{
  int pos = 0;

  for (int i = 0; i < nsects && pos < outlen - PCFG_MAXTYPE; i++)
  {
    int len = strlen (sects[i].type);
    memcpy (out + pos, sects[i].type, len);
    pos += len;
  }

  out[pos] = '\0';
}

/* Byte tags for marking detected patterns before the main scan. */
#define TAG_NONE 0
#define TAG_YEAR 1
#define TAG_CTX 2
#define TAG_KBD 3
#define TAG_EMAIL 4
#define TAG_WEB 5

/* Two tags for keyboard walks, used alternately. */
#define TAG_KBD_B 6
#define IS_KBD(t) (((t) == TAG_KBD) || ((t) == TAG_KBD_B))

/* Looks for @provider.tld. Returns the end position, or -1. */
static int detect_email_in (const char *pw, int pwlen, char *lower,
                            int *email_start, int *email_end,
                            char *provider, int *provlen)
{
  char *at = memchr (pw, '@', pwlen);
  if (!at) return 0;
  char *dot = memchr (pw, '.', pwlen);
  if (!dot) return 0;

  for (int i = 0; i < pwlen; i++)
    lower[i] = fast_lower ((unsigned char) pw[i]);
  lower[pwlen] = '\0';

  for (int t = 0; t < (int) N_TLDS; t++)
  {
    const char *tld = tld_table[t].tld;
    int tlen        = tld_table[t].len;

    char *found = strstr (lower, tld);
    if (!found) continue;

    int tld_pos = found - lower;
    int end_pos = tld_pos + tlen;

    int at_pos = -1;
    for (int j = tld_pos - 1; j >= 0; j--)
    {
      if (lower[j] == '@')
      {
        at_pos = j;
        break;
      }
    }
    if (at_pos < 0) continue;

    /* The provider is the whole domain, the TLD included: "gmail.com", not
     * "gmail" - a list of second-level names is not what the format records. */
    *provlen = end_pos - at_pos - 1;
    if (*provlen <= 0 || *provlen >= 256) continue;
    memcpy (provider, lower + at_pos + 1, *provlen);
    provider[*provlen] = '\0';

    *email_start = 0;
    *email_end   = end_pos;
    return 1;
  }
  return 0;
}

/* Looks for domain.tld, with an optional http/www prefix. */
static int detect_website_in (const char *pw, int pwlen, char *lower,
                              int *web_start, int *web_end,
                              char *host, int *hostlen,
                              char *prefix, int *pfxlen)
{
  if (!memchr (pw, '.', pwlen)) return 0;

  for (int i = 0; i < pwlen; i++)
    lower[i] = fast_lower ((unsigned char) pw[i]);
  lower[pwlen] = '\0';

  for (int t = 0; t < (int) N_TLDS; t++)
  {
    const char *tld = tld_table[t].tld;
    int tlen        = tld_table[t].len;

    char *found = strstr (lower, tld);
    if (!found) continue;

    int tld_pos = found - lower;
    int end_pos = tld_pos + tlen;

    /* Boundary check: char after TLD must not be alnum or hyphen */
    if (end_pos < pwlen)
    {
      unsigned char c = (unsigned char) lower[end_pos];
      if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')
        continue;
    }

    while (end_pos < pwlen)
    {
      unsigned char c = (unsigned char) lower[end_pos];
      if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
          c == '.' || c == '-' || c == '_' || c == '/' || c == '?' ||
          c == ':' || c == '#' || c == '=' || c == '&' || c == '%')
        end_pos++;
      else
        break;
    }

    int dom_start = 0;
    for (int j = tld_pos - 1; j >= 0; j--)
    {
      if (lower[j] == '.' || lower[j] == '/' || lower[j] == ':' || lower[j] == ' ')
      {
        dom_start = j + 1;
        break;
      }
    }

    *hostlen = tld_pos + tlen - dom_start;
    if (*hostlen <= 0 || *hostlen >= 256) continue;
    memcpy (host, lower + dom_start, *hostlen);
    host[*hostlen] = '\0';

    *pfxlen    = 0;
    *web_start = dom_start;
    /* Check for URL prefix: one compare for "http", then branch */
    if (dom_start >= 7 && strncmp (lower + dom_start - 7, "http", 4) == 0)
    {
      char *hp = lower + dom_start - 7 + 4;
      if (dom_start >= 12 && strncmp (hp, "s://www.", 8) == 0)
      {
        *web_start = dom_start - 12;
        strcpy (prefix, "https://www.");
        *pfxlen = 12;
      }
      else if (dom_start >= 11 && strncmp (hp, "://www.", 6) == 0)
      {
        *web_start = dom_start - 11;
        strcpy (prefix, "http://www.");
        *pfxlen = 11;
      }
      else if (strncmp (hp, "s://", 4) == 0)
      {
        *web_start = dom_start - 8;
        strcpy (prefix, "https://");
        *pfxlen = 8;
      }
      else if (strncmp (hp, "://", 3) == 0)
      {
        *web_start = dom_start - 7;
        strcpy (prefix, "http://");
        *pfxlen = 7;
      }
    }
    else if (dom_start >= 4 && strncmp (lower + dom_start - 4, "www.", 4) == 0)
    {
      *web_start = dom_start - 4;
      strcpy (prefix, "www.");
      *pfxlen = 4;
    }

    *web_end = end_pos;
    return 1;
  }
  return 0;
}

int pcfg_tokenize (char *pw, int pwlen, pcfg_token_t *sects, int maxsects,
                   unsigned char *tag, char *lower, hp_seen_t *seen)
{
  if (seen != NULL)
  {
    seen->provlen = 0;
    seen->hostlen = 0;
    seen->pfxlen  = 0;
  }

  if (pwlen <= 0 || maxsects <= 0 || pwlen >= PCFG_MAXLINE) return 0;

  memset (tag, TAG_NONE, pwlen);

  pcfg_kb_walk_t walks[16];
  int nwalks = pcfg_keyboard_walks (pw, pwlen, walks, 16);
  for (int w = 0; w < nwalks; w++)
  {
    const unsigned char t = (w & 1) ? TAG_KBD_B : TAG_KBD;

    for (int j = walks[w].start; j < walks[w].start + walks[w].len; j++)
      tag[j] = t;
  }

  /* Email detection, over the untagged regions. */
  int em_start, em_end, provlen;
  char provider[256];
  if (detect_email_in (pw, pwlen, lower, &em_start, &em_end, provider, &provlen))
  {
    int ok = 1;
    for (int j = em_start; j < em_end; j++)
      if (tag[j] != TAG_NONE)
      {
        ok = 0;
        break;
      }
    if (ok)
    {
      for (int j = em_start; j < em_end; j++)
        tag[j] = TAG_EMAIL;

      /* Only a span actually taken counts: one the keyboard pass owns is not one. */
      if ((seen != NULL) && (provlen > 0))
      {
        memcpy (seen->provider, provider, (size_t) provlen);
        seen->provlen = provlen;
      }
    }
  }

  int wb_start, wb_end, hostlen, pfxlen;
  char host[256], pfx[64];
  if (detect_website_in (pw, pwlen, lower, &wb_start, &wb_end, host, &hostlen, pfx, &pfxlen))
  {
    int ok = 1;
    for (int j = wb_start; j < wb_end; j++)
      if (tag[j] != TAG_NONE)
      {
        ok = 0;
        break;
      }
    if (ok)
    {
      for (int j = wb_start; j < wb_end; j++)
        tag[j] = TAG_WEB;

      if ((seen != NULL) && (hostlen > 0))
      {
        memcpy (seen->host, host, (size_t) hostlen);
        seen->hostlen = hostlen;

        if (pfxlen > 0)
        {
          memcpy (seen->prefix, pfx, (size_t) pfxlen);
          seen->pfxlen = pfxlen;
        }
      }
    }
  }

  /* All four bytes have to be free, not just the first: checking one and writing
   * four overwrote the keyboard pass and stranded the tail of its walk. */
  for (int j = 0; j + 3 < pwlen; j++)
  {
    if (tag[j] != TAG_NONE) continue;
    if ((pw[j] == '1' && pw[j + 1] == '9') ||
        (pw[j] == '2' && pw[j + 1] == '0'))
    {
      if (pw[j + 2] >= '0' && pw[j + 2] <= '9' &&
          pw[j + 3] >= '0' && pw[j + 3] <= '9')
      {
        if (j > 0 && pw[j - 1] >= '0' && pw[j - 1] <= '9') continue;
        if (j + 4 < pwlen && pw[j + 4] >= '0' && pw[j + 4] <= '9') continue;

        if ((tag[j + 1] != TAG_NONE) || (tag[j + 2] != TAG_NONE) || (tag[j + 3] != TAG_NONE)) continue;

        tag[j] = tag[j + 1] = tag[j + 2] = tag[j + 3] = TAG_YEAR;
      }
    }
  }

  /* Context-sensitive patterns. Scanning all of them cost a memcmp per pattern
   * per position; a presence bitmap built in one pass skips those whose first
   * byte is absent. Order is unchanged, so the tagging is identical. */
  bool ctx_seen[256];
  memset (ctx_seen, 0, sizeof (ctx_seen));
  for (int j = 0; j < pwlen; j++) ctx_seen[(unsigned char) pw[j]] = true;

  for (int p = 0; p < (int) N_CONTEXT_PATS; p++)
  {
    const char *pat = context_pats[p].pat;
    int plen        = context_pats[p].len;
    if (!ctx_seen[(unsigned char) pat[0]]) continue;
    for (int j = 0; j + plen <= pwlen; j++)
    {
      if (pw[j] != pat[0]) continue;
      if (tag[j] != TAG_NONE) continue;
      if (memcmp (&pw[j], pat, plen) == 0)
      {
        if (pat[0] == '#' && pat[1] == '1' && j + plen < pwlen &&
            pw[j + plen] >= '0' && pw[j + plen] <= '9')
          continue;
        int ok = 1;
        for (int k = 0; k < plen; k++)
          if (tag[j + k] != TAG_NONE)
          {
            ok = 0;
            break;
          }
        if (!ok) continue;
        for (int k = 0; k < plen; k++)
          tag[j + k] = TAG_CTX;
        break;
      }
    }
  }

  int nsects = 0;
  int i      = 0;

  while (i < pwlen && nsects < maxsects - 1)
  {
    const int before = i;

    if (tag[i] == TAG_YEAR)
    {
      /* Consume the run, rather than assuming the four bytes are there. */
      const int start = i;

      while ((i < pwlen) && (tag[i] == TAG_YEAR)) i++;

      const int ylen = i - start;

      if (ylen == 4)
      {
        set_section_str (&sects[nsects], &pw[start], 4, "Y1", 1);
      }
      else
      {
        set_section (&sects[nsects], &pw[start], ylen, 'D', ylen);
      }

      nsects++;
    }
    else if (tag[i] == TAG_CTX)
    {
      int start = i;
      while (i < pwlen && tag[i] == TAG_CTX) i++;
      set_section_str (&sects[nsects], &pw[start], i - start, "X1", 1);
      nsects++;
    }
    else if (IS_KBD (tag[i]))
    {
      /* Four is the minimum for a walk, where the section is made and not tagged. */
      const unsigned char t = tag[i];
      const int start       = i;

      while (i < pwlen && tag[i] == t) i++;

      const int klen = i - start;

      if (klen >= 4)
      {
        set_section (&sects[nsects], &pw[start], klen, 'K', klen);
        nsects++;
      }
      else
      {
        for (int k = start; k < i; k++) tag[k] = TAG_NONE;
        i = start;
      }
    }
    else if (tag[i] == TAG_EMAIL)
    {
      int start = i;
      while (i < pwlen && tag[i] == TAG_EMAIL) i++;
      set_section_str (&sects[nsects], &pw[start], i - start, "E", 0);
      nsects++;
    }
    else if (tag[i] == TAG_WEB)
    {
      int start = i;
      while (i < pwlen && tag[i] == TAG_WEB) i++;
      set_section_str (&sects[nsects], &pw[start], i - start, "W", 0);
      nsects++;
    }
    else
    {
      uint32_t cp;
      int cpn = utf8_decode (pw + i, pwlen - i, &cp);
      if (cpn == 0)
      {
        i++;
        continue;
      }

      if (utf8_is_alpha (cp))
      {
        int start = i;
        while (i < pwlen && tag[i] == TAG_NONE)
        {
          int n = utf8_decode (pw + i, pwlen - i, &cp);
          if (n == 0 || !utf8_is_alpha (cp)) break;
          i += n;
        }
        int alen    = i - start;
        int cpcount = utf8_cplen (pw + start, alen);

        /* A run long enough to be two words is offered to the word set, in as many
         * pieces as a reader could seat. A split that would not fit is no split. */
        int parts[PCFG_MAXSLOT / 2];
        int nparts = 0;
        if (hp_words && cpcount >= 8)
          nparts = pcfg_multiword_parse (hp_words, &pw[start], alen, parts, PCFG_MAXSLOT / 2);

        if (nparts > 1)
        {
          int off = start;
          for (int p = 0; p < nparts && nsects < maxsects - 1; p++)
          {
            int pcp = utf8_cplen (pw + off, parts[p]);
            set_section (&sects[nsects], &pw[off], parts[p], 'A', pcp);
            nsects++;
            off += parts[p];
          }
        }
        else
        {
          set_section (&sects[nsects], &pw[start], alen, 'A', cpcount);
          nsects++;
        }
      }
      else if (utf8_is_digit (cp))
      {
        /* The entry test looks at the codepoint, so the run must too: a byte test
         * let a non-ASCII digit in and out without advancing i, forever. */
        int start = i;
        while (i < pwlen && tag[i] == TAG_NONE)
        {
          int n = utf8_decode (pw + i, pwlen - i, &cp);
          if (n == 0 || !utf8_is_digit (cp)) break;
          i += n;
        }
        int dlen = i - start;
        set_section (&sects[nsects], &pw[start], dlen, 'D', utf8_cplen (pw + start, dlen));
        nsects++;
      }
      else
      {
        int start = i;
        while (i < pwlen && tag[i] == TAG_NONE)
        {
          int n = utf8_decode (pw + i, pwlen - i, &cp);
          if (n == 0)
          {
            i++;
            continue;
          }
          if (utf8_is_alpha (cp) || utf8_is_digit (cp)) break;
          i += n;
        }
        int ocp = utf8_cplen (pw + start, i - start);
        set_section (&sects[nsects], &pw[start], i - start, 'O', ocp);
        nsects++;
      }
    }

    /* A safety net: every branch above has to advance i. Better to lose a byte. */
    if (i == before)
    {
      /* Skip the whole run, not one byte of it. */
      const unsigned char t0 = tag[i];

      do
      {
        i++;
      } while ((i < pwlen) && (tag[i] == t0));
    }
  }

  return nsects;
}
