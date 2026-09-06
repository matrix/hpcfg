/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * What a line has to survive before it counts as a password.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcfg_common.h"
#include "pcfg_platform.h"
#include "pcfg_trainer_utils.h"

static const int8_t hex_lut[256] = {
  ['0'] = 0,
  ['1'] = 1,
  ['2'] = 2,
  ['3'] = 3,
  ['4'] = 4,
  ['5'] = 5,
  ['6'] = 6,
  ['7'] = 7,
  ['8'] = 8,
  ['9'] = 9,
  ['a'] = 10,
  ['b'] = 11,
  ['c'] = 12,
  ['d'] = 13,
  ['e'] = 14,
  ['f'] = 15,
  ['A'] = 10,
  ['B'] = 11,
  ['C'] = 12,
  ['D'] = 13,
  ['E'] = 14,
  ['F'] = 15,
  /* everything else is zero, so a non-hex byte has to be rejected by test */
};

static inline bool is_hex_digit (unsigned char c)
{
  return ((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F'));
}

/* "$HEX[...]" to bytes. Returns the decoded length, or -1 if it is not one. */
int hp_unhex (const char *s, int len, char *out, int outmax)
{
  if (len < 7) return -1;
  if (memcmp (s, "$HEX[", 5) != 0) return -1;
  if (s[len - 1] != ']') return -1;

  const int n = len - 6;

  if ((n & 1) != 0) return -1;
  if ((n / 2) > outmax) return -1;

  for (int i = 0; i < n; i += 2)
  {
    const unsigned char hi = (unsigned char) s[5 + i];
    const unsigned char lo = (unsigned char) s[6 + i];

    if ((is_hex_digit (hi) == false) || (is_hex_digit (lo) == false)) return -1;

    out[i / 2] = (char) ((hex_lut[hi] << 4) | hex_lut[lo]);
  }

  return n / 2;
}

/* What is left after decoding $HEX[]: bytes from a file that was not text. */

static int trim_ends (const char *s, int len, int *start_out)
{
  int a = 0, b = len;

  for (;;)
  {
    while ((a < b) && (((unsigned char) s[a] == 0x20) || ((unsigned char) s[a] == 0x09) ||
                       ((unsigned char) s[a] == 0x0A) || ((unsigned char) s[a] == 0x0D))) a++;

    /* the non-breaking space, which arrives stuck to values copied off the web */
    if (((b - a) >= 2) && ((unsigned char) s[a] == 0xC2) && ((unsigned char) s[a + 1] == 0xA0))
    {
      a += 2;
      continue;
    }

    break;
  }

  while ((b > a) && (((unsigned char) s[b - 1] == 0x20) || ((unsigned char) s[b - 1] == 0x09) ||
                     ((unsigned char) s[b - 1] == 0x0A) || ((unsigned char) s[b - 1] == 0x0D))) b--;

  *start_out = a;

  return b - a;
}

/* LE, BE or neither, the count hashcat-pcfg uses: which side the null bytes fall
 * on decides the order, and too many double NULs say it is not text at all. */
static int utf16_kind (const unsigned char *d, int len)
{
  if ((len < 4) || ((len & 1) != 0)) return 0;

  const int pairs = len / 2;

  int le = 0, be = 0, nul = 0;

  for (int i = 0; i < len; i += 2)
  {
    if ((d[i] == 0) && (d[i + 1] == 0))
      nul++;
    else if (d[i] == 0)
      be++;
    else if (d[i + 1] == 0)
      le++;
  }

  if (nul > (pairs / 10)) return 0;

  if ((le >= ((pairs * 7) / 10)) && (be < (pairs / 5))) return 1; /* LE */
  if ((be >= ((pairs * 7) / 10)) && (le < (pairs / 5))) return 2; /* BE */

  return 0;
}

static int utf16_to_utf8 (const unsigned char *d, int len, int kind, char *out, int outmax)
{
  int o = 0;

  for (int i = 0; i < len; i += 2)
  {
    uint32_t u = (kind == 1) ? (uint32_t) (d[i] | (d[i + 1] << 8))
                             : (uint32_t) ((d[i] << 8) | d[i + 1]);

    if ((u >= 0xD800) && (u <= 0xDBFF))
    {
      if ((i + 3) >= len) return 0;

      const uint32_t lo = (kind == 1) ? (uint32_t) (d[i + 2] | (d[i + 3] << 8))
                                      : (uint32_t) ((d[i + 2] << 8) | d[i + 3]);

      if ((lo < 0xDC00) || (lo > 0xDFFF)) return 0;

      u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);

      i += 2;
    }
    else if ((u >= 0xDC00) && (u <= 0xDFFF))
      return 0; /* orphan low surrogate */

    if ((o + 4) > outmax) return 0;

    const int n = utf8_encode (out + o, u);

    if (n <= 0) return 0;

    o += n;
  }

  return o;
}

int hp_recover (char *buf, int len, int outmax)
{
  if (len <= 0) return len;

  int start = 0;

  len = trim_ends (buf, len, &start);

  if (len <= 0) return 0;

  const unsigned char *d = (const unsigned char *) (buf + start);

  int kind = utf16_kind (d, len);
  int off  = 0;

  /* the stray NUL left in front by a reader splitting a UTF-16 file on the 0A byte */
  if ((kind == 0) && (len > 1) && (d[0] == 0))
  {
    kind = utf16_kind (d + 1, len - 1);
    if (kind != 0) off = 1;
  }

  /* and the same at the end, when the split falls on the other side */
  if ((kind == 0) && (len > 1) && (d[len - 1] == 0))
  {
    kind = utf16_kind (d, len - 1);
    if (kind != 0) len -= 1;
  }

  if (kind != 0)
  {
    char tmp[PCFG_MAXLINE];

    const int n = utf16_to_utf8 (d + off, len - off, kind, tmp, (int) sizeof (tmp));

    if (n > 0)
    {
      /* the text may end in its own CR even after the conversion */
      int s2      = 0;
      const int m = trim_ends (tmp, n, &s2);

      if ((m > 0) && (m <= outmax))
      {
        memmove (buf, tmp + s2, (size_t) m);
        return m;
      }
    }

    /* It would not convert: it stays as it was, and the validity check drops it. */
  }

  if (start != 0) memmove (buf, buf + start, (size_t) len);

  return len;
}

/* The tags hash formats write in front of themselves, from hashcat's modules:
 * the part between the first two dollars of each declared signature. */
static const char *hash_tags[] = {
  "/zip2", "1", "2a", "2b", "2x", "2y", "5", "6", "7", "7z", "8", "9", "ASN", "AWS-Sig-v4",
  "B", "BLAKE2", "DCC2", "DPAPImk", "H", "MSONLINEACCOUNT", "P", "PEM", "PHPS", "RAR3", "S",
  "SHA", "SNMPv3", "WINHELLO", "ab", "aescrypt", "ansible", "apr1", "argon2d", "argon2i",
  "argon2id", "as400", "axcrypt", "axcrypt_sha1", "bcve", "bisq", "bitcoin", "bitlocker",
  "bitwarden", "blockchain", "chacha20", "cram_md5", "cryptoapi", "diskcryptor", "dogechain",
  "ecryptfs", "electrum", "encdv", "encdv-pbkdf2", "episerver", "ethereum", "fde", "fvde",
  "gost12512hash", "gpg", "gy", "itunes_backup", "iwork", "jksprivk", "keepass", "keychain",
  "kgb", "knx-ip-secure-device-authentication-code", "krb5asrep", "krb5db", "krb5pa",
  "krb5tgs", "luks", "metamask", "metamask-short", "metamaskMobile", "ml", "mobilekeychain",
  "mongodb-scram", "mozilla", "multibit", "mysql", "mysqlna", "odf", "office", "oldoffice",
  "pbkdf2-hmac-sha1", "pbkdf2-hmac-sha512", "pbkdf2-sha256", "pdf", "pkzip", "pkzip2",
  "postgres", "racf", "racf-kdfaes", "radmin3", "rar5", "rc4", "sha1", "shiro1", "sip",
  "sm3", "sntp-ms", "solarwinds", "sshng", "sspr", "stellar", "tacacs-plus", "teamspeak",
  "telegram", "truecrypt", "uido", "vbk", "vbox", "veracrypt", "vmx", "wp", "y", "zip2",
  "zip3"
};

static const int hash_tags_cnt = (int) (sizeof (hash_tags) / sizeof (hash_tags[0]));

/* $tag$... : the frame of two dollars is what makes the tag trustworthy */
static bool is_tagged_hash (const char *s, int len)
{
  if ((len < 4) || (s[0] != '$')) return false;

  int end = 1;

  while ((end < len) && (end < 46) && (s[end] != '$')) end++;

  if ((end >= len) || (s[end] != '$')) return false;

  const int tlen = end - 1;

  for (int i = 0; i < hash_tags_cnt; i++)
  {
    if ((int) strlen (hash_tags[i]) != tlen) continue;
    if (memcmp (s + 1, hash_tags[i], (size_t) tlen) == 0) return true;
  }

  return false;
}

static inline bool b64ish (unsigned char c)
{
  return (((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) ||
          ((c >= '0') && (c <= '9')) || (c == '+') || (c == '/') || (c == '=') ||
          (c == '.') || (c == '$') || (c == '-'));
}

/* The {SCHEME}base64 of LDAP servers. Braces alone are a plausible password;
 * braces followed by sixteen characters of base64 are not. */
static bool is_ldap_scheme (const char *s, int len)
{
  if ((len < 20) || (s[0] != '{')) return false;

  int end = 1;

  while ((end < len) && (end < 18) && (s[end] != '}')) end++;

  if ((end >= len) || (s[end] != '}') || (end < 3)) return false;

  for (int i = 1; i < end; i++)
  {
    const unsigned char c = (unsigned char) s[i];

    if (!(((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) ||
          ((c >= '0') && (c <= '9')) || (c == '-') || (c == '_'))) return false;
  }

  if ((len - end - 1) < 16) return false;

  for (int i = end + 1; i < len; i++)
    if (b64ish ((unsigned char) s[i]) == false) return false;

  return true;
}

/* A digest in plain hexadecimal, alone or with its salt. The lengths are the
 * functions' own rather than a range: 32, 40, 56, 64, 96, 128. */
static bool is_bare_digest (const char *s, int len)
{
  int n = 0;

  while ((n < len) && (is_hex_digit ((unsigned char) s[n]) == true)) n++;

  /* Sixteen is LM and DES; past forty-eight it is a blob, and nobody types one. */
  const bool digest_len = ((n == 16) || (n == 32) || (n == 40) || (n == 56) ||
                           (n == 64) || (n == 96) || (n == 128) || ((n >= 48) && ((n & 1) == 0)));

  if (digest_len == false) return false;

  /* At least one letter: a string of digits is valid hexadecimal, and two dates
   * run together are not a digest. One of digits alone is rare enough to let by. */
  bool letter = false;

  for (int i = 0; i < n; i++)
  {
    const unsigned char c = (unsigned char) s[i];

    if (((c | 0x20) >= 'a') && ((c | 0x20) <= 'f'))
    {
      letter = true;
      break;
    }
  }

  if (letter == false) return false;

  if (n == len) return true;

  return ((s[n] == ':') || (s[n] == '*') || (s[n] == '$')) ? true : false;
}

/* A blob in base64. Length alone is not enough, but real base64 sooner or later
 * uses a plus, a slash or the trailing padding. */
static bool is_b64_blob (const char *s, int len)
{
  if (len < 40) return false;

  bool marked = false;

  for (int i = 0; i < len; i++)
  {
    const unsigned char c = (unsigned char) s[i];

    if ((c == '+') || (c == '/') || (c == '='))
    {
      marked = true;
      continue;
    }

    if (!(((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) ||
          ((c >= '0') && (c <= '9')))) return false;
  }

  return marked;
}

/* The colon-separated field formats, NetNTLM among them. What gives them away is
 * how many colons a long line carries, which a password does not. */
static bool is_field_blob (const char *s, int len)
{
  if (len < 60) return false;

  int colons = 0;

  for (int i = 0; i < len; i++)
    if (s[i] == ':') colons++;

  return (colons >= 4) ? true : false;
}

/* Formats that announce themselves, each wanting enough behind it to be a hash. */
static bool is_known_prefix (const char *s, int len)
{
  static const struct
  {
    const char *p;
    int minlen;
  } pre[] = {
    { "0x0100",         20 },
    { "0x0200",         20 },
    { "0xc007",         20 },
    { "grub.pbkdf2.",   40 },
    { "v1;PPH1_",       20 },
    { "SCRAM-SHA-",     30 },
    { "sha1$",          30 },
    { "sha256$",        30 },
    { "sha512$",        30 },
    { "md5$",           30 },
    { "pbkdf2_sha256$", 30 },
    { "pbkdf2-sha256$", 30 },
    { "pbkdf2-sha512$", 30 },
    { "pbkdf2-sha1$",   30 },
    { "WPA*",           30 },
    { "SCRYPT:",        30 },
    { "xmpp-scram",     30 },
    { "SQLCIPHER",      30 },
    { "PWS3",           30 },
    { "EXODUS",         30 },
    { "SHA256:",        30 },
  };

  for (size_t i = 0; i < (sizeof (pre) / sizeof (pre[0])); i++)
  {
    const int n = (int) strlen (pre[i].p);

    if ((len >= pre[i].minlen) && (len > n) && (memcmp (s, pre[i].p, (size_t) n) == 0)) return true;
  }

  return false;
}

bool hp_is_password (const char *s, int len)
{
  if (len <= 0) return false;

  for (int i = 0; i < len; i++)
  {
    const unsigned char c = (unsigned char) s[i];

    if (c < 0x20) return false; /* tab and every other control byte */

    /* DEL is left alone: it survives the file format, so rejecting it would be
     * this tool's own idea. U+0085 and U+2028 do not survive it. */
    if ((c == 0xC2) && ((i + 1) < len) && ((unsigned char) s[i + 1] == 0x85)) return false;
    if ((c == 0xE2) && ((i + 2) < len) &&
        ((unsigned char) s[i + 1] == 0x80) && ((unsigned char) s[i + 2] == 0xA8)) return false;
  }

  return true;
}

bool hp_is_junk (const char *s, int len)
{
  if (len < 6) return false;

  /* JWT: three base64 parts, and it announces itself */
  if ((len > 36) && (s[0] == 'e') && (s[1] == 'y') && (s[2] == 'J'))
  {
    int dots = 0;

    for (int i = 0; i < len; i++)
      if (s[i] == '.') dots++;

    if (dots == 2) return true;
  }

  /* PKCS#8 and PKCS#1 keys, and OpenSSH public keys */
  if ((len >= 40) && (s[0] == 'M') && (s[1] == 'I') && (s[2] == 'I')) return true;
  if ((len >= 20) && (memcmp (s, "AAAA", 4) == 0)) return true;

  if (is_tagged_hash (s, len) == true) return true;
  if (is_ldap_scheme (s, len) == true) return true;
  if (is_bare_digest (s, len) == true) return true;
  if (is_known_prefix (s, len) == true) return true;
  if (is_b64_blob (s, len) == true) return true;
  if (is_field_blob (s, len) == true) return true;

  /* A wallet seed in base58, which has no 0, O, I or l */
  if ((len >= 80) && (len <= 120))
  {
    bool b58 = true;

    for (int i = 0; (i < len) && (b58 == true); i++)
    {
      const char c = s[i];

      if (!(((c >= '1') && (c <= '9')) || ((c >= 'A') && (c <= 'H')) ||
            ((c >= 'J') && (c <= 'N')) || ((c >= 'P') && (c <= 'Z')) ||
            ((c >= 'a') && (c <= 'k')) || ((c >= 'm') && (c <= 'z')))) b58 = false;
    }

    if (b58 == true) return true;
  }

  /* A UUID or a 32-byte key written as base64 */
  if (((len == 44) || (len == 48)) && (s[len - 1] != '='))
  {
    bool b64 = true;

    for (int i = 0; (i < len) && (b64 == true); i++)
    {
      const char c = s[i];

      if (!(((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) ||
            ((c >= '0') && (c <= '9')) || (c == '+') || (c == '/'))) b64 = false;
    }

    if (b64 == true) return true;
  }

  return false;
}

/* How much memory to take when nobody said. */
size_t hp_default_budget (void)
{
  const size_t avail = hp_available_ram ();

  if (avail == 0) return 0; /* cannot tell, so do not pretend to */

  const double share = (hp_is_desktop () == true) ? 0.60 : 0.80;

  return (size_t) ((double) avail * share);
}
