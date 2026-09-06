/**
 * Author......: Gabriele "matrix" Gristina
 * License.....: MIT
 *
 * Keyboard walks: runs of keys that neighbour each other on some layout.
 */

#include <ctype.h>
#include <stdint.h>
#include <string.h>

#include "pcfg_common.h"
#include "pcfg_platform.h"

#define PCFG_KB_LAYOUTS 5
#define PCFG_KB_KEYS 128
#define PCFG_KB_MIN 4 /* the shortest walk Weir records */

/* A non-ASCII key cannot begin or continue a walk, but it still occupies a place:
 * dropping it from a row moves every key to its right one column left, making
 * keys that do not touch look adjacent. This byte holds the column. */
#define PCFG_KB_GAP '\x01'
#define PCFG_KB_WALKS 16

/* A key's place in a byte: zero where the layout has no such key, otherwise the
 * row in the high nibble and the column in the low one. */
#define PCFG_KB_AT(row, col) ((uint8_t) ((((row) + 1) << 4) | ((col) & 0x0f)))
#define PCFG_KB_ROW(v) (((v) >> 4) - 1)
#define PCFG_KB_COL(v) ((v) & 0x0f)

typedef struct
{
  const char *plain;
  const char *shifted; /* NULL where the layout does not shift into ASCII */
} pcfg_kb_row_t;

typedef struct
{
  const char *name;
  pcfg_kb_row_t rows[8];
} pcfg_kb_layout_t;

/* The five layouts, each as the rows a finger walks along, ASCII only. */
static const pcfg_kb_layout_t pcfg_kb_layouts[PCFG_KB_LAYOUTS] = {
  { "qwerty", { { "1234567890-=", "!@#$%^&*()_+" }, { "qwertyuiop[]\\", "QWERTYUIOP{}|" }, { "asdfghjkl;'", "ASDFGHJKL:\"" }, { "zxcvbnm,./", "ZXCVBNM<>?" }, { NULL, NULL } } },

  { "jcuken", { { "1234567890-=", "!\""
                                  "\x01"
                                  ";%:?*()_+" },
                { NULL, NULL } }                                                                                                                                  },

  { "qwertz", { { "1234567890", "!\"$%&/()=?" }, { "qwertzuiop", "QWERTZUIOP" }, { "asdfghjkl", "ASDFGHJKL" }, { "yxcvbnm,.-", "YXCVBNM;:_" }, { NULL, NULL } }                },

  { "azerty", { { "1234567890", NULL }, { "azertyuiop", "AZERTYUIOP" }, { "qsdfghjklm", "QSDFGHJKLM" }, { "wxcvbn,;:!", "WXCVBN?./"
                                                                                                                        "\x01" },
                { NULL, NULL } }                                                                                                                                  },

  { "dvorak", { { "1234567890[]", "!@#$%^&*(){}" }, { "',.pyfgcrl/=\\", "\"<>PYFGCRL?+|" }, { "aoeuidhtns-", "AOEUIDHTNS_" }, { ";qjkxbmwvz", ":QJKXBMWVZ" }, { NULL, NULL } } },
};

/* Where each byte sits, per layout, and which layouts have it at all. */
static uint8_t pcfg_kb_place[PCFG_KB_LAYOUTS][PCFG_KB_KEYS];
static uint8_t pcfg_kb_known[PCFG_KB_KEYS];

/* Bit l set when the two bytes are a step on layout l. */
static uint8_t pcfg_kb_step[PCFG_KB_KEYS][PCFG_KB_KEYS];

static hp_once_t pcfg_kb_once = HP_ONCE_INIT;

static void pcfg_kb_place_row (int layout, int row, const char *keys)
{
  if (keys == NULL) return;

  for (int col = 0; keys[col] != 0; col++)
  {
    const unsigned char c = (unsigned char) keys[col];

    if (c >= PCFG_KB_KEYS) continue;

    if (c == PCFG_KB_GAP) continue; /* holds the column, is not a key */

    pcfg_kb_place[layout][c] = PCFG_KB_AT (row, col);

    pcfg_kb_known[c] |= (uint8_t) (1u << layout);
  }
}

static void pcfg_kb_build (void)
{
  memset (pcfg_kb_place, 0, sizeof (pcfg_kb_place));
  memset (pcfg_kb_known, 0, sizeof (pcfg_kb_known));
  memset (pcfg_kb_step, 0, sizeof (pcfg_kb_step));

  for (int l = 0; l < PCFG_KB_LAYOUTS; l++)
  {
    for (int r = 0; pcfg_kb_layouts[l].rows[r].plain != NULL; r++)
    {
      pcfg_kb_place_row (l, r, pcfg_kb_layouts[l].rows[r].plain);
      pcfg_kb_place_row (l, r, pcfg_kb_layouts[l].rows[r].shifted);
    }
  }

  /* From each key to the eight around it: a few thousand lookups, not eighty thousand. */
  for (int l = 0; l < PCFG_KB_LAYOUTS; l++)
  {
    /* The bytes at each coordinate: it can hold the plain one and the shifted. */
    unsigned char at[16][16][2];
    int nat[16][16];

    memset (nat, 0, sizeof (nat));

    for (int c = 0; c < PCFG_KB_KEYS; c++)
    {
      const uint8_t p = pcfg_kb_place[l][c];

      if (p == 0) continue;

      const int r = PCFG_KB_ROW (p);
      const int x = PCFG_KB_COL (p);

      if (nat[r][x] < 2) at[r][x][nat[r][x]++] = (unsigned char) c;
    }

    for (int c = 0; c < PCFG_KB_KEYS; c++)
    {
      const uint8_t p = pcfg_kb_place[l][c];

      if (p == 0) continue;

      const int r = PCFG_KB_ROW (p);
      const int x = PCFG_KB_COL (p);

      for (int dr = -1; dr <= 1; dr++)
      {
        for (int dx = -1; dx <= 1; dx++)
        {
          if ((dr == 0) && (dx == 0)) continue; /* a key is not its own step */

          const int nr = r + dr;
          const int nx = x + dx;

          if ((nr < 0) || (nr > 15) || (nx < 0) || (nx > 15)) continue;

          for (int k = 0; k < nat[nr][nx]; k++)
            pcfg_kb_step[c][at[nr][nx][k]] |= (uint8_t) (1u << l);
        }
      }
    }
  }
}

static void pcfg_kb_init (void)
{
  /* Once for the process: "if (done) return; done = 1;" lets a second thread in
   * before the first has finished, and passwords lose their keyboard section. */
  hp_once (&pcfg_kb_once, pcfg_kb_build);
}

/* Whether a run that is adjacent all the way is also worth recording. */
static const char *const pcfg_kb_not_walks[] = { "drew", "kiki", "fred", "were", "pop", "123;", "234;", NULL };

static bool pcfg_kb_worth_it (const char *run, int len)
{
  if (len < PCFG_KB_MIN) return false;

  /* Openings that are the start of a word rather than of a walk. */
  if (run[0] == 'e') return false;
  if (run[0] == 'y') return false;
  if ((run[0] == 't') && (run[1] == 'y')) return false;
  if ((run[1] == 'e') && (run[2] == 'r')) return false;
  if ((run[0] == 't') && (run[1] == 't') && (run[2] == 'y')) return false;
  if ((run[0] == '1') && (run[1] == '2') && (run[2] == '3')) return false;

  /* And the one ending: "...123" is a suffix unless a q leads into it. */
  if ((run[len - 1] == '3') && (run[len - 2] == '2') && (run[len - 3] == '1') && (run[len - 4] != 'q') && (run[len - 4] != 'Q')) return false;

  for (int w = 0; pcfg_kb_not_walks[w] != NULL; w++)
  {
    const char *word = pcfg_kb_not_walks[w];
    const int wlen   = (int) strlen (word);

    for (int i = 0; (i + wlen) <= len; i++)
    {
      int j = 0;

      while ((j < wlen) && (tolower ((unsigned char) run[i + j]) == word[j])) j++;

      if (j == wlen) return false;
    }
  }

  /* Two kinds of character out of letters, digits and the rest. */
  int kinds = 0, letter = 0, digit = 0, other = 0;

  for (int i = 0; i < len; i++)
  {
    const unsigned char c = (unsigned char) run[i];

    if (isalpha (c))
      letter = 1;
    else if (isdigit (c))
      digit = 1;
    else
      other = 1;
  }

  kinds = letter + digit + other;

  return (kinds >= 2) ? true : false;
}

/* Every walk in a password, left to right. */
int pcfg_keyboard_walks (const char *pw, int pwlen, pcfg_kb_walk_t *walks, int max_walks)
{
  pcfg_kb_init ();

  if (pwlen < PCFG_KB_MIN) return 0;

  int found = 0;
  int at    = 0;
  int len   = 1;

  unsigned live = pcfg_kb_known[(unsigned char) pw[0] & 0x7f];

  if ((unsigned char) pw[0] >= PCFG_KB_KEYS) live = 0;

  for (int i = 1; i <= pwlen; i++)
  {
    const unsigned char a = (unsigned char) pw[i - 1];
    const unsigned char b = (i < pwlen) ? (unsigned char) pw[i] : 0;

    unsigned next = 0;

    if ((i < pwlen) && (a < PCFG_KB_KEYS) && (b < PCFG_KB_KEYS)) next = live & pcfg_kb_step[a][b];

    if (next != 0)
    {
      live = next;
      len++;

      continue;
    }

    if ((len >= PCFG_KB_MIN) && (found < max_walks) && (pcfg_kb_worth_it (pw + at, len) == true))
    {
      walks[found].start = at;
      walks[found].len   = len;

      found++;
    }

    at   = i;
    len  = 1;
    live = (b < PCFG_KB_KEYS) ? pcfg_kb_known[b] : 0u;
  }

  return found;
}
