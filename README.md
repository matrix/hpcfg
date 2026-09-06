# hpcfg - High-Performance PCFG trainer

A PCFG trainer. It trains; hashcat guesses.

Official repository: <https://github.com/matrix/hpcfg>

Its default output is a ruleset hashcat reads, in the same 4.x layout
pcfg_cracker, pcfg-go and Cpcfg use. Handing it to those three takes
`--ruleset-format pcfg-cracker`: the default declares hpcfg's own version, which
pcfg_cracker refuses, and leaves out the lists its loader opens regardless.

```sh
make
./hpcfg -t rockyou.txt -g /tmp/ruleset
./hpcfg -t hibp.txt -g /tmp/ruleset -w        # lines are count:password
hashcat -m 0 -a 4 hashes.txt /tmp/ruleset
```

## Building

A C compiler and pthreads, nothing else: no configure and no dependencies to
fetch. Go and Python are needed only to regenerate the Unicode tables and to run
the tests. `make` picks the OS up from `uname`.

| | |
|---|---|
| Linux, Android | `make` |
| macOS | `make` |
| FreeBSD, OpenBSD, NetBSD, DragonFly | `gmake` |
| Windows, under MSYS2 or Cygwin | `make`, which writes `hpcfg.exe` |
| Windows, cross-built from Linux | `make CC=x86_64-w64-mingw32-gcc` |

Any other `uname` is refused by name rather than failing later in the compile.
LTO is on where it works and off where it is known not to; `ENABLE_LTO=0` turns
it off by hand.

```sh
make info      # the OS it detected, the compiler target, whether LTO is on
make native    # -march=native: faster, and runs only on a CPU like this one
make clean
```

| flag | |
|---|---|
| `-t, --train <file>` | training wordlist, `-` for stdin |
| `-g, --ruleset-save <dir>` | ruleset to write |
| `-w, --weighted` | weighted input, `<count><sep><password>` |
| `-s, --sep <chars>` | bytes that may separate the count (default `:`) |
| `-f, --terminal-count-min <n>` | drop terminals seen fewer than n times |
| `-m, --mw-file <file>` | words to know before the corpus is read |
| `--count-min <n>` | with `--weighted`, skip lines whose count is below n |
| `-c, --coverage <0..1>` | the grammar's share against OMEN's; 0 is OMEN alone, 1 turns it off |
| `-S, --sensitive-enable` | also write the addresses and the URLs themselves |
| `--ruleset-format <name>` | who the ruleset is for: `hashcat` (default) writes what hashcat reads and what a merge reads back, `pcfg-cracker` adds what pcfg_cracker and pcfg-go need to load it |
| `--rulesets-merge <dir>` | fold rulesets together instead of training; `--rulesets-merge-weights a:b` to set the shares |
| `-i, --ruleset-info <dir>` | what the ruleset holds, and what is wrong with it |
| `--ruleset-diff <dir>` | with `-i`, how much of the mass two rulesets agree on |
| `--mw-threshold`, `--mw-len-min`, `--mw-len-max`, `--multiword-disable` | the splitting policy, which decides the terminals |
| `--mw-save <file>` | the words this run found, for the chunks of a split run to share |
| `--omen-alphabet-save <file>` / `--omen-alphabet-file <file>` | the byte frequencies the OMEN alphabet is chosen from |
| `-M, --memory-max <n>` | a ceiling on everything that grows with the corpus; without it a figure read off free memory decides when the counters spill |
| `--admission-min <n>` | a terminal earns a slot only once seen n times |
| `-n, --omen-ngram <n>` | OMEN n-gram size, 2 to 5 (default 4) |
| `--omen-level-max <n>` | deepest OMEN keyspace level, 1 to 40 (default 18); past it the escape generates nothing |
| `-J, --df-disable` | keep the lines the filters take for hashes, keys and tokens |
| `-T, --threads <n>` | threads counting (default: the machine's cores) |
| `-v, --verbose` | report what each pass costs |

### Looking at what came out

```sh
./hpcfg -i /tmp/ruleset                          # what it holds, and what is wrong with it
./hpcfg -i /tmp/ruleset --ruleset-diff /tmp/other   # how much of the mass the two agree on
```

### For a reader other than hashcat

```sh
./hpcfg -t rockyou.txt -g /tmp/ruleset --ruleset-format pcfg-cracker
```

### Training a corpus in pieces

A corpus too large for one run is trained in parts and folded together. The parts
have to share the word set and the byte frequencies, or each one chooses its own
and the pieces do not add up to what a single run would have given. So the first
pass reads the whole corpus for those two files and writes no ruleset - leave
`-g` off:

```sh
./hpcfg -t all.txt --mw-save words.txt --omen-alphabet-save bytes.txt

./hpcfg -t part1.txt -g rules.1 -m words.txt --omen-alphabet-file bytes.txt
./hpcfg -t part2.txt -g rules.2 -m words.txt --omen-alphabet-file bytes.txt

./hpcfg --rulesets-merge rules.1 --rulesets-merge rules.2 -g rules.all -t all.txt
```

`--rulesets-merge` is repeated once per ruleset, `-g` names the output, and `-t`
hands the merge a corpus to take the escape's level distribution from, which the
rulesets cannot carry between them. `--rulesets-merge-weights 1:2` sets the
shares by hand instead of taking each ruleset's own size.

That merge reproduces training on the union: the result above is identical to
`./hpcfg -t all.txt -g rules.one -m words.txt --omen-alphabet-file bytes.txt` in
every file but `config.ini`, which carries a fresh uuid and the names this run
was given.

Two things have to hold for that. The counters must not be bounded: a run
that reaches its `-M` budget, or that admits through `--admission-min` with a filter small
enough to collide, keeps whichever terminals its threads reached first, and two
such runs of one input need not agree. And the escape must divide evenly. It
takes `floor(passwords * (1 - coverage) / coverage)` slots, so two halves round
down twice where the whole rounds once: a corpus that does not divide leaves the
merge one count short, which moves every probability in `Grammar/grammar.txt`
by about 1e-5 and one figure in `totals.txt` by one. No terminal list changes.

The names follow hashcat-pcfg-dev's: a domain, then the subject, then the qualifier last.
The spellings hpcfg used before still work, undocumented, so nothing scripted against them breaks.
`-h` lists the rest.

`tests/hpcfg_test.py` holds the checks. It needs Python and nothing else, builds
every corpus it uses, and runs the same on Windows:

```sh
python tests/hpcfg_test.py                 # 57 tests, four of them skipped
python tests/hpcfg_test.py --list          # what each one checks
python tests/hpcfg_test.py -s omen -v      # one section, naming every test
python tests/hpcfg_test.py -k merge        # only tests whose name contains this
```

Four of them ask another implementation to open a ruleset hpcfg wrote, and are
skipped until it is given. They are the ones worth running before a release,
because they are the only ones that check hpcfg against something other than
itself:

```sh
python tests/hpcfg_test.py \
  --hashcat /path/to/hashcat \
  --pcfg-cracker /path/to/pcfg_cracker/pcfg_guesser.py \
  --pcfg-go /path/to/pcfg_guesser \
  --cpcfg /path/to/Cpcfg/pcfg
```

`--hpcfg <path>` tests a binary other than `./hpcfg`, and `--keep` leaves the
scratch directory behind and says where it is.

`src/pcfg_unicode_tables.c` decides what counts as a letter, a digit and an
uppercase one. It is generated from Go's own tables, which are what pcfg-go asks
through `unicode.IsLetter`, so the two agree by construction at the version the
tables were generated at. The result is committed, so building needs neither Go
nor Python:

```sh
cd tools && go run gen_unicode_tables.go > ../src/pcfg_unicode_tables.c
```

The generated file names the Unicode version it carries. Go's tables move with
its releases, so regenerating against a newer toolchain reclassifies codepoints
and changes what the trainer counts: 15.0.0 to 17.0.0 moved 9.658 of them, none
below U+0500 and sixteen inside the BMP. It is a decision, not a refresh.

## Against the implementations it descends from

Measured on one idle machine, 20 cores and 62 GB, gcc 13.3 with `-O3 -flto`,
one trainer at a time, three runs each, median wall clock and highest peak RSS.
Against [Cpcfg](https://github.com/Cynosureprime/Cpcfg) at `7fc67d2` and
[pcfg-go](https://github.com/cyclone-github/pcfg-go) at `8fb59c2`, each built
from a fresh clone of its default branch and run with its own defaults.

**hashmob.net combined founds, 2.453.669.782 lines, 29.2 GiB** - the whole
public archive, `hashmob.net_2026-09-06.official.found` out of
`cdn.hashmob.net/combined_founds/`:

| | | time | peak |
|---|---|---|---|
| **hpcfg** | **finished, 13 GB ruleset** | **18m 06s** | **44.9 GB** |
| Cpcfg | killed at ~5% of the corpus | 5m 35s | 58.3 GB |
| pcfg-go | killed while still loading | 2m 50s | 60.6 GB |

Both of the others were killed by the kernel, `rc=137`, having asked for more
memory than the machine has. hpcfg finished because it spills: four spills of
about 105 million terminals each, merged at the end. The ruleset it wrote
passes `--ruleset-info` with no anomalies - 21.7M structures, 369.8M terminals
in 921 lists, the grammar summing to 1.000000.

**Weighted rockyou, 14.344.391 lines**, `<count> <password>`:

| | time | peak |
|---|---|---|
| **hpcfg** | **10.12s** | **1.65 GB** |
| pcfg-go | 11.09s | 5.09 GB |
| Cpcfg | 14.16s | 14.95 GB |

Fastest on both, in a ninth of Cpcfg's memory on rockyou and a third of
pcfg-go's. The gap that matters is the first table's: a corpus large enough
that the other two do not finish at all.

It reads better than the detectors it descends from because three defects in
them were found by refusing to call a residual difference "known":

- the year pass checked one byte was free and wrote four, overwriting the
  keyboard pass and leaving one- and two-character "keyboard walks" behind,
  which the minimum of four says cannot exist;
- consecutive keyboard walks are contiguous in a password, and collecting a run
  of one tag merged them: `1qaz2wsx3edc` became a single rare K12 instead of
  the three common terminals `1qaz`, `2wsx`, `3edc`;
- `utf8_to_lower` assumed one parity across all of Latin Extended-A, where it
  changes twice, and lowercased the Turkish dotted capital I to the dotless one.

The two deliberate departures - a multiword set completed before any password
is parsed against it, and a flat table in place of the trie - are what make
training deterministic: the same corpus trains to the same ruleset, byte for
byte, which is what lets `--rulesets-merge` reproduce it.

`tests/hpcfg_test.py --cpcfg <path>` runs that comparison. With `--hashcat` it
trains and asks hashcat what it generates first.

## State

Trains, counts on every core, and writes a ruleset hashcat reads, OMEN included.
Bounded by a memory budget and an admission filter rather than by hope. Rulesets
can be folded together afterwards with `--rulesets-merge`, which is what lets a corpus be
trained in pieces. Not yet done: the extended ruleset.

Under `--ruleset-format pcfg-cracker` the ruleset is read by pcfg_cracker and
pcfg-go, which is checked rather than claimed: trained on the same million lines of rockyou,
hpcfg, pcfg-go and pcfg_cracker produce the same directory and the same length
levels, and hashcat opens all three with the same ten candidates. Over half a
million candidates hpcfg agrees with pcfg-go on 99.7% and with pcfg_cracker on
97.2% - and the two of them agree with each other on 97.2%, so what is left is
the distance between those two implementations rather than hpcfg's distance
from either. Handed hpcfg's ruleset, pcfg_cracker generates what it generates
from its own.

Two of the rules the output has to satisfy were found by this comparison, and
both were wrong for hashcat too.
