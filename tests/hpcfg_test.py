#!/usr/bin/env python3
"""
hpcfg functional test suite.

One file, standard library only, so that the same command runs on Linux, macOS
and Windows.  It builds every corpus it needs, so nothing outside the tree has
to be downloaded or kept in step.

    python tests/hpcfg_test.py
    python tests/hpcfg_test.py --list
    python tests/hpcfg_test.py -k keyboard -v

The core tests need the hpcfg binary and nothing else.  The interoperability
tests need the readers they are about, and are reported as skipped when those
are not given:

    python tests/hpcfg_test.py --hashcat ../hashcat/hashcat \\
                               --pcfg-cracker ../pcfg_cracker/pcfg_guesser.py \\
                               --pcfg-go ../pcfg-go/pcfg_guesser

The exit status is 0 when every test that ran passed.  A skip is not a failure;
what was skipped, and why, is printed at the end.
"""

import argparse
import configparser
import filecmp
import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# How far a probability may be off before it counts as wrong.  Terminal lists
# are normalised as they are written, so this is float noise, not tolerance for
# a real difference.
EPS = 1e-9


# ---------------------------------------------------------------------------
# Test registry
# ---------------------------------------------------------------------------

TESTS = []


class Skip(Exception):
    """Raised by a test that cannot run here.  Not a failure."""


def test(section, needs=None):
    """Register a test.  `needs` names an optional external tool."""
    def deco(fn):
        TESTS.append({
            "section": section,
            "name": fn.__name__[5:] if fn.__name__.startswith("test_") else fn.__name__,
            "fn": fn,
            "needs": needs,
            "doc": (fn.__doc__ or "").strip().split("\n")[0],
        })
        return fn
    return deco


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def check_eq(got, want, what):
    if got != want:
        raise AssertionError("%s: got %r, want %r" % (what, got, want))


# ---------------------------------------------------------------------------
# Running hpcfg
# ---------------------------------------------------------------------------

class Env:
    """Everything a test is handed: the binary, the tools, a scratch directory."""

    def __init__(self, hpcfg, tools, workdir):
        self.hpcfg = hpcfg
        self.tools = tools
        self.workdir = workdir
        self._n = 0

    def tmp(self, name):
        """A fresh path under the scratch directory.  Not created."""
        self._n += 1
        return self.workdir / ("%03d_%s" % (self._n, name))

    def run(self, *args, stdin=None, want_ok=True, timeout=600):
        """Run hpcfg.  Returns (returncode, stdout, stderr) as text."""
        argv = [str(self.hpcfg)] + [str(a) for a in args]
        data = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
        p = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout)
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace")
        if want_ok and p.returncode != 0:
            raise AssertionError(
                "hpcfg %s exited %d\n--- stdout ---\n%s\n--- stderr ---\n%s"
                % (" ".join(str(a) for a in args), p.returncode, out, err))
        return p.returncode, out, err

    def train(self, corpus, name="rs", *extra):
        """Train on `corpus`, return the ruleset directory."""
        out = self.tmp(name)
        self.run("-t", corpus, "-g", out, *extra)
        return out

    def tool(self, key):
        path = self.tools.get(key)
        if not path:
            raise Skip("pass --%s to run this" % key.replace("_", "-"))
        return path


# ---------------------------------------------------------------------------
# Corpora
#
# Built here rather than shipped, and built the same way everywhere: a tiny
# linear congruential generator instead of `random`, whose stream is not
# promised to be stable across Python versions.
# ---------------------------------------------------------------------------

class Rng:
    def __init__(self, seed=20260906):
        self.s = seed & 0xFFFFFFFF

    def next(self):
        self.s = (1103515245 * self.s + 12345) & 0x7FFFFFFF
        return self.s

    def pick(self, seq):
        return seq[self.next() % len(seq)]

    def frac(self):
        return self.next() / float(0x7FFFFFFF)


WORDS = ["love", "monkey", "dragon", "princess", "summer", "winter", "hunter",
         "soccer", "master", "shadow", "ninja", "tiger", "flower", "orange",
         "purple", "silver", "golden", "secret", "forest", "rocket"]
SUFFIX = ["", "1", "12", "123", "1234", "01", "2010", "2011", "2019", "2020",
          "!", "!!", "@", "#1", "99", "007"]
PREFIX = ["", "the", "my", "xx", "i"]
WALKS = ["qwerty", "1qaz2wsx", "asdfgh", "zxcvbn", "1q2w3e", "qazwsx"]


def write_lines(path, lines, newline="\n", encoding="utf-8"):
    """Write text with the line ending we asked for, on every platform."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding=encoding, newline="") as f:
        for line in lines:
            f.write(line + newline)
    return path


def make_corpus(path, n=20000, seed=20260906):
    """A corpus with alpha, digits, symbols, years, walks and compounds in it."""
    r = Rng(seed)
    out = []
    for _ in range(n):
        p = r.frac()
        if p < 0.08:
            w = r.pick(WALKS) + r.pick(SUFFIX)
        elif p < 0.16:
            w = r.pick(WORDS) + r.pick(WORDS) + r.pick(SUFFIX)
        else:
            w = r.pick(PREFIX) + r.pick(WORDS) + r.pick(SUFFIX)
        if r.frac() < 0.03:
            w = w.capitalize()
        out.append(w)
    return write_lines(path, out)


def make_weighted(path, n=4000, sep=":", seed=7):
    r = Rng(seed)
    out = []
    for _ in range(n):
        w = r.pick(PREFIX) + r.pick(WORDS) + r.pick(SUFFIX)
        out.append("%d%s%s" % (1 + r.next() % 40, sep, w))
    return write_lines(path, out)


def repeat(path, words, times=40, newline="\n", encoding="utf-8"):
    lines = [w for w in words for _ in range(times)]
    return write_lines(path, lines, newline=newline, encoding=encoding)


# ---------------------------------------------------------------------------
# Reading a ruleset
# ---------------------------------------------------------------------------

def read_text(path):
    """Bytes to text, tolerating whatever the corpus put in a terminal."""
    return path.read_bytes().decode("utf-8", "surrogateescape")


def prob_file(path):
    """A "value<TAB>probability" list as a dict.  Order is never significant."""
    out = {}
    for line in read_text(path).splitlines():
        i = line.rfind("\t")
        if i < 0:
            continue
        try:
            out[line[:i]] = float(line[i + 1:])
        except ValueError:
            continue
    return out


def prob_files(root, skip_omen=True):
    """Every probability list in a ruleset, keyed by its path relative to root."""
    out = {}
    root = Path(root)
    for p in sorted(root.rglob("*.txt")):
        rel = p.relative_to(root)
        if skip_omen and rel.parts[0] == "Omen":
            continue
        if rel.name == "totals.txt":
            continue
        out[rel.as_posix()] = prob_file(p)
    return out


def read_config(root):
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_string(read_text(Path(root) / "config.ini"))
    return cp


def structures(root):
    """The base structures and their probabilities."""
    return prob_file(Path(root) / "Grammar" / "grammar.txt")


def split_structure(s):
    """"A8Y1" -> [("A", 8), ("Y", 1)].  "M" -> [("M", 0)]."""
    out = []
    i = 0
    while i < len(s):
        sym = s[i]
        i += 1
        num = ""
        while i < len(s) and s[i].isdigit():
            num += s[i]
            i += 1
        out.append((sym, int(num) if num else 0))
    return out


def tree_files(root):
    root = Path(root)
    return sorted(p.relative_to(root).as_posix()
                  for p in root.rglob("*") if p.is_file())


def compare_rulesets(a, b, ignore=("config.ini",)):
    """Files that differ between two rulesets, config.ini excluded by default.

    Returns (only_in_a, only_in_b, differing).
    """
    fa, fb = set(tree_files(a)), set(tree_files(b))
    for name in ignore:
        fa.discard(name)
        fb.discard(name)
    differ = []
    for rel in sorted(fa & fb):
        if not filecmp.cmp(Path(a) / rel, Path(b) / rel, shallow=False):
            differ.append(rel)
    return sorted(fa - fb), sorted(fb - fa), differ


def assert_same_ruleset(a, b, what, ignore=("config.ini",)):
    only_a, only_b, differ = compare_rulesets(a, b, ignore)
    check(not only_a and not only_b and not differ,
          "%s\n  only in first : %s\n  only in second: %s\n  differing     : %s"
          % (what, only_a[:8], only_b[:8], differ[:8]))


# ---------------------------------------------------------------------------
# Command line and startup
# ---------------------------------------------------------------------------

@test("cli")
def test_binary_runs(env):
    """--version exits 0 and names the program"""
    _, out, _ = env.run("--version")
    check("hpcfg" in out, "--version did not name hpcfg: %r" % out)


@test("cli")
def test_version_states_ruleset_format(env):
    """--version says which ruleset layout it writes"""
    _, out, _ = env.run("--version")
    low = out.lower()
    check("4.x" in low, "--version does not name the layout: %r" % out)
    check("pcfg-cracker" in low,
          "--version does not mention the compatibility format: %r" % out)


@test("cli")
def test_help_lists_every_section(env):
    """-h prints the option table"""
    _, out, err = env.run("-h")
    # Help that was asked for belongs on stdout, where it can be paged or
    # searched.  Only the help shown because the command line was wrong goes
    # to stderr.
    check(out.strip(), "-h printed nothing on stdout")
    check(not err.strip(), "-h wrote to stderr as well: %r" % err[:200])
    for want in ("Training", "Multiword", "Model", "Ruleset", "Run"):
        check("[ %s ]" % want in out, "-h has no %s section" % want)
    for want in ("--train", "--ruleset-save", "--coverage", "--rulesets-merge"):
        check(want in out, "-h does not document %s" % want)
    # Every short option the parser takes has to be shown as one.
    for want in ("-w, --weighted", "-s, --sep", "-t, --train", "-c, --coverage"):
        check(want in out, "-h does not show the short form in %r" % want)


@test("cli")
def test_unknown_format_is_refused(env):
    """--ruleset-format takes only the two names it documents"""
    corpus = make_corpus(env.tmp("c.txt"), 200)
    rc, _, err = env.run("-t", corpus, "-g", env.tmp("rs"),
                         "--ruleset-format", "nonsense", want_ok=False)
    check(rc != 0, "a bogus --ruleset-format was accepted")
    check("nonsense" in err, "the error does not quote what was passed: %r" % err)


@test("cli")
def test_usage_on_a_bad_option_goes_to_stderr(env):
    """the help shown because the command line was wrong is not stdout"""
    rc, out, err = env.run("--no-such-option", want_ok=False)
    check(rc != 0, "an unknown option was accepted")
    check(not out.strip(), "a rejected command line wrote to stdout: %r" % out[:200])
    check(err.strip(), "a rejected command line said nothing on stderr")


@test("cli")
def test_numeric_options_refuse_what_is_not_a_number(env):
    """a mistyped figure is an error, never a silent zero"""
    corpus = make_corpus(env.tmp("c.txt"), 400)
    # -c is the one that mattered: 0 means "OMEN alone", so a coverage that
    # read as zero threw the whole grammar away without saying anything.
    cases = [("--coverage", "O.6"), ("--coverage", "abc"),
             ("--omen-alphabet", "xx"), ("--threads", "two"),
             ("--terminal-count-min", "5x"), ("--admission-min", ""),
             ("--mw-threshold", "-"), ("--count-min", "1e3"),
             ("--mw-len-min", "four"), ("--mw-len-max", "12.5")]
    for opt, bad in cases:
        rc, _, err = env.run("-t", corpus, "-g", env.tmp("rs"), opt, bad,
                             want_ok=False)
        check(rc != 0, "%s %r was accepted" % (opt, bad))
        check(opt in err, "the error for %s %r does not name the option: %r"
              % (opt, bad, err))


@test("cli")
def test_coverage_zero_is_only_reached_on_purpose(env):
    """the grammar is discarded only when a real zero asks for it"""
    corpus = make_corpus(env.tmp("c.txt"), 2000)
    asked = structures(env.train(corpus, "zero", "-c", "0"))
    check_eq(sorted(asked), ["M"], "an explicit -c 0 no longer means OMEN alone")
    rc, _, _ = env.run("-t", corpus, "-g", env.tmp("typo"), "-c", "O",
                       want_ok=False)
    check(rc != 0, "a coverage that is not a number still trained something")


@test("cli")
def test_missing_corpus_is_refused(env):
    """a corpus that is not there fails, and says so"""
    rc, _, err = env.run("-t", env.tmp("absent.txt"), "-g", env.tmp("rs"),
                         want_ok=False)
    check(rc != 0, "training on a missing file succeeded")
    check("cannot read" in err.lower(), "unhelpful error: %r" % err)


@test("cli")
def test_missing_ruleset_is_refused(env):
    """-i on a directory that is not there fails"""
    rc, _, _ = env.run("-i", env.tmp("absent_dir"), want_ok=False)
    check(rc != 0, "inspecting a missing ruleset succeeded")


@test("cli")
def test_legacy_option_names_still_work(env):
    """the spellings hpcfg used before are still accepted"""
    corpus = make_corpus(env.tmp("c.txt"), 3000)
    new = env.train(corpus, "new")
    old = env.tmp("old")
    env.run("--training", corpus, "--ruleset", old)
    assert_same_ruleset(new, old, "old and new option spellings disagree")


# ---------------------------------------------------------------------------
# Ruleset layout
# ---------------------------------------------------------------------------

@test("structure")
def test_ruleset_layout(env):
    """training writes the directories the readers open"""
    rs = env.train(make_corpus(env.tmp("c.txt"), 8000))
    for rel in ("config.ini", "totals.txt", "Grammar/grammar.txt"):
        check((rs / rel).is_file(), "missing %s" % rel)
    for d in ("Alpha", "Digits", "Other", "Capitalization", "Grammar", "Omen"):
        check((rs / d).is_dir(), "missing directory %s" % d)


@test("structure")
def test_config_ini_has_the_required_keys(env):
    """config.ini carries the sections a reader looks for"""
    rs = env.train(make_corpus(env.tmp("c.txt"), 3000))
    cp = read_config(rs)
    for sect in ("TRAINING_PROGRAM_DETAILS", "TRAINING_DATASET_DETAILS", "START"):
        check(cp.has_section(sect), "config.ini has no [%s]" % sect)
    prog = cp["TRAINING_PROGRAM_DETAILS"]
    for key in ("contact", "author", "program", "version"):
        check(key in prog, "[TRAINING_PROGRAM_DETAILS] has no %s" % key)
    check_eq(prog["program"], "hpcfg", "program name in config.ini")
    data = cp["TRAINING_DATASET_DETAILS"]
    for key in ("encoding", "uuid", "number_of_passwords_in_set"):
        check(key in data, "[TRAINING_DATASET_DETAILS] has no %s" % key)
    check_eq(int(data["number_of_passwords_in_set"]), 3000, "passwords counted")


@test("structure")
def test_config_ini_declares_files_that_exist(env):
    """every filename config.ini promises is on disk"""
    rs = env.train(make_corpus(env.tmp("c.txt"), 8000))
    cp = read_config(rs)
    import json
    for sect in cp.sections():
        s = cp[sect]
        if "directory" not in s or "filenames" not in s:
            continue
        for fn in json.loads(s["filenames"]):
            p = rs / s["directory"] / fn
            check(p.is_file(), "[%s] promises %s/%s, which is not there"
                  % (sect, s["directory"], fn))


@test("structure")
def test_default_format_declares_the_trainer_version(env):
    """the default writes hpcfg's own version, claiming nothing for a reader"""
    _, out, _ = env.run("--version")
    version = out.split()[1]
    rs = env.train(make_corpus(env.tmp("c.txt"), 2000))
    got = read_config(rs)["TRAINING_PROGRAM_DETAILS"]["version"]
    check_eq(got, version, "config.ini version under the default format")


@test("structure")
def test_compat_format_declares_the_layout_version(env):
    """--ruleset-format pcfg-cracker declares 4.x, which is what that reader gates on"""
    corpus = make_corpus(env.tmp("c.txt"), 2000)
    rs = env.train(corpus, "cc", "--ruleset-format", "pcfg-cracker")
    got = read_config(rs)["TRAINING_PROGRAM_DETAILS"]["version"]
    check(got.startswith("4."), "compat config.ini declares %r, not a 4.x layout" % got)


@test("structure")
def test_compat_format_adds_the_reader_files(env):
    """the compat format adds what pcfg_cracker and pcfg-go open, and nothing is lost"""
    corpus = make_corpus(env.tmp("c.txt"), 8000)
    default = env.train(corpus, "default")
    compat = env.train(corpus, "compat", "--ruleset-format", "pcfg-cracker")
    have, extra = set(tree_files(default)), set(tree_files(compat))
    check(not (have - extra),
          "the compat format dropped %s" % sorted(have - extra)[:8])
    added = extra - have
    for rel in ("Emails/email_providers.txt", "Websites/website_hosts.txt",
                "Grammar/raw_grammar.txt", "Omen/EP.level",
                "Omen/alphabet.txt", "Omen/omen_keyspace.txt"):
        check(rel in added, "the compat format does not add %s" % rel)


@test("structure")
def test_totals_file(env):
    """totals.txt counts each terminal type, and the counts are positive"""
    rs = env.train(make_corpus(env.tmp("c.txt"), 8000))
    rows = 0
    for line in read_text(rs / "totals.txt").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        check_eq(len(parts), 2, "totals.txt line %r" % line)
        check(int(parts[1]) > 0, "totals.txt counts %s at %s" % (parts[0], parts[1]))
        rows += 1
    check(rows > 0, "totals.txt is empty")


# ---------------------------------------------------------------------------
# The numbers in the ruleset
# ---------------------------------------------------------------------------

@test("probability")
def test_every_list_sums_to_one(env):
    """each terminal list is a distribution"""
    rs = env.train(make_corpus(env.tmp("c.txt"), 12000))
    for rel, d in prob_files(rs).items():
        if not d:
            continue
        total = sum(d.values())
        check(abs(total - 1.0) < 1e-6,
              "%s sums to %.12f over %d entries" % (rel, total, len(d)))


@test("probability")
def test_probabilities_are_in_range(env):
    """no probability is zero, negative or above one"""
    rs = env.train(make_corpus(env.tmp("c.txt"), 12000))
    for rel, d in prob_files(rs).items():
        for value, p in d.items():
            check(0.0 < p <= 1.0 + EPS,
                  "%s: %r has probability %r" % (rel, value, p))


@test("probability")
def test_no_empty_terminals(env):
    """a terminal always has a value"""
    rs = env.train(make_corpus(env.tmp("c.txt"), 12000))
    for rel, d in prob_files(rs).items():
        check("" not in d, "%s holds a zero-length terminal" % rel)


@test("probability")
def test_length_lists_hold_values_of_that_length(env):
    """Alpha/8.txt holds eight-character values, and so on"""
    rs = env.train(make_corpus(env.tmp("c.txt"), 12000))
    for group in ("Alpha", "Digits", "Other", "Keyboard"):
        d = Path(rs) / group
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.txt")):
            want = int(p.stem)
            for value in prob_file(p):
                check_eq(len(value), want, "%s/%s holds %r" % (group, p.name, value))


@test("probability")
def test_structures_only_reference_lists_that_exist(env):
    """every base structure can be expanded"""
    rs = env.train(make_corpus(env.tmp("c.txt"), 12000))
    where = {"A": "Alpha", "D": "Digits", "O": "Other", "K": "Keyboard",
             "X": "Context", "Y": "Years"}
    for s in structures(rs):
        for sym, n in split_structure(s):
            if sym == "M":
                continue
            check(sym in where, "structure %r uses the unknown symbol %r" % (s, sym))
            # Context and Years are flat lists: the count is in the structure,
            # the file is always 1.txt.
            name = "1.txt" if sym in ("X", "Y") else "%d.txt" % n
            p = Path(rs) / where[sym] / name
            check(p.is_file(), "structure %r needs %s/%s, which is missing"
                  % (s, where[sym], name))


@test("probability")
def test_capitalization_masks_cover_every_alpha_length(env):
    """an alpha list of length N has a capitalization mask list of length N"""
    rs = env.train(make_corpus(env.tmp("c.txt"), 12000))
    for p in sorted((Path(rs) / "Alpha").glob("*.txt")):
        mask = Path(rs) / "Capitalization" / p.name
        check(mask.is_file(), "Alpha/%s has no Capitalization/%s" % (p.name, p.name))
        for value in prob_file(mask):
            check_eq(len(value), int(p.stem), "mask length in %s" % mask.name)
            check(set(value) <= set("UL"),
                  "mask %r in %s is not made of U and L" % (value, mask.name))


# ---------------------------------------------------------------------------
# Tokenizer regressions
#
# Each of these stands for a defect that was found in the detectors hpcfg
# descends from, and every one of them produced a grammar that loaded without
# an error and generated the wrong thing.
# ---------------------------------------------------------------------------

@test("tokenizer")
def test_consecutive_keyboard_walks_are_kept_apart(env):
    """1qaz2wsx3edc is three common walks, not one rare twelve-character walk"""
    corpus = repeat(env.tmp("kb.txt"), ["1qaz2wsx3edc"], 60)
    rs = env.train(corpus, "kb", "--multiword-disable")
    got = structures(rs)
    check("K4K4K4" in got,
          "expected the structure K4K4K4, got %s" % sorted(got))
    check("K12" not in got, "the three walks were merged into one K12")
    four = prob_file(Path(rs) / "Keyboard" / "4.txt")
    check_eq(set(four), {"1qaz", "2wsx", "3edc"}, "the walks recovered")


@test("tokenizer")
def test_no_keyboard_walk_is_shorter_than_four(env):
    """the year pass must not leave a one- or two-character walk behind"""
    words = ["1qaz2wsx2010", "qwerty2011", "asdfgh1999", "zxcvbn2020",
             "1q2w3e2019", "qazwsx2021"]
    rs = env.train(repeat(env.tmp("y.txt"), words, 40), "kbyear")
    kb = Path(rs) / "Keyboard"
    if not kb.is_dir():
        raise Skip("this corpus produced no keyboard terminals")
    for p in sorted(kb.glob("*.txt")):
        check(int(p.stem) >= 4, "Keyboard/%s: a walk shorter than four" % p.name)
        for value in prob_file(p):
            check(len(value) >= 4, "keyboard terminal %r is too short" % value)


@test("tokenizer")
def test_years_are_detected(env):
    """a four digit year goes to Years, not to Digits"""
    words = ["monkey2010", "dragon2019", "silver2020", "forest2011"]
    rs = env.train(repeat(env.tmp("y.txt"), words, 40), "years")
    years = prob_file(Path(rs) / "Years" / "1.txt")
    check_eq(set(years), {"2010", "2019", "2020", "2011"}, "years recovered")
    for s in structures(rs):
        check("D4" not in s, "a year was filed as a four digit run in %r" % s)


@test("tokenizer")
def test_latin_extended_a_case_parity(env):
    """lowercasing follows Latin Extended-A where its parity changes"""
    # U+0100 and U+0139 and U+0179 sit on the three runs of that block, whose
    # upper and lower halves do not share one parity.
    words = ["ĀBCDEF", "ĹMNOPQ", "ŹXYWVU"]
    rs = env.train(repeat(env.tmp("u.txt"), words, 40), "latin",
                   "--multiword-disable")
    seen = set()
    for p in (Path(rs) / "Alpha").glob("*.txt"):
        seen |= set(prob_file(p))
    for want in ("ābcdef", "ĺmnopq", "źxywvu"):
        check(want in seen, "expected %r among the alpha terminals, got %s"
              % (want, sorted(seen)))


@test("tokenizer")
def test_turkish_dotted_capital_i(env):
    """the dotted capital I lowercases to i, not to the dotless one"""
    rs = env.train(repeat(env.tmp("tr.txt"), ["İSTANBUL"], 40), "turkish",
                   "--multiword-disable")
    seen = set()
    for p in (Path(rs) / "Alpha").glob("*.txt"):
        seen |= set(prob_file(p))
    check("istanbul" in seen,
          "expected 'istanbul' among the alpha terminals, got %s" % sorted(seen))
    check("ıstanbul" not in seen,
          "the dotted capital I was lowercased to the dotless one")


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

@test("determinism")
def test_training_twice_gives_the_same_ruleset(env):
    """the same corpus trains to the same ruleset, which is what lets a merge be exact"""
    corpus = make_corpus(env.tmp("c.txt"), 12000)
    a = env.train(corpus, "a")
    b = env.train(corpus, "b")
    assert_same_ruleset(a, b, "two runs of one corpus disagree")


@test("determinism")
def test_thread_count_does_not_change_the_ruleset(env):
    """counting on one core and on four gives the same answer"""
    corpus = make_corpus(env.tmp("c.txt"), 12000)
    one = env.train(corpus, "t1", "-T", "1")
    four = env.train(corpus, "t4", "-T", "4")
    assert_same_ruleset(one, four, "the thread count changed the ruleset")


@test("determinism")
def test_config_ini_differs_only_where_it_must(env):
    """two runs of one corpus differ in config.ini by the uuid alone"""
    corpus = make_corpus(env.tmp("c.txt"), 4000)
    a = read_config(env.train(corpus, "a"))
    b = read_config(env.train(corpus, "b"))
    for sect in a.sections():
        for key in a[sect]:
            if key == "uuid":
                check(a[sect][key] != b[sect][key], "the uuid repeated across runs")
                continue
            check_eq(b[sect].get(key), a[sect][key], "[%s] %s" % (sect, key))


# ---------------------------------------------------------------------------
# Coverage and OMEN
# ---------------------------------------------------------------------------

@test("omen")
def test_coverage_one_turns_omen_off(env):
    """--coverage 1 gives the grammar all of the mass"""
    corpus = make_corpus(env.tmp("c.txt"), 4000)
    got = structures(env.train(corpus, "c1", "-c", "1"))
    check("M" not in got, "the omen escape is still in the grammar at coverage 1")
    check(abs(sum(got.values()) - 1.0) < 1e-6, "the structures do not sum to one")


@test("omen")
def test_coverage_zero_is_omen_alone(env):
    """--coverage 0 gives OMEN all of the mass"""
    corpus = make_corpus(env.tmp("c.txt"), 4000)
    got = structures(env.train(corpus, "c0", "-c", "0"))
    check_eq(sorted(got), ["M"], "the grammar at coverage 0")
    check(abs(got["M"] - 1.0) < 1e-6, "the escape takes %r, not all of it" % got["M"])


@test("omen")
def test_coverage_splits_the_mass_as_asked(env):
    """the escape takes what --coverage leaves it"""
    corpus = make_corpus(env.tmp("c.txt"), 20000)
    for c in ("0.25", "0.5", "0.75"):
        got = structures(env.train(corpus, "c" + c.replace(".", ""), "-c", c))
        want = 1.0 - float(c)
        check("M" in got, "no escape in the grammar at coverage %s" % c)
        check(abs(got["M"] - want) < 0.005,
              "coverage %s left the escape %.6f, expected about %.6f"
              % (c, got["M"], want))


@test("omen")
def test_omen_ngram_is_written_through(env):
    """--omen-ngram lands in the OMEN config across the documented range"""
    corpus = make_corpus(env.tmp("c.txt"), 6000)
    for n in (2, 3, 4, 5):
        rs = env.train(corpus, "n%d" % n, "-n", str(n))
        cfg = read_text(rs / "Omen" / "config.txt")
        line = [l for l in cfg.splitlines() if l.startswith("ngram")]
        check(line, "Omen/config.txt declares no ngram for -n %d" % n)
        check_eq(line[0].split("=")[1].strip(), str(n), "ngram for -n %d" % n)


@test("omen")
def test_omen_ngram_outside_the_range_is_refused(env):
    """--omen-ngram takes the 2 to 5 the help documents, and nothing else"""
    corpus = make_corpus(env.tmp("c.txt"), 800)
    for n in ("1", "6", "99", "0"):
        rc, _, err = env.run("-t", corpus, "-g", env.tmp("n" + n), "-n", n,
                             want_ok=False)
        check(rc != 0, "--omen-ngram %s was accepted" % n)
        check(n in err, "the error does not quote what was passed: %r" % err)


@test("omen")
def test_omen_alphabet_round_trip(env):
    """an alphabet saved from one corpus can be handed to the next run"""
    corpus = make_corpus(env.tmp("c.txt"), 8000)
    freq = env.tmp("alpha.txt")
    first = env.tmp("first")
    env.run("-t", corpus, "-g", first, "--omen-alphabet-save", freq)
    check(freq.is_file() and freq.stat().st_size > 0, "no alphabet was saved")
    second = env.train(corpus, "second", "--omen-alphabet-file", freq)
    assert_same_ruleset(first, second,
                        "reusing the alphabet of a corpus changed its own ruleset")


# ---------------------------------------------------------------------------
# Merging
# ---------------------------------------------------------------------------

def split_and_merge(env, lines):
    """Train the whole, train each half on shared words and alphabet, merge.

    Returns (whole, merged).  The corpus is handed to the merge because
    without it the OMEN level distribution is the sum of the rulesets' own,
    which is close and not exact - hpcfg says so when it happens.
    """
    corpus = write_lines(env.tmp("c.txt"), lines)
    half = len(lines) // 2
    a_txt = write_lines(env.tmp("a.txt"), lines[:half])
    b_txt = write_lines(env.tmp("b.txt"), lines[half:])

    mw, freq = env.tmp("mw.txt"), env.tmp("alpha.txt")
    whole = env.tmp("whole")
    env.run("-t", corpus, "-g", whole, "--mw-save", mw, "--omen-alphabet-save", freq)

    a = env.train(a_txt, "half_a", "--mw-file", mw, "--omen-alphabet-file", freq)
    b = env.train(b_txt, "half_b", "--mw-file", mw, "--omen-alphabet-file", freq)

    merged = env.tmp("merged")
    env.run("-g", merged, "--rulesets-merge", a, "--rulesets-merge", b, "-t", corpus)
    return whole, merged


@test("merge")
def test_merge_reproduces_training_on_the_union(env):
    """two halves merged with the corpus to hand equal training on the whole"""
    # 30000 lines, so that the escape the coverage asks for divides evenly:
    # the default coverage of 0.6 gives it two thirds of the passwords, and
    # 30000 and its two halves all land on a whole number.  test_merge_rounds
    # below covers the case where they do not.
    corpus = make_corpus(env.tmp("src.txt"), 30000)
    whole, merged = split_and_merge(env, read_text(corpus).splitlines())
    assert_same_ruleset(whole, merged, "the merge did not reproduce the whole")


@test("merge")
def test_merge_rounds_the_escape_but_nothing_else(env):
    """an uneven split moves the escape count by one and no terminal at all"""
    # The escape gets floor(passwords * (1 - coverage) / coverage) slots.  Two
    # halves floor twice and the whole floors once, so a corpus that does not
    # divide evenly leaves the merge one count short in the escape.  That is
    # confined to the grammar and the totals: every terminal list has to come
    # back untouched, and the structure probabilities have to agree closely.
    corpus = make_corpus(env.tmp("src.txt"), 20000)
    whole, merged = split_and_merge(env, read_text(corpus).splitlines())

    soft = ("config.ini", "Grammar/grammar.txt", "totals.txt")
    assert_same_ruleset(whole, merged,
                        "the merge changed a terminal list", ignore=soft)

    a, b = structures(whole), structures(merged)
    check_eq(sorted(b), sorted(a), "the merge changed which structures exist")
    for name in a:
        check(abs(a[name] - b[name]) < 1e-4,
              "structure %s: %.10f whole against %.10f merged"
              % (name, a[name], b[name]))

    ta = dict(l.split("\t") for l in read_text(Path(whole) / "totals.txt").splitlines() if l)
    tb = dict(l.split("\t") for l in read_text(Path(merged) / "totals.txt").splitlines() if l)
    check_eq(sorted(tb), sorted(ta), "the merge changed which totals exist")
    for k in ta:
        check(abs(int(ta[k]) - int(tb[k])) <= 1,
              "total %s: %s whole against %s merged" % (k, ta[k], tb[k]))


@test("merge")
def test_merge_weights_shift_the_mass(env):
    """--rulesets-merge-weights changes the share each ruleset takes"""
    corpus = make_corpus(env.tmp("c.txt"), 6000)
    one = repeat(env.tmp("one.txt"), ["monkeymonkey1"], 200)
    two = repeat(env.tmp("two.txt"), ["dragondragon2"], 200)
    a = env.train(one, "wa")
    b = env.train(two, "wb")

    even = env.tmp("even")
    env.run("-g", even, "--rulesets-merge", a, "--rulesets-merge", b, "-t", corpus)
    tilted = env.tmp("tilted")
    env.run("-g", tilted, "--rulesets-merge", a, "--rulesets-merge", b,
            "--rulesets-merge-weights", "1:9", "-t", corpus)

    _, _, differ = compare_rulesets(even, tilted)
    check(differ, "the merge weights changed nothing in the ruleset")


# ---------------------------------------------------------------------------
# Reading the corpus
# ---------------------------------------------------------------------------

@test("input")
def test_weighted_input(env):
    """--weighted reads count and password off one line"""
    corpus = make_weighted(env.tmp("w.txt"), 2000)
    rs = env.train(corpus, "w", "-w")
    n = int(read_config(rs)["TRAINING_DATASET_DETAILS"]["number_of_passwords_in_set"])
    check(n > 2000, "the counts were not applied: %d passwords for 2000 lines" % n)
    for rel, d in prob_files(rs).items():
        for value in d:
            check(":" not in value,
                  "%s holds %r, so the separator was not stripped" % (rel, value))


@test("input")
def test_custom_separator(env):
    """--sep takes a separator other than the colon"""
    corpus = make_weighted(env.tmp("w.txt"), 1500, sep=" ")
    rs = env.train(corpus, "sep", "-w", "--sep", " ")
    for rel, d in prob_files(rs).items():
        for value in d:
            check(" " not in value, "%s holds %r" % (rel, value))


@test("input")
def test_count_min_filters_by_count(env):
    """--count-min drops the lines counted below it"""
    lines = ["1:rarepassword", "2:rarepassword"] + ["500:commonword"] * 3
    corpus = write_lines(env.tmp("w.txt"), lines)
    kept = env.train(corpus, "all", "-w")
    cut = env.train(corpus, "cut", "-w", "--count-min", "100")
    n_kept = int(read_config(kept)["TRAINING_DATASET_DETAILS"]["number_of_passwords_in_set"])
    n_cut = int(read_config(cut)["TRAINING_DATASET_DETAILS"]["number_of_passwords_in_set"])
    check(n_cut < n_kept, "--count-min dropped nothing (%d vs %d)" % (n_cut, n_kept))


@test("input")
def test_stdin_is_a_corpus(env):
    """-t - reads the corpus from standard input"""
    corpus = make_corpus(env.tmp("c.txt"), 3000)
    from_file = env.train(corpus, "file")
    from_stdin = env.tmp("stdin")
    env.run("-t", "-", "-g", from_stdin, stdin=corpus.read_bytes())
    assert_same_ruleset(from_file, from_stdin,
                        "a corpus on stdin trained differently from the same file")


@test("input")
def test_crlf_line_endings(env):
    """a corpus written on Windows trains to the same ruleset"""
    words = [w + s for w in WORDS[:8] for s in ("1", "12", "2020")]
    unix = repeat(env.tmp("lf.txt"), words, 8, newline="\n")
    dos = repeat(env.tmp("crlf.txt"), words, 8, newline="\r\n")
    a = env.train(unix, "lf")
    b = env.train(dos, "crlf")
    assert_same_ruleset(a, b, "carriage returns changed the ruleset")


@test("input")
def test_blank_lines_are_not_passwords(env):
    """empty lines are not counted"""
    words = ["monkey1", "dragon2", "silver3"]
    plain = write_lines(env.tmp("p.txt"), words * 20)
    padded = write_lines(env.tmp("q.txt"),
                         [x for w in words * 20 for x in (w, "")])
    a = env.train(plain, "plain")
    b = env.train(padded, "padded")
    na = int(read_config(a)["TRAINING_DATASET_DETAILS"]["number_of_passwords_in_set"])
    nb = int(read_config(b)["TRAINING_DATASET_DETAILS"]["number_of_passwords_in_set"])
    check_eq(nb, na, "blank lines were counted as passwords")


# ---------------------------------------------------------------------------
# Multiword
# ---------------------------------------------------------------------------

@test("multiword")
def test_multiword_split_is_shared_through_a_file(env):
    """--mw-save and --mw-file let the chunks of a split run agree"""
    corpus = make_corpus(env.tmp("c.txt"), 12000)
    mw = env.tmp("mw.txt")
    first = env.tmp("first")
    env.run("-t", corpus, "-g", first, "--mw-save", mw)
    check(mw.is_file() and mw.stat().st_size > 0, "no words were saved")
    words = [l for l in read_text(mw).splitlines() if l.strip()]
    check(len(words) > 0, "the saved multiword file is empty")
    second = env.train(corpus, "second", "--mw-file", mw)
    assert_same_ruleset(first, second,
                        "handing a corpus its own words changed its ruleset")


@test("multiword")
def test_multiword_disable_changes_the_terminals(env):
    """--multiword-disable leaves compounds whole"""
    # The parts have to be common and the compound rare.  A run that is itself
    # a word seen at least --mw-threshold times is left whole on purpose, so a
    # frequent compound is not evidence either way.
    lines = (["monkey"] * 80 + ["dragon"] * 80 + ["silver"] * 80 +
             ["forest"] * 80 + ["monkeydragon"] * 2 + ["silverforest"] * 2)
    corpus = write_lines(env.tmp("mw.txt"), lines)
    split = env.train(corpus, "split")
    whole = env.train(corpus, "whole", "--multiword-disable")

    check("A6A6" in structures(split),
          "the compound was not split: %s" % sorted(structures(split)))
    check("A12" not in structures(split),
          "the compound survived whole even with splitting on")
    check("A12" in structures(whole),
          "--multiword-disable still split the compound: %s"
          % sorted(structures(whole)))
    seen = set()
    for p in (Path(whole) / "Alpha").glob("*.txt"):
        seen |= set(prob_file(p))
    check("monkeydragon" in seen,
          "with splitting off the compound is gone: %s" % sorted(seen))


# ---------------------------------------------------------------------------
# Filters and metadata
# ---------------------------------------------------------------------------

@test("filters")
def test_terminal_count_min_drops_rare_terminals(env):
    """--terminal-count-min removes what was barely seen"""
    lines = ["commonword"] * 400 + ["raretermx"] * 2
    corpus = write_lines(env.tmp("c.txt"), lines)
    keep = env.train(corpus, "keep", "--multiword-disable")
    drop = env.train(corpus, "drop", "--multiword-disable", "-f", "10")

    def alphas(rs):
        out = set()
        for p in (Path(rs) / "Alpha").glob("*.txt"):
            out |= set(prob_file(p))
        return out

    check("raretermx" in alphas(keep), "the rare terminal was never there")
    check("raretermx" not in alphas(drop), "--terminal-count-min kept it anyway")
    check("commonword" in alphas(drop), "--terminal-count-min dropped the common one")


@test("filters")
def test_metadata_flags_reach_config_ini(env):
    """--comments and --encoding are recorded"""
    corpus = make_corpus(env.tmp("c.txt"), 1500)
    rs = env.train(corpus, "meta", "--comments", "a note", "-e", "iso-8859-1")
    cp = read_config(rs)
    check_eq(cp["TRAINING_DATASET_DETAILS"]["comments"], "a note",
             "comments in config.ini")
    check_eq(cp["TRAINING_DATASET_DETAILS"]["encoding"], "iso-8859-1",
             "encoding in config.ini")


@test("filters")
def test_memory_ceiling_is_accepted(env):
    """--memory-max takes a suffixed figure and still trains"""
    corpus = make_corpus(env.tmp("c.txt"), 4000)
    rs = env.train(corpus, "mem", "-M", "512M")
    check((rs / "Grammar" / "grammar.txt").is_file(),
          "no grammar was written under a memory ceiling")


# ---------------------------------------------------------------------------
# Reading a ruleset back
# ---------------------------------------------------------------------------

@test("info")
def test_ruleset_info_reads_its_own_output(env):
    """-i reports on a ruleset hpcfg wrote"""
    rs = env.train(make_corpus(env.tmp("c.txt"), 8000), "rs")
    _, out, _ = env.run("-i", rs)
    for want in ("Program", "Structures", "Terminals"):
        check(want in out, "-i does not report %s" % want)
    check("hpcfg" in out, "-i does not name the trainer")
    for bad in ("zero length", "walk shorter than 4"):
        check(bad not in out, "-i found a defect in a fresh ruleset: %s" % bad)


@test("info")
def test_ruleset_diff_compares_two(env):
    """-i with --ruleset-diff reports on a pair"""
    corpus = make_corpus(env.tmp("c.txt"), 6000)
    a = env.train(corpus, "a")
    b = env.train(repeat(env.tmp("o.txt"), ["monkey1", "dragon2"], 200), "b")
    _, same, _ = env.run("-i", a, "--ruleset-diff", a)
    _, other, _ = env.run("-i", a, "--ruleset-diff", b)
    check(same != other,
          "--ruleset-diff reports the same thing against itself and against another")


# ---------------------------------------------------------------------------
# The readers
# ---------------------------------------------------------------------------

def top_lists(root):
    """Every list ranked by probability, for comparing what gets generated first."""
    return {rel: sorted(d, key=lambda k: -d[k])
            for rel, d in prob_files(root).items() if d}


def rank_agreement(a, b, n):
    """Share of each list's top n that two rulesets agree on.

    Exact equality is the wrong measure: two totals that differ slightly make
    every probability differ in its last digits.  What matters is how much of
    each list's top the two share, since that is what gets generated first.
    """
    la, lb = top_lists(a), top_lists(b)
    hits = total = 0
    for rel in set(la) & set(lb):
        sa, sb = la[rel], lb[rel]
        if min(len(sa), len(sb)) < n:
            continue
        hits += len(set(sa[:n]) & set(sb[:n]))
        total += n
    return (hits / total) if total else None


@test("readers", needs="hashcat")
def test_hashcat_reads_the_default_ruleset(env):
    """train, hand the ruleset to hashcat, and look at what comes out first"""
    hashcat = env.tool("hashcat")
    rs = env.train(make_corpus(env.tmp("c.txt"), 8000), "rs")
    p = subprocess.run([str(hashcat), "-a", "4", "--stdout", "--limit", "10", str(rs)],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
    got = [l for l in p.stdout.decode("utf-8", "replace").splitlines() if l]
    check(got, "hashcat generated nothing from the ruleset:\n%s"
          % p.stderr.decode("utf-8", "replace")[:800])
    if VERBOSE:
        print("      first candidates: %s" % ", ".join(got[:5]))


@test("readers", needs="pcfg_cracker")
def test_pcfg_cracker_loads_the_compat_format(env):
    """pcfg_cracker reads the format written for it, and refuses the default"""
    guesser = Path(env.tool("pcfg_cracker"))
    rules = guesser.parent / "Rules"
    check(rules.is_dir(), "no Rules directory beside %s" % guesser)
    corpus = make_corpus(env.tmp("c.txt"), 8000)

    made = []
    try:
        for name, extra in (("hpcfg_t_default", []),
                            ("hpcfg_t_compat", ["--ruleset-format", "pcfg-cracker"])):
            rs = env.train(corpus, name, *extra)
            dest = rules / name
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(rs, dest)
            made.append(dest)

        def guess(name):
            p = subprocess.run([sys.executable, str(guesser), "-r", name, "-n", "5"],
                               cwd=str(guesser.parent), stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=900)
            return p.stdout.decode("utf-8", "replace")

        compat = guess("hpcfg_t_compat")
        check("not compatible" not in compat,
              "pcfg_cracker refused the format written for it:\n%s" % compat[-800:])

        default = guess("hpcfg_t_default")
        if "not compatible" not in default:
            raise Skip("this pcfg_cracker accepts the default format too, so "
                       "there is nothing here to tell apart")
    finally:
        for d in made:
            shutil.rmtree(d, ignore_errors=True)


@test("readers", needs="pcfg_go")
def test_pcfg_go_loads_the_compat_format(env):
    """pcfg-go reads the format written for it"""
    guesser = env.tool("pcfg_go")
    corpus = make_corpus(env.tmp("c.txt"), 8000)
    home = env.tmp("gohome")
    (home / "Rules").mkdir(parents=True)
    for name, extra in (("hpcfg_default", []),
                        ("hpcfg_compat", ["--ruleset-format", "pcfg-cracker"])):
        shutil.copytree(env.train(corpus, name, *extra), home / "Rules" / name)

    def guess(name):
        p = subprocess.run([str(guesser), "-r", name, "-n", "5"], cwd=str(home),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=900)
        return p.returncode, p.stdout.decode("utf-8", "replace")

    rc, out = guess("hpcfg_compat")
    check(rc == 0, "pcfg-go refused the format written for it:\n%s" % out[-800:])


@test("readers", needs="cpcfg")
def test_agreement_with_the_implementations_it_descends_from(env):
    """how much of each list's top hpcfg and Cpcfg agree on"""
    cpcfg = env.tool("cpcfg")
    corpus = make_corpus(env.tmp("c.txt"), 20000)
    mine = env.train(corpus, "mine")
    theirs = env.tmp("theirs")
    p = subprocess.run([str(cpcfg), "-t", str(corpus), "-g", str(theirs)],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800)
    check(p.returncode == 0, "Cpcfg failed:\n%s"
          % p.stderr.decode("utf-8", "replace")[-800:])
    for n in (10, 100):
        share = rank_agreement(mine, theirs, n)
        if share is None:
            continue
        if VERBOSE:
            print("      top %-4d agreement: %.1f%%" % (n, 100 * share))
        check(share > 0.5,
              "only %.1f%% of the top %d agrees with Cpcfg" % (100 * share, n))


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

VERBOSE = False


def find_hpcfg(given):
    if given:
        p = Path(given).resolve()
        if not p.is_file():
            sys.exit("hpcfg not found at %s" % p)
        return p
    for name in ("hpcfg.exe", "hpcfg"):
        p = ROOT / name
        if p.is_file():
            return p.resolve()
    sys.exit("hpcfg is not built.  Run make in %s, or pass --hpcfg." % ROOT)


def main():
    global VERBOSE
    ap = argparse.ArgumentParser(
        description="hpcfg functional tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("The exit status")[0].strip())
    ap.add_argument("--hpcfg", help="the binary under test (default: ./hpcfg)")
    ap.add_argument("--hashcat", help="hashcat binary, for the reader test")
    ap.add_argument("--pcfg-cracker", dest="pcfg_cracker",
                    help="path to pcfg_guesser.py")
    ap.add_argument("--pcfg-go", dest="pcfg_go", help="pcfg-go guesser binary")
    ap.add_argument("--cpcfg", help="Cpcfg trainer binary")
    ap.add_argument("-k", "--filter", help="run only tests whose name contains this")
    ap.add_argument("-s", "--section", help="run only this section")
    ap.add_argument("-l", "--list", action="store_true", help="list the tests and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--keep", action="store_true",
                    help="keep the scratch directory and print where it is")
    args = ap.parse_args()
    VERBOSE = args.verbose

    selected = TESTS
    if args.section:
        selected = [t for t in selected if t["section"] == args.section]
    if args.filter:
        selected = [t for t in selected if args.filter.lower() in t["name"].lower()]

    if args.list:
        for t in selected:
            print("%-13s %-46s %s" % (t["section"], t["name"], t["doc"]))
        print("\n%d tests in %d sections"
              % (len(selected), len(set(t["section"] for t in selected))))
        return 0

    if not selected:
        sys.exit("no test matched")

    hpcfg = find_hpcfg(args.hpcfg)
    tools = {k: v for k, v in (("hashcat", args.hashcat),
                               ("pcfg_cracker", args.pcfg_cracker),
                               ("pcfg_go", args.pcfg_go),
                               ("cpcfg", args.cpcfg)) if v}

    print("hpcfg    : %s" % hpcfg)
    print("python   : %s on %s" % (sys.version.split()[0], sys.platform))
    print("tests    : %d\n" % len(selected))

    workdir = Path(tempfile.mkdtemp(prefix="hpcfg-test-"))
    passed, failed, skipped = [], [], []
    section = None
    t0 = time.perf_counter()

    try:
        for t in selected:
            if t["section"] != section:
                section = t["section"]
                print("- [ %s ]" % section)
            env = Env(hpcfg, tools, workdir / t["name"])
            env.workdir.mkdir(parents=True, exist_ok=True)
            started = time.perf_counter()
            try:
                t["fn"](env)
            except Skip as e:
                skipped.append((t["name"], str(e)))
                print("  SKIP %-52s %s" % (t["name"], e))
            except Exception as e:
                failed.append((t["name"], e, traceback.format_exc()))
                print("  FAIL %-52s" % t["name"])
            else:
                passed.append(t["name"])
                print("  ok   %-52s %5.2fs" % (t["name"], time.perf_counter() - started))
            if not args.keep:
                shutil.rmtree(env.workdir, ignore_errors=True)
    finally:
        if args.keep:
            print("\nscratch kept in %s" % workdir)
        else:
            shutil.rmtree(workdir, ignore_errors=True)

    if failed:
        print("\n" + "=" * 72)
        for name, err, tb in failed:
            print("FAIL %s" % name)
            text = str(err) if isinstance(err, AssertionError) else tb
            for line in text.rstrip().split("\n"):
                print("     %s" % line)
            print()

    print("=" * 72)
    print("%d passed, %d failed, %d skipped in %.1fs"
          % (len(passed), len(failed), len(skipped), time.perf_counter() - t0))
    if skipped:
        print("\nskipped, and why:")
        for name, why in skipped:
            print("  %-52s %s" % (name, why))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
