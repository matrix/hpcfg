# hpcfg

##
## Detect Operating System, the way hashcat's own Makefile does, so a builder
## who knows one knows the other.
##

UNAME := $(shell uname -s 2>/dev/null || echo Unknown)

ANDROID_DETECT := $(findstring Android,$(shell uname -a 2>/dev/null))
ifneq (,$(ANDROID_DETECT))
  UNAME := Android
endif

# the Windows version number has to come off the name to build on cygwin hosts
UNAME := $(patsubst CYGWIN_NT-%,CYGWIN,$(UNAME))

# and the same for msys
UNAME := $(patsubst MSYS_NT-%,MSYS2,$(UNAME))
UNAME := $(patsubst MINGW32_NT-%,MSYS2,$(UNAME))
UNAME := $(patsubst MINGW64_NT-%,MSYS2,$(UNAME))

# Cross-building for Windows takes the Windows side whatever the host says.
# hashcat is built natively or under MSYS2 and so never has to ask; this does,
# and asking uname gets the host, which quietly adds -pthread and leaves the
# .exe wanting libwinpthread-1.dll for threads it never uses.
TARGET := $(shell $(CC) -dumpmachine 2>/dev/null)
ifneq (,$(findstring mingw,$(TARGET)))
  UNAME := MSYS2
endif

ifeq (,$(filter $(UNAME),Android Linux OpenBSD FreeBSD NetBSD DragonFly Darwin CYGWIN MSYS2))
$(error "! Your Operating System ($(UNAME)) is not supported by this Makefile")
endif

##
## Compiler
##

CC ?= cc

ifneq (,$(filter $(UNAME),OpenBSD FreeBSD NetBSD DragonFly))
CC := cc
endif

ifeq ($(UNAME),NetBSD)
CC := gcc
endif

##
## Flags
##

CFLAGS  ?= -O3 -fomit-frame-pointer -Wall -Wextra
LDFLAGS ?=
LIBS     =
EXE      =

# Kept out of CFLAGS so it survives a CFLAGS override on the command line,
# the way `native` below passes one down to the sub-make.
INCLUDES = -Iinclude

# LTO is off where it is known to break rather than where it happens to fail
ENABLE_LTO ?= 1

CC_IS_CLANG := $(shell $(CC) --version 2>/dev/null | grep -c clang)

ifneq (,$(filter $(UNAME),MSYS2 NetBSD DragonFly))
ifneq ($(CC_IS_CLANG),0)
  ENABLE_LTO := 0
endif
endif

# Plain -flto leaves gcc guessing how many LTRANS jobs it may run, so it warns and
# then links serially. Asking for auto has it spawn make to run them, and the make
# it spawns is whatever the system calls make. That is GNU make everywhere this
# builds except NetBSD, where it is bmake: it reads this file, cannot, and prints
# a screen of parse errors before gcc falls back to serial regardless. NetBSD
# keeps the warning and loses nothing. clang does not take the spelling.
LTO_FLAG = -flto

ifeq ($(ENABLE_LTO),1)
ifeq ($(CC_IS_CLANG),0)
ifneq ($(UNAME),NetBSD)
  LTO_FLAG = -flto=auto
endif
endif
  CFLAGS  += $(LTO_FLAG)
  LDFLAGS += $(LTO_FLAG)
endif

ifneq (,$(filter $(UNAME),MSYS2 CYGWIN))
  # threads, locks, the clock and the C runtime all come from the system DLLs
  EXE = .exe
else
  CFLAGS  += -pthread
  LDFLAGS += -pthread
endif

ifneq (,$(filter $(UNAME),Linux Android))
  LIBS += -lm
endif

ifneq (,$(filter $(UNAME),OpenBSD FreeBSD NetBSD DragonFly))
  LIBS += -lm
endif

##
## Build
##
## Objects and the dependency files beside them are built into obj/ so that
## the source tree stays as it was checked out, the way hashcat's own does.
##

OBJDIR = obj

SRC = src/main.c src/pcfg_trainer.c src/pcfg_trainer_utils.c src/pcfg_trainer_omen.c \
      src/pcfg_trainer_tokenize.c src/pcfg_trainer_keyboard.c \
      src/pcfg_ruleset.c src/pcfg_ruleset_inspect.c src/pcfg_store.c src/pcfg_multiword.c \
      src/pcfg_platform.c src/pcfg_common.c src/pcfg_unicode_tables.c
OBJ = $(SRC:src/%.c=$(OBJDIR)/%.o)

# The compiler already knows which headers an object was built from, so it is
# asked to write it down rather than have the makefile guess: -MMD records
# them next to the object, -MP adds a bare target for each so that deleting or
# renaming a header does not break the next build with a missing prerequisite.
# This is per object, where naming the headers by hand was per directory: a
# change to one header no longer rebuilds all thirteen.
DEPFLAGS = -MMD -MP

hpcfg$(EXE): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) $(DEPFLAGS) -c $< -o $@

-include $(OBJ:.o=.d)

# Tuned for the machine doing the build. Not the default: a binary built this
# way runs only on a CPU with at least these instructions.
native:
	$(MAKE) CFLAGS="$(CFLAGS) -march=native" hpcfg$(EXE)

info:
	@echo "## Operating System : $(UNAME)"
	@echo "## Compiler target  : $(TARGET)"
	@echo "## LTO              : $(ENABLE_LTO)"

clean:
	rm -f hpcfg hpcfg.exe
	rm -f $(OBJDIR)/*.o $(OBJDIR)/*.d

.PHONY: clean native info
