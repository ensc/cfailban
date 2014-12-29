PACKAGE = cfailban
VERSION = 0.0.1

srcdir = $(dir $(firstword $(MAKEFILE_LIST)))

include $(srcdir)/ensc-lib/build-simple.mk

VPATH += $(abs_top_srcdir)

AM_CPPFLAGS = \
	-I $(abs_top_srcdir) -I $(abs_top_builddir) \
	-D PACKAGE=\"$(PACKAGE)\" -D VERSION=\"$(VERSION)\" \
	-D _GNU_SOURCE -D CONFIG_DYNAMIC_DEBUG_LEVEL

AM_CFLAGS = \
	-std=gnu99 ${C_FLTO}

AM_LDFLAGS = \
	-Wl,-as-needed \
	${LD_FLTO}

CFLAGS = -Wall -W -Werror -Wno-unused-parameter -Wmissing-prototypes -Wshadow -O1 -g3

extra_CPPFLAGS := \
	$(call _find_symbol,iniparser_getsecnkeys,\#include <iniparser.h>) \
	$(call _find_symbol,CLOCK_BOOTTIME,\#include <time.h>)

AM_CPPFLAGS += ${extra_CPPFLAGS}

bin_PROGRAMS = cfailban

test_PROGRAMS = testsuite/source-fifo
test_SCRIPTS = testsuite/run_source-fifo

cfailban_SOURCES = \
	src/configuration-rules.c \
	src/configuration-source.c \
	src/configuration-filter.c \
	src/configuration-whitelist.c \
	src/configuration.c \
	src/configuration.h \
	src/failban.c \
	src/failban.ggo.in \
	src/failban.h \
	src/filter.c \
	src/iniparser-legacy.c \
	src/iniparser-legacy.h \
	src/logging.h \
	src/rules.c \
	src/rules.h \
	src/source-fifo.c \
	src/source-socket.c \
	src/source-generic.c \
	src/source-generic.h \
	src/source.c \
	src/source.h \
	ensc-lib/compiler-gcc.h \
	ensc-lib/compiler-lint.h \
	ensc-lib/compiler.h \
	ensc-lib/iniparser-pwdb.c \
	ensc-lib/iniparser.h \
	ensc-lib/io.c \
	ensc-lib/io.h \
	ensc-lib/list.h \
	ensc-lib/logging.c \
	ensc-lib/logging.h \
	ensc-lib/safe_calloc.h \
	ensc-lib/strbuf.h \
	ensc-lib/timespec.h \
	ensc-lib/xalloc.h \

cfailban_OBJECTS = \
	src/failban-cmdline.o

cfailban_LIBS = \
	-liniparser \
	-lcom_err \
	-lrt

CFLAGS_src/failban-cmdline.o = -Wno-unused-but-set-variable

CPPFLAGS_cfailban = -I ${abs_top_builddir}/src

testsuite/source-fifo_SOURCES = \
	testsuite/source-fifo.c \
	src/source-fifo.c \
	src/source-generic.c \
	src/source-generic.h \
	src/source.h \
	ensc-lib/logging.c \
	ensc-lib/logging.h \

testsuite/source-fifo_LIBS = \
	-lcom_err

BUILT_SOURCES = \
	src/failban.ggo \
	src/failban-cmdline.c \
	src/failban-cmdline.h \

ALL_SOURCES = \
	Makefile \
	cfailban.conf \
	${cfailban_SOURCES} \
	${testsuite/source-fifo_SOURCES} \
	${test_SCRIPTS}

SED_CMD = \
	-e 's!@SYSCONFDIR@!${sysconfdir}!g'

#################################

all:	$(bin_PROGRAMS) $(test_PROGRAMS)

cfailban:	${cfailban_SOURCES} ${cfailban_OBJECTS}
	$(CC) $(call _buildflags,C) $(filter %.c %.o,$^) -o $@ $($@_LIBS)

testsuite/source-fifo:	${testsuite/source-fifo_SOURCES} ${testsuite/source-fifo_OBJECTS} \
	| testsuite/.dirstamp
	$(CC) $(call _buildflags,C) $(filter %.c %.o,$^) -o $@ $($@_LIBS)

src/failban-cmdline.o:	src/failban-cmdline.c src/failban-cmdline.h
	$(CC) $(call _buildflags,C) $(filter %.c,$^) -c -o $@

src/failban-cmdline.c src/failban-cmdline.h:	src/.failban-cmdline.stamp

src/.%-cmdline.stamp:	src/%.ggo | src/.dirstamp
	$(GENGETOPT) -i $< -F ${@D}/$*-cmdline
	@touch $@

src/%.ggo:	src/%.ggo.in | src/.dirstamp
	-rm -f $@ $@.tmp
	$(SED) $(SED_CMD) $< >$@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

%/.dirstamp:
	mkdir -p ${@D}
	@touch $@

clean:
	rm -f .*stamp */.*stamp *.o */*.o
	rm -f ${BUILT_SOURCES} ${bin_PROGRAMS} ${test_PROGRAMS}

$(eval $(call _distrule,.xz,${ALL_SOURCES}))
$(eval $(call _checkrules,${ALL_SOURCES}))
