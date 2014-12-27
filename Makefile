abs_top_srcdir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
VPATH += $(abs_top_srcdir)

include $(abs_top_srcdir)/ensc-lib/build-simple.mk

GENGETOPT = gengetopt

C_FLTO = -flto
LD_FLTO = -fuse-linker-plugin ${C_FLTO}

AM_CPPFLAGS = \
	-I $(abs_top_srcdir) -I $(abs_top_builddir) \
	-D PACKAGE=\"$(PACKAGE)\" -D VERSION=\"$(VERSION)\" \
	-D _GNU_SOURCE -D CONFIG_DYNAMIC_DEBUG_LEVEL

AM_CFLAGS = \
	-std=gnu11  ${C_FLTO}

AM_LDFLAGS = \
	${LD_FLTO}

CFLAGS = -Wall -W -Werror -Wno-unused-parameter -Wmissing-prototypes -Wshadow -O1 -g3

bin_PROGRAMS = failban
test_PROGRAMS = testsuite/source-fifo

failban_SOURCES = \
	src/failban.ggo \
	src/failban.c \
	src/configuration.c \
	src/configuration.h \
	src/configuration-rules.c \
	src/configuration-source.c \
	src/rules.c \
	src/rules.h \
	src/filter.c \
	src/source-fifo.c \
	src/source-generic.c \
	src/source-generic.h \
	src/source.c \
	src/source.h \
	src/logging.h \
	ensc-lib/list.h \
	ensc-lib/io.c \
	ensc-lib/io.h \
	ensc-lib/logging.c \
	ensc-lib/logging.h \
	ensc-lib/iniparser-pwdb.c \
	ensc-lib/iniparser.h \

failban_OBJECTS = \
	src/failban-cmdline.o

failban_LIBS = \
	-liniparser \
	-lcom_err

CFLAGS_src/failban-cmdline.o = -Wno-unused-but-set-variable

CPPFLAGS_failban = -I ${abs_top_builddir}/src

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
	src/failban-cmdline.c \
	src/failban-cmdline.h \

#################################

all:	$(bin_PROGRAMS) $(test_PROGRAMS)

failban:	${failban_SOURCES} ${failban_OBJECTS}
	$(CC) $(call _buildflags,C) $(filter %.c %.o,$^) -o $@ $($@_LIBS)

testsuite/source-fifo:	${testsuite/source-fifo_SOURCES} ${testsuite/source-fifo_OBJECTS}
	$(CC) $(call _buildflags,C) $(filter %.c %.o,$^) -o $@ $($@_LIBS)

src/failban-cmdline.o:	src/failban-cmdline.c src/failban-cmdline.h
	$(CC) $(call _buildflags,C) $(filter %.c,$^) -c -o $@

src/failban-cmdline.c src/failban-cmdline.h:	src/.failban-cmdline.stamp

src/.%-cmdline.stamp:	src/%.ggo | src/.dirstamp
	$(GENGETOPT) -i $< -F ${@D}/$*-cmdline
	touch $@

%/.dirstamp:
	mkdir -p ${@D}
	@touch $@

clean:
	rm -f .*stamp */.*stamp *.o */*.o
	rm -f ${BUILT_SOURCES}

check-syntax:
	$(CC) $(call _buildflags,C) ${CHK_SOURCES} -o /dev/null -c
