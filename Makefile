TESTDIR := test
SRCDIR := src
APPDIR := app
INCDIR := inc
OBJDIR := obj
OUTDIR := bin
LIBPRE := lib
LIBEXT := a
SRCEXT := c
HDREXT := h
DEPEXT := d
OBJEXT := o
YACCEXT := y
LEXEXT := l

COMPILE_DB_EXT := json
COMPILE_DB := compile_commands.$(COMPILE_DB_EXT)
CTAGS := ctags

LFLAGS +=
YFLAGS +=
CFLAGS += -std=c99 -Wall -Wextra -Wpedantic -I$(INCDIR)
APPCFLAGS += -D_POSIX_C_SOURCE=200809L # App needs POSIX real-time extensions
APPCFLAGS += -D__XSI_VISIBLE=1 # App needs X/Open System Interfaces (XSI) for gettimeofday

ifeq ($(DEBUG),1)
CFLAGS += -fsanitize=address,undefined -O0 -g
LDFLAGS += -fsanitize=address,undefined
YFLAGS += -t
else
CFLAGS += -O3 -DNDEBUG
endif

ifeq ($(RATP_LOGGING),1)
CFLAGS += -DRATP_LOGGING
endif

TARGET := ratp
APP_TARGET := ratp_talk
TEST_TARGET := test_ratp

SOURCES := $(SRCDIR)/ratp.c \
           $(SRCDIR)/ratp_packet_parser.c

LEX_SOURCES := $(TESTDIR)/schema_scanner.l
LEX_C_OUTPUTS := $(LEX_SOURCES:.$(LEXEXT)=.$(SRCEXT))
LEX_OUTPUTS := $(LEX_C_OUTPUTS) $(LEX_SOURCES:.$(LEXEXT)=.$(HDREXT))

YACC_SOURCES := $(TESTDIR)/schema_parser.y
YACC_C_OUTPUTS := $(YACC_SOURCES:.$(YACCEXT)=.$(SRCEXT))
YACC_OUTPUTS := $(YACC_C_OUTPUTS) $(YACC_SOURCES:.$(YACCEXT)=.$(HDREXT))

TEST_SOURCES := $(TESTDIR)/test_ratp.c \
                $(TESTDIR)/test_ratp_packet.c \
                $(TESTDIR)/test_ratp_packet_parser.c \
                $(TESTDIR)/schema_tester.c \
                $(LEX_C_OUTPUTS) \
                $(YACC_C_OUTPUTS) \
                $(TESTDIR)/test_main.c

APP_SOURCES := $(APPDIR)/ratp_talk.c

################################################################################
# Derived variables

OBJECTS := $(patsubst $(SRCDIR)/%,$(OBJDIR)/%,$(SOURCES:.$(SRCEXT)=.$(OBJEXT)))
TEST_OBJECTS := $(patsubst $(TESTDIR)/%,$(OBJDIR)/%,$(TEST_SOURCES:.$(SRCEXT)=.$(OBJEXT)))
APP_OBJECTS := $(patsubst $(APPDIR)/%,$(OBJDIR)/%,$(APP_SOURCES:.$(SRCEXT)=.$(OBJEXT)))
ALL_OBJECTS := $(OBJECTS) $(TEST_OBJECTS) $(APP_OBJECTS)
COMPILE_DB_OBJECTS := $(patsubst $(SRCDIR)/%,$(OBJDIR)/%,$(SOURCES:.$(SRCEXT)=.$(COMPILE_DB_EXT)))
COMPILE_DB_TEST_OBJECTS := $(patsubst $(TESTDIR)/%,$(OBJDIR)/%,$(TEST_SOURCES:.$(SRCEXT)=.$(COMPILE_DB_EXT)))
COMPILE_DB_APP_OBJECTS := $(patsubst $(APPDIR)/%,$(OBJDIR)/%,$(APP_SOURCES:.$(SRCEXT)=.$(COMPILE_DB_EXT)))
ALL_COMPILE_DB_OBJECTS := $(COMPILE_DB_OBJECTS) $(COMPILE_DB_TEST_OBJECTS) $(COMPILE_DB_APP_OBJECTS)

HEADERS := $(shell find $(INCDIR) $(SRCDIR) $(TESTDIR) $(APPDIR) -type f -name *.$(HDREXT))

################################################################################
# High-level targets

all: app

app: directories $(OUTDIR)/$(APP_TARGET)

lib: directories $(OUTDIR)/$(LIBPRE)$(TARGET).$(LIBEXT)

test: directories $(OUTDIR)/$(TEST_TARGET)

directories:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(OUTDIR)

clean:
	rm -rf $(OBJDIR)
	rm -f $(YACC_OUTPUTS) $(LEX_OUTPUTS)
	rm -f tags $(COMPILE_DB)

clean_all: clean
	rm -rf $(OUTDIR)

################################################################################
# Automatic header include dependencies
-include $(ALL_OBJECTS:.$(OBJEXT)=.$(DEPEXT))

$(OBJDIR)/%.$(DEPEXT): $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -MM $(SRCDIR)/$*.$(SRCEXT) > $(OBJDIR)/$*.$(DEPEXT)
	@mv -f $(OBJDIR)/$*.$(DEPEXT) $(OBJDIR)/$*.$(DEPEXT).tmp
	@sed -e 's|.*:|$(OBJDIR)/$*.$(OBJEXT):|' < $(OBJDIR)/$*.$(DEPEXT).tmp > $(OBJDIR)/$*.$(DEPEXT)
	@sed -e 's/.*://' -e 's/\\$$//' < $(OBJDIR)/$*.$(DEPEXT).tmp | fmt -1 | sed -e 's/^ *//' -e 's/$$/:/' >> $(OBJDIR)/$*.$(DEPEXT)
	@rm -f $(OBJDIR)/$*.$(DEPEXT).tmp

$(OBJDIR)/%.$(DEPEXT): $(APPDIR)/%.$(SRCEXT)
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $(APPCFLAGS) -MM $(APPDIR)/$*.$(SRCEXT) > $(OBJDIR)/$*.$(DEPEXT)
	@mv -f $(OBJDIR)/$*.$(DEPEXT) $(OBJDIR)/$*.$(DEPEXT).tmp
	@sed -e 's|.*:|$(OBJDIR)/$*.$(OBJEXT):|' < $(OBJDIR)/$*.$(DEPEXT).tmp > $(OBJDIR)/$*.$(DEPEXT)
	@sed -e 's/.*://' -e 's/\\$$//' < $(OBJDIR)/$*.$(DEPEXT).tmp | fmt -1 | sed -e 's/^ *//' -e 's/$$/:/' >> $(OBJDIR)/$*.$(DEPEXT)
	@rm -f $(OBJDIR)/$*.$(DEPEXT).tmp

$(OBJDIR)/%.$(DEPEXT): $(TESTDIR)/%.$(SRCEXT)
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -MM $(TESTDIR)/$*.$(SRCEXT) > $(OBJDIR)/$*.$(DEPEXT)
	@mv -f $(OBJDIR)/$*.$(DEPEXT) $(OBJDIR)/$*.$(DEPEXT).tmp
	@sed -e 's|.*:|$(OBJDIR)/$*.$(OBJEXT):|' < $(OBJDIR)/$*.$(DEPEXT).tmp > $(OBJDIR)/$*.$(DEPEXT)
	@sed -e 's/.*://' -e 's/\\$$//' < $(OBJDIR)/$*.$(DEPEXT).tmp | fmt -1 | sed -e 's/^ *//' -e 's/$$/:/' >> $(OBJDIR)/$*.$(DEPEXT)
	@rm -f $(OBJDIR)/$*.$(DEPEXT).tmp

################################################################################
# Compilaiton rules

$(OBJDIR)/%.$(OBJEXT): $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) -o $@ $<

$(OBJDIR)/%.$(OBJEXT): $(APPDIR)/%.$(SRCEXT)
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $(APPCFLAGS) -o $@ $<

$(OBJDIR)/%.$(OBJEXT): $(TESTDIR)/%.$(SRCEXT)
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) -o $@ $<

# Cancel default lex rule
%.c: %.l

# Cancel default yacc rule
%.c: %.y

%.$(SRCEXT) %.$(HDREXT): %.$(LEXEXT) $(YACC_OUTPUTS)
	$(LEX) $(LFLAGS) $<

%.$(SRCEXT) %.$(HDREXT): %.$(YACCEXT)
	$(YACC) $(YFLAGS) -d -o $*.$(SRCEXT) $<

$(OUTDIR)/$(LIBPRE)$(TARGET).$(LIBEXT): $(OBJECTS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(OUTDIR)/$(TEST_TARGET): $(OUTDIR)/$(LIBPRE)$(TARGET).$(LIBEXT) $(TEST_OBJECTS)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $(filter-out $<,$^) -L$(<D) -l$(TARGET) -o $@

$(OUTDIR)/$(APP_TARGET): $(OUTDIR)/$(LIBPRE)$(TARGET).$(LIBEXT) $(APP_OBJECTS)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $(filter-out $<,$^) -L$(<D) -l$(TARGET) -o $@

################################################################################
# Tooling help

$(OBJDIR)/%.$(COMPILE_DB_EXT): $(SRCDIR)/%.$(SRCEXT)
	@$(CC) -c $(CFLAGS) -o /dev/null -MJ $@ $<

$(OBJDIR)/%.$(COMPILE_DB_EXT): $(APPDIR)/%.$(SRCEXT)
	@$(CC) -c $(CFLAGS) $(APPCFLAGS) -o /dev/null -MJ $@ $<

$(OBJDIR)/%.$(COMPILE_DB_EXT): $(TESTDIR)/%.$(SRCEXT)
	@$(CC) -c $(CFLAGS) -o /dev/null -MJ $@ $<

$(COMPILE_DB): $(ALL_COMPILE_DB_OBJECTS)
	@awk 'BEGIN { print "[" } { print "  " $$0 } END { print "]" }' $^ > $@

tags: $(SOURCES) $(TEST_SOURCES) $(APP_SOURCES) $(HEADERS)
	$(CTAGS) -o $@ $^

.PHONY: all lib test directories clean clean_all
