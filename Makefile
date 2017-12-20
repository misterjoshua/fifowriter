CFLAGS=-Wall -pedantic -g
LFLAGS=-g -lc
LINKER=gcc

SRCDIR=src
OBJDIR=obj
BINDIR=bin

SOURCES := $(wildcard $(SRCDIR)/*.c)
OBJECTS := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

TARGET=bin/fifowriter

# Build objs in obj dir.
$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@



all: $(TARGET)




$(TARGET): $(OBJECTS)
	$(LINKER) $(LFLAGS) $(OBJECTS) -o $@

clean:
	find $(BINDIR) $(OBJDIR) -type f -not -name ".git*" -print0 | xargs rm -f
