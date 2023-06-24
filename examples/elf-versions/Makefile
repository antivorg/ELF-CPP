CC = g++
CFLAGS=-I -Wall -g

SCDIR = ../../elf-cpp

_DEPS = $(SCDIR)/inc/elf_parser.hpp
_OBJ = main.o $(SCDIR)/src/elf_parser.o

IDIR = .
ODIR = .
EDIR = ../../bin
OUT = elf-versions

DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(EDIR)/$(OUT): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
	rm $(OBJ)

.PHONY: clean
clean:
	rm $(EDIR)/$(OUT)

clean_obj:
	rm $(OBJ)

