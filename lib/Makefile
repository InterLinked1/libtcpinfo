CC		= gcc
CFLAGS = -Wall -Werror -Wno-unused-parameter -Wextra -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement -Wmissing-declarations -Wmissing-format-attribute -Wformat=2 -Wshadow -std=gnu99 -pthread -O0 -g -Wno-stack-protector -fno-omit-frame-pointer -D_FORTIFY_SOURCE=2
EXE		= tcpinfo
LIBNAME = lib$(EXE)
LIBS	= -lm
RM		= rm -f
INSTALL = install

MAIN_OBJ := $(EXE).o

all : main

%.o: %.c
	$(CC) $(CFLAGS) -c  $^ -fPIC

main : $(MAIN_OBJ)
	$(CC) -shared -fPIC -o $(LIBNAME).so $^ $(LIBS)

install: main
	$(INSTALL) -m  755 $(LIBNAME).so "/usr/lib"
	$(INSTALL) -m  755 $(EXE).h "/usr/include"

clean :
	$(RM) *.i *.o $(LIBNAME).so

.PHONY: all
.PHONY: main
.PHONY: clean
