CC = gcc
AR = ar
RM = rm
CFLAGS = -W -Wall -pedantic -Wno-zero-length-array -O2 -I/usr/local/include -I/opt/local/include -I. -I./ipsw -I./libloader -mmacosx-version-min=10.12
OBJECTS = libbelladonna.o

.PHONY: exploits idevicerestore

all: libbelladonna.a
	@make -C tools

libbelladonna.a: exploits idevicerestore $(OBJECTS)
	@echo Building $(@)
	@echo AR rs $(@) $(OBJECTS) idevicerestore/*.o exploits/*.o
	@$(AR) rs $(@) $(OBJECTS) idevicerestore/*.o exploits/*.o

idevicerestore:
	@echo Building $(@)
	@make -C idevicerestore

exploits:
	@echo Building $(@)
	@make -C exploits

%.o: %.c
	@echo CC -c $(<) -o $(@)
	@$(CC) $(CFLAGS) -c $(<) -o $(@)

clean:
	@make clean -C exploits
	@make clean -C tools
	@make clean -C idevicerestore
	@$(RM) -rf *.o
	@$(RM) -rf *.a
