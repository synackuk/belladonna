CC = gcc
RM = rm
CFLAGS = -W -Wall -pedantic -O2 -I../
LDFLAGS = -L/usr/lib -L/usr/local/lib -L../ -L/usr/local/opt/openssl/lib
LIBRARIES = -lfragmentzip -lbelladonna -lz -lzip -lirecovery -limobiledevice -lplist -lcrypto -lcurl
OBJECTS = belladonna.o

all: belladonna

belladonna: $(OBJECTS)
	@echo Building $(@)
	@$(CC) $(LDFLAGS) $(LIBRARIES) -o belladonna $(OBJECTS)

%.o: %.c
	@echo CC -c $(<) -o $(@)
	@$(CC) $(CFLAGS) -c $(<) -o $(@)

clean:
	@$(RM) -rf *.o
	@$(RM) -rf belladonna