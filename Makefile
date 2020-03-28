CC ?= gcc
#ifdef DEBUG
CFLAGS := -g
#endif
SOURCES := $(wildcard src/*.c)
OBJECTS := $(patsubst %.c, %.o, ${SOURCES})

all: ELF_Parser

ELF_Parser: ${OBJECTS} 
	@echo ${OBJECTS}
	${Q} ${CC} ${CFLAGS} $^ -o $@

%.o: %.c
	${Q} ${CC} ${CFLAGS} -c $< -o $@

clean:
	- rm ${OBJECTS} 

.PHONY: all
