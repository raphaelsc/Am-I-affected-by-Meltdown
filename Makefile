CC=g++
CFLAGS=-I. --std=c++11 -O0 --no-pie -fPIC
CC_VER_GTE48 := $(shell expr `$(CC) -dumpversion | cut -f1 -d.` \>= 4.8)

OBJ=meltdown_checker.o

ifeq ($(CC_VER_GTE48), 1)
CFLAGS += -mrtm -DHAS_COMPILER_RTM_SUPPORT
endif

%.o: %.cc
	$(CC) $(CFLAGS) -c -o $@ $< 

meltdown-checker: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean

clean:
	rm -f meltdown-checker *.o *~ *.out
