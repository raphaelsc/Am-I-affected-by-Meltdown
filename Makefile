CC=g++
CFLAGS=-I. --std=c++11 -O0 --no-pie -fPIC
GCC_VER_GTE48 := $(shell echo `gcc -dumpversion | cut -f1-2 -d.` \>= 4.8 | bc )

OBJ=meltdown_checker.o

ifeq ($(GCC_VER_GTE48), 1)
CFLAGS += -mrtm -DHAS_COMPILER_RTM_SUPPORT
endif

%.o: %.cc
	$(CC) $(CFLAGS) -c -o $@ $< 

meltdown-checker: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean

clean:
	rm -f meltdown-checker *.o *~ *.out
