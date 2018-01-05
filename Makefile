CC=g++
CFLAGS=-I. --std=c++11 -O0 --no-pie -mrtm
OBJ=meltdown_checker.o

%.o: %.cc
	$(CC) $(CFLAGS) -c -o $@ $< 

meltdown-checker: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean

clean:
	rm -f meltdown-checker *.o *~ *.out
