CC = gcc
#LIBS = -lrt -lpthread
LIBS = -lpthread
FLAGS = -O -w -Wall -O9 -funroll-loops -DGF_BITS=8
EXECS = ../entrance ../exit ../entrance_dbg ../exit_dbg ../repeater

all: $(EXECS)

../entrance: forwarder.c
	$(CC) $(FLAGS) -o ../entrance $? ../FEC/fec.o $(LIBS) -DTYPE=0 
	cp ../entrance ../remote/

../entrance_dbg: forwarder.c
	$(CC) $(FLAGS) -g -o ../entrance_dbg $? ../FEC/fec.o $(LIBS) -DMYDEBUG -DTYPE=0
	cp ../entrance_dbg ../remote/

../exit: forwarder.c
	$(CC) $(FLAGS) -o ../exit $? ../FEC/fec.o $(LIBS) -DTYPE=1
	cp ../exit ../remote/

../exit_dbg: forwarder.c
	$(CC) $(FLAGS) -g -o ../exit_dbg $? ../FEC/fec.o $(LIBS) -DMYDEBUG -DTYPE=1
	cp ../exit_dbg ../remote/

../repeater: repeater.c
	$(CC) $(FLAGS) -o ../repeater $? $(LIBS)
	cp ../repeater ../remote/

clean:
	rm $(EXECS)
