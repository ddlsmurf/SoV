# Macros
PROG = SoV
SRC = \
	src/SoV.c \
	src/SoV_CommandLineArguments.c \
	src/SoV_OuputQueue.c \
	src/SoV_PacketBuilder.c \
	src/SoV_PCap.c \
	src/SoV_Queue.c \
	src/SoV_Sockets.c \
	src/SoV_Utils.c
SRCH = \
	src/SoV.h \
	src/SoV_Constants.h \
	src/SoV_OS_Includes.h \
	src/SoV_OuputQueue.h \
	src/SoV_PacketBuilder.h \
	src/SoV_PCap.h \
	src/SoV_Queue.h \
	src/SoV_Sockets.h \
	src/SoV_Utils.h
CC = gcc
CFLAGS = -g -Wall
LIBS = -lpcap
OBJ =  $(SRC:.c=.o)

all: $(PROG)

$(PROG) : $(OBJ)
	$(CC) $(LIBS) $(OBJ) -o $(PROG)

$(OBJ) : $(SRCH)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	\rm $(OBJ)

fclean: clean
	\rm ./$(PROG)

re: clean all

tar: $(PROG) clean
	tar cjfv $(PROG)-src.tar.bz2 $(SRC) $(SRCH) Makefile SoV.vcproj
	tar cjfv $(PROG)-bin-osx.tar.bz2 $(PROG)
