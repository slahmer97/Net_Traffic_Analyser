# include makefile.mk

SOURCES = main.c internet_layer.c link_layer.c transport_layer.c application_layer.c
HEADERS = internet_layer.h link_layer.h transport_layer.h bootph.h includes.h global.h
OBJS= $(SOURCES:.c=.o)
GCH = $(SOURCES:.c=.h.gch)

LIBS = -lpcap
CC = gcc

target : $(SOURCES) $(HEADERS)
	$(CC) $(SOURCES) $(HEADERS) -lpcap


main.o : main.c
	$(CC) $(FLAGS) $(LIBS) main.c -o main.o

exec-wlp2s0 :
	sudo ./a.out -i wlp2s0

exec-wlp2s0-1 :
	sudo ./a.out -i wlp2s0 -v 1

exec-wlp2s0-2 :
	sudo ./a.out -i wlp2s0 -v 2

exec-wlp2s0-3 :
	sudo ./a.out -i wlp2s0 -v 3

clean :
	rm $(OBJS) 2>/dev/null && rm $(GCH) 2>/dev/null
