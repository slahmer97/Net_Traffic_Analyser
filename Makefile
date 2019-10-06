# include makefile.mk

SOURCES = main.c internet_layer.c link_layer.c transport_layer.c application_layer.c
HEADERS = glob.h internet_layer.h link_layer.h transport_layer.h bootp.h includes.h
OBJS= $(SOURCES:.c=.o)
GCH = $(SOURCES:.c=.gch)

LIBS = -lpcap
CC = gcc

target : $(SOURCES) $(HEADERS)
	$(CC) $(SOURCES) $(HEADERS) -lpcap


main.o : main.c glob.h
	$(CC) $(FLAGS) $(LIBS) main.c glob.h -o main.o

exec-wlp2s0 :
	sudo ./a.out -i wlp2s0

exec-wlp2s0-1 :
	sudo ./a.out -i wlp2s0 -v 1

exec-wlp2s0-2 :
	sudo ./a.out -i wlp2s0 -v 2

exec-wlp2s0-3 :
	sudo ./a.out -i wlp2s0 -v 3

clean :
	rm $(OBJS)
clean2 :
	rm $(GCH)