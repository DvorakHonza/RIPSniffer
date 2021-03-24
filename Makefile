CFLAGS=-std=gnu99 -Wall -Wextra -pedantic -g

all: myripsniffer myripresponse myriprequest

myripsniffer: myriplib.c myripsniffer.c -lpcap

myripresponse: myriplib.c myripresponse.c

myriprequest: myriplib.c myriprequest.c

clean:
	@rm -f myripsniffer
	@rm -f myripresponse
	@rm -f myriprequest