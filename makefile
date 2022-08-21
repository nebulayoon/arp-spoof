LDLIBS=-lpcap

all: send-arp-test


main.o: mac.h ip.h ethhdr.h arphdr.h main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

iphdr.o: mac.h ethhdr.h iphdr.cpp

util.o : util.h util.cpp

arpattk.o : mainstruct.h arpattk.h arpattk.cpp

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o iphdr.o util.o arpattk.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o