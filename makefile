LDLIBS += -lpcap

all: deauth_attack

airodump: deauth_attack.c

clean:
	rm -f deauth_attack *.o