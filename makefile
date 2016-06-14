mydump: mydump.c
	gcc mydump.c -o mydump -lpcap

clean:
	rm -f mydump
