send_arp: main.o func.o
	gcc -o send_arp main.o func.o -lpcap

main.o: header.h main.c
	gcc -c -o main.o main.c

func.o: header.h func.c
	gcc -c -o func.o func.c

clean:
	rm *.o send_arp
