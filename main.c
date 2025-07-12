#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "dnsutils.h"

/*
recursive resolver server:
1) lookup cache with TTL
2) query root server
3) query TLD server from root response(NS record)
4) query the authoritative server with respect to the domain your looking for to get the DNS record(A/AAAA/MX/CNAME) with UDP/IP
*/

int main(void) {
	return EXIT_FAILURE;
}
