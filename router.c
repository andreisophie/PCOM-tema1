#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>

#define MAX_RT_SIZE 100000

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// parse route table
	struct route_table_entry *route_table = calloc(MAX_RT_SIZE, sizeof(struct route_table_entry));
	read_rtable(argv[1], route_table);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		printf("---START PACHET---\n");
		printf("Adresa mea IP este %s\n", get_interface_ip(interface));
		// verific tipul de pachet (IP sau ARP)
		uint16_t pck_ether_type = ntohs(eth_hdr->ether_type);
		if (pck_ether_type == 0x0800) {
			printf("Am primit pachet IP\n");
			struct iphdr *header_ip = (struct iphdr *)(buf + sizeof(struct ether_header));
			// verific daca pachetul este pentru mine
			if (inet_addr(get_interface_ip(interface)) ==  header_ip->daddr) {
				printf("Acest pachet este pentru mine\n");
			} else {
				printf("Acest pachet este pentru altcineva\n");
				// verific checksum-ul
				uint16_t old_check = ntohs(header_ip->check);
				header_ip->check = 0;
				printf("checksum pachet = %d\n", old_check);
				printf("checksum calculat = %d\n", checksum((uint16_t *)header_ip, sizeof(struct iphdr)));
				if (old_check != checksum((uint16_t *)header_ip, sizeof(struct iphdr))) {
					printf("checksum gresit\n");
					continue;
				}
				printf("checksum corect\n");
				// verific TTL
				if (header_ip->ttl == 1 || header_ip->ttl == 0) {
					printf("pachetul are ttl<1, trebuie aruncat\n");
					// trimit raspuns ICMP catre sender
					continue;
				}
				header_ip->ttl--;
				// caut in tabela de rutare

				// actualizez checksum
				header_ip->check = checksum((uint16_t *)header_ip, sizeof(struct iphdr));
				
			}
		} else {
			if (pck_ether_type == 0x0806) {
				printf("Am primit pachet ARP\n");
			} else {
				printf("Am primit un pachet pe care nu il cunosc\n");
			}
		}
		printf("---GATA PACHET---\n\n");
	}
}

