#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define MAX_RT_SIZE 100000
#define MAX_ARP_SIZE 100000

// some global variables
static struct route_table_entry *rtable;
static int rtable_len;
static struct arp_entry *arp_table;
static int arp_table_len;

// comparator sortez descrescator dupa prefix si masca
int comparator(const void *route1, const void *route2) {
	struct route_table_entry *rentry1 = (struct route_table_entry *)route1;
	struct route_table_entry *rentry2 = (struct route_table_entry *)route2;

	if (rentry1->prefix != rentry2->prefix) {
		return rentry2->prefix - rentry1->prefix;
	}

	return rentry2->mask - rentry1->mask;
}

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	// TODO: implement binary search for this function
	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++). Entries in
	 * the rtable are in network order already */
	for (int i = 0; i < rtable_len; i++) {
		/* Cum tabela este sortată, primul match este prefixul ce mai specific */
		if (rtable[i].prefix == (ip_dest & rtable[i].mask)) {
			return &rtable[i];
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// parse route table and sort it
	rtable = calloc(MAX_RT_SIZE, sizeof(struct route_table_entry));
	rtable_len = read_rtable(argv[1], rtable);
	qsort((void *)rtable, rtable_len, sizeof(struct route_table_entry), comparator);
	// use static arp for destination mac address
	arp_table = calloc(MAX_ARP_SIZE, sizeof(struct arp_entry));
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

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
				// TODO: fa ceva
			} else {
				// verific checksum-ul
				uint16_t old_check = ntohs(header_ip->check);
				header_ip->check = 0;
				if (old_check != checksum((uint16_t *)header_ip, sizeof(struct iphdr))) {
					printf("checksum gresit\n");
					continue;
				}
				printf("checksum corect\n");
				// verific TTL
				if (header_ip->ttl == 1 || header_ip->ttl == 0) {
					printf("pachetul are ttl<1, trebuie aruncat\n");
					// TODO: trimit raspuns ICMP catre sender
					continue;
				}
				header_ip->ttl--;
				// actualizez checksum
				header_ip->check = htons(checksum((uint16_t *)header_ip, sizeof(struct iphdr)));

				// caut in tabela de rutare
				struct route_table_entry *entry_next_hop = get_best_route(header_ip->daddr);
				uint32_t next_hop_ip = entry_next_hop->next_hop;

				get_interface_mac(interface, eth_hdr->ether_shost);
				DIE(eth_hdr->ether_shost == NULL, "get_interface_mac error");
				// look for destination max in ARP table
				for (int i = 0; i < arp_table_len; i++) {
					if (arp_table[i].ip == next_hop_ip) {
						memcpy(eth_hdr->ether_dhost, arp_table[i].mac, 6 * sizeof(uint8_t));
					}
				}

				send_to_link(entry_next_hop->interface, buf, len);
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

