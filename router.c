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

int send_packet(void *buf,
				int len,
				struct ether_header *eth_hdr,
				struct iphdr *ip_hdr,
				int interface);

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

int check_checksum_ip(struct iphdr *header_ip) {
	// verific checksum-ul
	uint16_t old_check = ntohs(header_ip->check);
	header_ip->check = 0;
	if (old_check != checksum((uint16_t *)header_ip, sizeof(struct iphdr))) {
		printf("checksum ip gresit\n");
		return -1;
	}
	printf("checksum ip corect\n");
	return 0;
}

int check_checksum_icmp(struct icmphdr *icmp_hdr) {
	uint16_t old_checksum = ntohs(icmp_hdr->checksum);
	icmp_hdr->checksum = 0;
	uint16_t calc_checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));
	if (old_checksum != calc_checksum) {
		printf("Checksum icmp gresit\n");
		printf("checksum icmp old = %d\n", old_checksum);
		printf("checksum icmp calculat = %d\n", calc_checksum);
		return -1;
	}
	return 0;
}

// functie care construieste un nou pachet de eroare icmp cu tipul si codul date
int send_icmp_error(int interface, struct iphdr *old_iphdr, int icmp_type, int icmp_code) {
	// trimit raspuns ICMP catre sender
	char buf2[MAX_PACKET_LEN] = {0};
	size_t len2 = sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8;
	// separ headerele din noul pachet
	struct ether_header *eth_hdr2 = (struct ether_header *)buf2;
	struct iphdr *ip_hdr2 = (struct iphdr *)(buf2 + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr2 = (struct icmphdr *)(buf2 + sizeof(struct ether_header) + sizeof(struct iphdr));
	// setez tipul pachetului
	eth_hdr2->ether_type = htons(0x0800);
	// setez campurile din header-ul IP
	ip_hdr2->ihl = 5;
	ip_hdr2->version = 4;
	ip_hdr2->tos = 0;
	// TODO: id ?
	ip_hdr2->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr2->frag_off = htons(0);
	ip_hdr2->protocol = IPPROTO_ICMP;
	ip_hdr2->ttl = 64;
	ip_hdr2->saddr = old_iphdr->daddr;
	ip_hdr2->daddr = old_iphdr->saddr;
	ip_hdr2->check = htons(checksum((uint16_t *)ip_hdr2, sizeof(struct iphdr)));
	// setez campurile din header-ul icmp
	icmp_hdr2->type = icmp_type;
	icmp_hdr2->code = icmp_code;
	icmp_hdr2->checksum = htons(checksum((uint16_t *)icmp_hdr2, sizeof(struct icmphdr)));
	// copiez sub header-ul icmp vechiul header ip si 8 octeti din pachetul vechi
	memcpy(icmp_hdr2 + sizeof(struct icmphdr), old_iphdr, sizeof(struct iphdr) + 8);
	return send_packet(buf2, len2, eth_hdr2, ip_hdr2, interface);
}

// functie care trimite un raspuns arp reply la un arp request
int reply_arp(void *buf,
				int len,
				struct ether_header *eth_hdr,
				struct arp_header *arp_hdr,
				int interface) {
	// marchez pachetul ca fiind reply
	arp_hdr->op = htons(2);
	// inversez adresele ip
	uint32_t ip_addr = arp_hdr->spa;
	arp_hdr->spa = arp_hdr->tpa;
	arp_hdr->tpa = ip_addr;
	// completez adresele mac
	memcpy(arp_hdr->tha, arp_hdr->sha, 6);
	get_interface_mac(interface, arp_hdr->sha);
	// swap adresele mac din header ethernet
	uint8_t mac_addr[6];
	memcpy(mac_addr, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, mac_addr, 6);
	printf("Trimit pachet arp\n");
	printf("ether_dhost=");
	for (int i = 0; i < 6; i++) {
		printf("%x.", eth_hdr->ether_dhost[i]);
	}
	printf("\n");
	printf("ether_shost=");
	for (int i = 0; i < 6; i++) {
		printf("%x.", eth_hdr->ether_shost[i]);
	}
	printf("\n");

	return send_to_link(interface, buf, len);
}

// functie care imi trimite pachetul dupa ce am setat header-ul ip si celelalte date
// (aceasta functie imi cauta adresele mac)
int send_packet(void *buf,
				int len,
				struct ether_header *eth_hdr,
				struct iphdr *ip_hdr,
				int interface) {
	struct route_table_entry *entry_next_hop = get_best_route(ip_hdr->daddr);
	if (entry_next_hop == NULL) {
		printf("unknown IP address\n");
		send_icmp_error(interface, ip_hdr, 3, 0);
		return -1;
	}
	uint32_t next_hop_ip = entry_next_hop->next_hop;

	get_interface_mac(interface, eth_hdr->ether_shost);
	DIE(eth_hdr->ether_shost == NULL, "get_interface_mac error");
	// look for destination mac in ARP table
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == next_hop_ip) {
			memcpy(eth_hdr->ether_dhost, arp_table[i].mac, 6 * sizeof(uint8_t));
		}
	}

	return send_to_link(entry_next_hop->interface, buf, len);
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

		printf("\n---START PACHET---\n");
		printf("Adresa mea IP este %s\n", get_interface_ip(interface));
		// verific tipul de pachet (IP sau ARP)
		uint16_t pck_ether_type = ntohs(eth_hdr->ether_type);
		if (pck_ether_type == 0x0800) {
			printf("Am primit pachet IP\n");
			struct iphdr *header_ip = (struct iphdr *)(buf + sizeof(struct ether_header));

			// verific checksum-ul ip
			if (check_checksum_ip(header_ip) < 0) {
				continue;
			}

			// verific TTL
			if (header_ip->ttl == 1 || header_ip->ttl == 0) {
				// daca ttl<=1, trimit raspuns icmp
				printf("pachetul are ttl<=1, trimit raspuns");
				send_icmp_error(interface, header_ip, 11, 0);
				continue;
			}
			header_ip->ttl--;
			printf("ttl=%d\n", header_ip->ttl);

			// verific daca pachetul este pentru mine
			if (inet_addr(get_interface_ip(interface)) ==  header_ip->daddr) {
				printf("Acest pachet este pentru mine\n");
				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				// verific checksum-ul header-ului icmp
				// if (check_checksum_icmp(icmp_hdr) < 0) {
				// 	continue;
				// }

				// verific ce vrea pachetul
				printf("icmp type=%d, code=%d\n", icmp_hdr->type, icmp_hdr->code);
				if (icmp_hdr->type == 8 && icmp_hdr->code == 0) {
					// am primit pachet "Hello" (echo request)
					// raspund cu "I'm alive" (echo reply)
					icmp_hdr->type = 0;
					icmp_hdr->code = 0;
					uint32_t src_addr = header_ip->saddr;
					header_ip->saddr = header_ip->daddr;
					header_ip->daddr = src_addr;
				} else {
					printf("ICMP Message not recognized\n");
				}
				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));
			}
			
			// actualizez checksum
			header_ip->check = htons(checksum((uint16_t *)header_ip, sizeof(struct iphdr)));

			// trimit pachetul cu functia specializata
			send_packet(&buf, len, eth_hdr, header_ip, interface);
		} else {
			if (pck_ether_type == 0x0806) {
				printf("Am primit pachet ARP\n");
				struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
				// daca pachetul este de tip request, ii raspund
				if (arp_hdr->op == htons(1)) {
					reply_arp(buf, len, eth_hdr, arp_hdr, interface);
				}
			} else {
				printf("Am primit un pachet pe care nu il cunosc\n");
			}
		}
		printf("---GATA PACHET---\n");
	}
}

