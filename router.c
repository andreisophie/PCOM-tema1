#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);


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

		uint16_t pck_ether_type = ntohs(eth_hdr->ether_type);
		if (pck_ether_type == 0x0800) {
			printf("Am primit pachet IP\n");
		} else {
			if (pck_ether_type == 0x0806) {
				printf("Am primit pachet ARP\n");
			} else {
				printf("Am primit un pachet pe care nu il cunosc\n");
			}
		}
	}
}

