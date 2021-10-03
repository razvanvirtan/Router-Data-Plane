#include <queue.h>
#include <fcntl.h>
#include "skel.h"
#include "list.h"

#define HASH_VALUE 33469

typedef struct route_line {
	struct in_addr prefix;
	struct in_addr next_hop;
	struct in_addr mask;
	int interface;
} route_line;

typedef struct route_node {
	route_line *line;
	struct route_node *left_child, *right_child;
} *Route_node;

typedef struct arp_line {
	struct in_addr ip;
	u_int8_t mac[ETH_ALEN];
	u_int8_t mac_set;
	queue packets_queue;
} *ARP_line;

// This function creates an empty entry in the route table tree.
Route_node create_route_node() {
	Route_node node = (Route_node) malloc(sizeof(struct route_node));
	node->left_child = node->right_child = NULL;
	node->line = NULL;

	return node;
}

/**
	@brief Function for reading a field of a route table entry (ex. mask, prefix etc).

	@param file File descriptor for the route table file
	@return char* The field that was a read, as a char (will need conversion)
**/
char* read_field(int file) {
	char* field = (char *) malloc(30 * sizeof(char));
	char character, result;
	int idx = 0;

	result = read(file, &character, sizeof(character));
	while(result != 0 && character != ' ' && character != '\n') {
		field[idx] = character;
		idx++;
		result = read(file, &character, sizeof(character));
	}

	if (idx == 0) {
		free(field);
		return  NULL;
	}
	field[idx] = '\0';

	return field;
}

/**
	@brief Function for parsing a route table file and obtaining the trie
	representation.

	@param file_name Name of the route table file
	@return Route_node, the root of the trie
**/
Route_node parseRouteTable(char *file_name) {
	Route_node root = create_route_node();

	int file = open(file_name, O_RDONLY);
	if (file < 0)
		return NULL;

	char *to_convert;
	u_int8_t mask_length;
	u_int32_t current_bit, selector, host_mask, host_prefix;
	route_line* new_line;
	Route_node new_node, parent;
	while (1) {
		// read the line of the route table
		new_line = (route_line*) malloc(sizeof(route_line));
		to_convert = read_field(file);
		if (to_convert == NULL)
			break;
		inet_aton(to_convert, &(new_line->prefix));
		host_prefix = ntohl(new_line->prefix.s_addr);
		free(to_convert);
		to_convert = read_field(file);
		inet_aton(to_convert, &(new_line->next_hop));
		free(to_convert);
		to_convert = read_field(file);
		inet_aton(to_convert, &(new_line->mask));
		host_mask = ntohl(new_line->mask.s_addr);
		free(to_convert);
		to_convert = read_field(file);
		new_line->interface = atoi(to_convert);
		free(to_convert);

		// find mask length
		mask_length = 0; selector = 1 << 31;
		while (host_mask & selector) {
			mask_length++;
			selector /= 2;
		}

		// insert this table line in the trie
		new_node = create_route_node();
		new_node->line = new_line;
		parent = root;
		selector = 1 << 31;
		
		// search the insertion point and create new nodes where needed
		while (mask_length > 1) {
			current_bit = host_prefix & selector;
			if (current_bit) {
				if (parent->right_child == NULL)
					parent->right_child = create_route_node();
				parent = parent->right_child;
			}
			else {
				if (parent->left_child == NULL)
					parent->left_child = create_route_node();
				parent = parent->left_child;
			}
			mask_length--; selector /= 2;
		}

		// insert the node coresponding to this table entry
		if (host_prefix & selector) {
			if (parent->right_child == NULL) {
				parent->right_child = new_node;
			}
			else if (parent->right_child->line == NULL ||
					parent->right_child->line->mask.s_addr < new_line->mask.s_addr) {
						parent->right_child->line = new_node->line;
				}
		}
		else {
			if (parent->left_child == NULL) {
				parent->left_child = new_node;
			}
			else if (parent->left_child->line == NULL ||
					parent->left_child->line->mask.s_addr < new_line->mask.s_addr) {
						parent->left_child->line = new_node->line;
				}
		}	
	} 
	return root;
}

/**
	@brief Function for finding the best match in the route table, for the given
	ip address.

	@param ip The ip whose best match we need to find
	@param root The root of the route table trie
	@return Pointer to the table entry that corresponds to the best match
**/
route_line* table_lookup(uint32_t ip, Route_node root) {
	uint32_t selector = 1 << 31, host_ip = ntohl(ip);
	Route_node current_node = root, best_match = NULL;

	while (current_node) {
		if (current_node->line != NULL) {
			best_match = current_node;
		}
		if ((host_ip & selector) == 0) {
			current_node = current_node->left_child;
		}
		else {
			current_node = current_node->right_child;
		}
		selector /= 2;
	}

	if (best_match == NULL)
		return NULL;
	return best_match->line;
}

/**
	@brief Function for inserting a new entry in the ARP table.

	@param ip The ip associated to a mac address in the new line of the table
	@param arp_table The arp_table to insert the entry in
	@return Pointer to the new inserted line
**/
ARP_line arp_insert(uint32_t ip, list *arp_table) {
	list bucket = arp_table[ip % HASH_VALUE];
	
	ARP_line new_line = (ARP_line) malloc(sizeof(struct arp_line));
	new_line->ip.s_addr = ip;
	new_line->packets_queue = queue_create();
	new_line->mac_set = 0;

	arp_table[ip % HASH_VALUE] = cons(new_line, bucket);
	
	return (ARP_line) arp_table[ip % HASH_VALUE]->element;
}

/**
	@brief Function for searching an entry that corresponds to an ip in the ARP table

	@param ip The ip address to look for
	@param arp_table The arp_table where we want to search
	@return Pointer to the entry we found, or NULL when we can't find one
**/
ARP_line arp_lookup(uint32_t ip, list *arp_table) {
	list iterator = arp_table[ip % HASH_VALUE];
	while (iterator != NULL) {
		if (((ARP_line ) (iterator->element))->ip.s_addr == ip) {
			return (ARP_line) (iterator->element);
		}
		iterator = iterator->next;
	}
	return NULL;
}

int main(int argc, char *argv[])
{  
	setvbuf(stdout , NULL , _IONBF , 0);
	packet m, *buffer, *send;
	int rc;
	struct arp_header *arp_hdr;
	struct in_addr interface_ip;
	struct ether_header eth_hdr;
	struct ether_header *send_header;
	struct iphdr *ip_hdr;
	struct icmphdr *icmp_hdr;
	route_line* table_line;
	int sent;

	init(argc - 2, argv + 2);
	Route_node root = parseRouteTable(argv[1]);
	list *arp_table = (list*) calloc(HASH_VALUE, sizeof(list));

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		arp_hdr = parse_arp(m.payload);
		inet_aton(get_interface_ip(m.interface), &interface_ip);

		// send ARP reply
		if (arp_hdr != NULL && ntohs(arp_hdr->op) == ARPOP_REQUEST) {
			eth_hdr.ether_type = htons(ETHERTYPE_ARP);
			memcpy(eth_hdr.ether_dhost, arp_hdr->sha, 6);
			get_interface_mac(m.interface, eth_hdr.ether_shost);

			send_arp(arp_hdr->spa, interface_ip.s_addr, &eth_hdr, m.interface, htons(ARPOP_REPLY));
			continue;
		}

		// receive ARP reply and send packets in queue
		if (arp_hdr != NULL && ntohs(arp_hdr->op) == ARPOP_REPLY) {
			ARP_line arp_line = arp_lookup(arp_hdr->spa, arp_table);
			if (arp_line == NULL)
				continue;
			memcpy(arp_line->mac, arp_hdr->sha, ETH_ALEN);
			arp_line->mac_set = 1;

			while (!queue_empty(arp_line->packets_queue)) {
				send = queue_deq(arp_line->packets_queue);
				send->interface = htonl(m.interface);
				send_header = (struct ether_header*) send->payload;
				memcpy(send_header->ether_dhost, arp_hdr->sha, ETH_ALEN);
				get_interface_mac(m.interface, send_header->ether_shost);

				ip_hdr = (struct iphdr *) (m.payload + sizeof(struct ether_header));
				ip_hdr->ttl = ip_hdr->ttl - 1;
				ip_hdr->check = 0;
				ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
				
				send_packet(m.interface, send);			
				free(send);
			}

			continue;
		}

		ip_hdr = (struct iphdr *) (m.payload + sizeof(struct ether_header));
		if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0)
				continue;
		table_line = table_lookup(ip_hdr->daddr, root);
		send_header = (struct ether_header*) m.payload;

		// ICMP reply
		icmp_hdr = parse_icmp(m.payload);
		if (icmp_hdr != NULL && icmp_hdr->type == ICMP_ECHO) {
			sent = 0;
			// check if this router is the destination
			if (ip_hdr->daddr == interface_ip.s_addr) {
				send_icmp(ip_hdr->saddr, ip_hdr->daddr, send_header->ether_dhost,
					send_header->ether_shost, ICMP_ECHOREPLY, 0, m.interface, icmp_hdr->un.echo.id,
					icmp_hdr->un.echo.sequence);
				sent = 1;
				break;
			}
			if (sent)
				continue;
		}

		// ICMP time limit excedeed
		if (ip_hdr->ttl <= 1) {
			send_icmp(ip_hdr->saddr, interface_ip.s_addr, send_header->ether_dhost,
				send_header->ether_shost, ICMP_TIME_EXCEEDED, 0, m.interface, 0, 0);
				continue;
			}

		// ICMP host unreach
		if (table_line == NULL) {
			send_icmp(ip_hdr->saddr, interface_ip.s_addr, send_header->ether_dhost,
				send_header->ether_shost, ICMP_DEST_UNREACH, 0, m.interface, 0, 0);
			continue;
		}

		ARP_line arp_line = arp_lookup(table_line->next_hop.s_addr, arp_table);
		/*
		 * if no ARP entry, send an ARP request and start buffering packets
		 * for this address
		 */
		if (arp_line == NULL) {
			arp_line = arp_insert(table_line->next_hop.s_addr, arp_table);
			eth_hdr.ether_type = htons(ETHERTYPE_ARP);
			inet_aton(get_interface_ip(table_line->interface), &interface_ip);
			memset(eth_hdr.ether_dhost, 0xff, 6);
			get_interface_mac(table_line->interface, eth_hdr.ether_shost);
			send_arp(table_line->next_hop.s_addr, interface_ip.s_addr, &eth_hdr, table_line->interface, htons(ARPOP_REQUEST));
		}
		// if we don't have the MAC yet, buffer this packet 
		if (arp_line->mac_set == 0) {
			buffer = (packet *) malloc(sizeof(packet));
			buffer->len = m.len;
			memcpy(buffer->payload, m.payload, m.len);
			queue_enq(arp_line->packets_queue, buffer);

			continue;
		}
		// if we have the next hop MAC, forward this packet
		else {
			send_header = (struct ether_header *) m.payload;
			inet_aton(get_interface_ip(table_line->interface), &interface_ip);
			memcpy(send_header->ether_dhost, arp_line->mac, 6);
			get_interface_mac(table_line->interface, send_header->ether_shost);

			ip_hdr->ttl = ip_hdr->ttl - 1;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

			send_packet(table_line->interface, &m);
		}
	}

	return 0;
}
