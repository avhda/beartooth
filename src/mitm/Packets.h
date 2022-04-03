#pragma once
#include <cinttypes>

#define MACADDR_LEN 6
#define IPADDR_LEN	4
#define MAX_PACKET_SIZE 65535

#define ARP_REQUEST_OPCODE	1
#define ARP_REPLY_OPCODE	2

#define PROTOCOL_IPV4		0x0800
#define PROTOCOL_ARP		0x0806

#define HARDWARE_TYPE_ETHERNET 1

typedef uint8_t macaddr[MACADDR_LEN];
typedef uint8_t ipaddr[IPADDR_LEN];

struct PacketHeader
{
	long		timeval_sec;    // seconds
	long		timeval_usec;   // microseconds
	uint32_t	caplen;			// length of portion present
	uint32_t	len;			// length of the packet
};

struct EthLayer
{
	macaddr		dest;
	macaddr		src;
	uint16_t	protocol;
};

struct ArpPacket
{
	EthLayer	eth_layer;
	uint16_t	hardware_type;					// Ethernet
	uint16_t	protocol;						// IPv4
	uint8_t		hrd_len;						// Hardware Length
	uint8_t		proto_len;						// Protocol Length
	uint16_t	opcode;							// ARP Request / ARP Reply
	macaddr		arp_sha;						// Sender MAC address
	ipaddr		arp_spa;						// Sender IPv4 address
	macaddr		arp_tha;						// Target MAC address
	ipaddr		arp_tpa;						// Target IPv4 address
};

void craft_arp_request_packet(
	ArpPacket* packet,
	macaddr source_mac,
	uint32_t source_ip,
	uint32_t target_ip
);

void craft_arp_reply_packet(
	ArpPacket* packet,
	macaddr source_mac,
	macaddr dest_mac,
	uint32_t source_ip,
	uint32_t dest_ip
);

void craft_arp_reply_packet(
	ArpPacket* packet,
	macaddr source_mac,
	macaddr dest_mac,
	const char* source_ip,
	const char* dest_ip
);
