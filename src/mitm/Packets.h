#pragma once
#include <cinttypes>
#include <string>

#ifdef _MSC_VER
#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))
#endif

#define MACADDR_LEN 6
#define IPADDR_LEN	4
#define MAX_PACKET_SIZE 65535

#define ARP_REQUEST_OPCODE	1
#define ARP_REPLY_OPCODE	2

#define PROTOCOL_IPV4		0x0800
#define PROTOCOL_ARP		0x0806
#define PROTOCOL_UDP		0x0011

#define PORT_DNS			53

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

struct GenericPacket
{
	uint8_t buffer[MAX_PACKET_SIZE];
};

PACK(struct ArpPacket
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
});

PACK(struct IpLayer
{
	EthLayer	eth_layer;	   // Ethernet frame
	uint8_t		ip_verlen;     // 4-bit IPv4 version
							   // 4-bit header length (in 32-bit words)
	uint8_t		tos;           // IP type of service
	uint16_t	totallength;   // Total length
	uint16_t	id;            // Unique identifier 
	uint16_t	offset;        // Fragment offset field
	uint8_t		ttl;           // Time to live
	uint8_t		protocol;      // Protocol(TCP,UDP etc)
	uint16_t	checksum;      // IP checksum
	uint32_t	srcaddr;       // Source address
	uint32_t	destaddr;      // Source address
});

PACK(struct TcpLayer
{
	IpLayer		ip_layer;
	uint16_t	src_port;
	uint16_t	dest_port;
});

PACK(struct UdpLayer
{
	IpLayer		ip_layer;
	uint16_t	src_port;
	uint16_t	dest_port;
	uint16_t	length;
	uint16_t	checksum;
});

PACK(struct DnsQuestion
{
	char        qname[254]; // 253 characters is the maximum length of a domain name (including dots)
	uint16_t    qtype;
	uint16_t    qclass;
});

PACK(struct DnsAnswer
{
	char        name[254]; // 253 characters is the maximum length of a domain name (including dots)
	uint16_t    type;
	uint16_t    dnsclass;
	uint32_t    tts;
	uint16_t    length;
	void* data;
});

PACK(struct DnsLayer
{
	UdpLayer	udp_layer;
	uint16_t    id;
	uint16_t    flags;
	uint16_t    qdcount;
	uint16_t    ancount;
	uint16_t    nscount;
	uint16_t    arcount;
	DnsQuestion qd;
	DnsAnswer   an;
});

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

std::string extract_dns_query_qname(DnsLayer* packet);
