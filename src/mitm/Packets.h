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
#define PROTOCOL_TCP		0x0006
#define PROTOCOL_UDP		0x0011

#define PORT_DNS			53
#define PORT_TLS			443

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

struct EthHeader
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
	EthHeader	eth_layer;
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

PACK(struct IpHeader
{
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

#define TCP_FLAGS_PSH_ACK	0x18

PACK(struct TcpHeader
{
	uint16_t	src_port;
	uint16_t	dest_port;
	uint32_t	sequence_number;
	uint32_t	ack_number;
	uint8_t		header_len;
	uint8_t		flags;
	uint16_t	window;
	uint16_t	checksum;
	uint16_t	urgent_pointer;
	uint8_t		options[12];
});

PACK(struct UdpHeader
{
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

PACK(struct DnsHeader
{
	uint16_t    id;
	uint16_t    flags;
	uint16_t    qdcount;
	uint16_t    ancount;
	uint16_t    nscount;
	uint16_t    arcount;
	DnsQuestion qd;
	DnsAnswer   an;
});

PACK(struct TlsServerNameExtension
{
	uint16_t	type;
	uint16_t	length;
	uint16_t	server_name_list_len;
	uint8_t		server_name_type;
	uint16_t	server_name_len;
	char* server_name[256];
});

#define TLS_CONTENT_TYPE_HANDSHAKE 22

PACK(struct TlsHeader
{
	uint8_t		content_type;
	uint16_t	version;
	uint16_t	length;
});

#define TLS_HANDSHAKE_TYPE_HELLO_CLIENT 1

PACK(struct TlsHandshake
{
	uint8_t		type;					// Handshake type i.e. Hello Client
	uint8_t		length[3];				// 3 byte length value
	uint16_t	version;				// TLS protocol version
	uint8_t		random[32];				// 32 byte random key field
	uint8_t		session_id_len;			// Length of the session ID (usually 32 bytes)
	uint8_t		session_id[32];			// Session ID
	uint16_t	cipher_suites_len;		// Length of the section with encryption algos
	uint8_t		cipher_suites[32];		// Most common case: 16 suites (32 bytes)
	uint8_t		compression_method_len;	// Number of compression methods
	uint8_t		compression_method;		// Most common case: no compression (null)
	uint16_t	extensions_len;			// Length of the extensions segment
	uint32_t	extension_reserved;		// Reserved extension
	TlsServerNameExtension extension_server_name;
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

EthHeader*	get_eth_header(uint8_t* packet);
IpHeader*	get_ip_header(uint8_t* packet);
TcpHeader*	get_tcp_header(uint8_t* packet);
UdpHeader*	get_udp_header(uint8_t* packet);
DnsHeader*	get_dns_header(uint8_t* packet);

// Since TCP packet can have an optional 12 byte "options" field,
// the offset of the TLS packet header can vary depending on the TCP packet's size.
TlsHeader* get_tls_header(uint8_t* packet);

TlsHandshake* get_tls_handshake(TlsHeader* tls_header);

bool has_client_dns_layer(uint8_t* packet);
bool has_client_tls_layer(uint8_t* packet);

std::string extract_dns_query_qname(DnsHeader* dns_header);
std::string extract_tls_connection_server_name(TlsHandshake* tls_handshake);
