#pragma once
#include <cinttypes>
#include <string>
#include <vector>

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
	uint16_t	hardware_type;					// (Ethernet,etc)
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
	uint16_t	flags;         // Flags and fragment offset field
	uint8_t		ttl;           // Time to live
	uint8_t		protocol;      // Protocol(TCP,UDP,etc)
	uint16_t	checksum;      // IP checksum
	uint32_t	srcaddr;       // Source address
	uint32_t	destaddr;      // Source address
});

#define TCP_FLAGS_FIN       1 << 0
#define TCP_FLAGS_SYN       1 << 1
#define TCP_FLAGS_RST       1 << 2
#define TCP_FLAGS_PSH       1 << 3
#define TCP_FLAGS_ACK       1 << 4
#define TCP_FLAGS_URGENT    1 << 5
#define TCP_FLAGS_ECN       1 << 6
#define TCP_FLAGS_CWR       1 << 7

#define TCP_FLAGS_PSH_ACK	0x18

PACK(struct TcpHeader
{
	uint16_t	src_port;
	uint16_t	dest_port;
	uint32_t	sequence_number;
	uint32_t	ack_number;
	uint8_t		header_len;		// upper 4 bits times 4 is the length
	union
	{
		uint8_t		flags;
		struct {
			uint8_t		FIN			: 1;
			uint8_t		SYN			: 1;
			uint8_t		RST			: 1;
			uint8_t		PSH			: 1;
			uint8_t		ACK			: 1;
			uint8_t		URGENT		: 1;
			uint8_t		ECN			: 1;
			uint8_t		CWR			: 1;
		} flag_bits;
	};
	uint16_t	window;
	uint16_t	checksum;
	uint16_t	urgent_pointer;
	uint8_t		options[12];
});

PACK(struct PseudoTcpIpHeader
{
	uint32_t	ip_src;
	uint32_t	ip_dst;
	uint8_t		zero = 0;
	uint8_t		protocol = PROTOCOL_TCP;
	uint16_t	tcp_len;
	TcpHeader	tcph;
});

PACK(struct UdpHeader
{
	uint16_t	src_port;
	uint16_t	dest_port;
	uint16_t	length;
	uint16_t	checksum;
});

#define DNS_QUERY_CLASS_IN		1
#define DNS_QUERY_TYPE_IPV4		1
#define DNS_QUERY_TYPE_IPV6		28

PACK(struct DnsQuestion
{
	std::string qname; // 253 characters is the maximum length of a domain name (including dots)
	uint16_t    qtype;
	uint16_t    qclass;
});

PACK(struct DnsAnswer
{
	std::string name; // 253 characters is the maximum length of a domain name (including dots)
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

#define TLS_CIPHER_SUITE_RESERVED                       0xaaaa
#define TLS_AES_128_GCM_SHA256                          0x1301
#define TLS_AES_256_GCM_SHA384                          0x1302
#define TLS_CHACHA20_POLY1305_SHA256                    0x1303
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256         0xc02b
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256           0xc02f
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384         0xc02c
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384           0xc030
#define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256   0xcca9
#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256     0xcca8
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA              0xc013
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA              0xc014
#define TLS_RSA_WITH_AES_128_GCM_SHA256                 0x009c
#define TLS_RSA_WITH_AES_256_GCM_SHA384                 0x009d
#define TLS_RSA_WITH_AES_128_CBC_SHA                    0x002f
#define TLS_RSA_WITH_AES_256_CBC_SHA                    0x0035

PACK(struct TlsHandshake
{
	uint8_t		type;					// Handshake type i.e. Hello Client
	uint8_t		length[3];				// 3 byte length value
	uint16_t	version;				// TLS protocol version
	uint8_t		random[32];				// 32 byte random key field
	uint8_t		session_id_len;			// Length of the session ID
});

//
// Since TLS handshake's certain fields
// are of varying length from this point on,
// offsets need to be calculated dynamically.
//
namespace tls
{
	uint8_t*	get_session_id(TlsHandshake* handshake);
	uint16_t	get_cipher_suites_len(TlsHandshake* handshake);
	void		get_cipher_suites(TlsHandshake* handshake, std::vector<uint16_t>& cipher_suites);
	uint8_t		get_compression_methods_len(TlsHandshake* handshake);
	void		get_compression_methods(TlsHandshake* handshake, std::vector<uint8_t>& compression_methods);
	uint16_t	get_extensions_len(TlsHandshake* handshake);
	uint32_t	get_extension_reserved(TlsHandshake* handshake);
	TlsServerNameExtension* get_extension_server_name(TlsHandshake* handshake);
}

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

void craft_eth_header(
	uint8_t* packet,
	macaddr src_mac,
	macaddr dest_mac,
	uint16_t protocol
);

void craft_ip_header_for_portscan(
	uint8_t* packet,
	const char* src_ip,
	const char* dest_ip,
	uint8_t protocol
);

void craft_tcp_header_for_portscan(
	uint8_t* packet,
	uint16_t src_port,
	uint16_t dest_port,
	uint8_t	flags,
	uint32_t seq_number = 0,
	uint32_t ack_number = 0
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

bool has_arp_layer(uint8_t* packet);
bool has_ip_layer(uint8_t* packet);
bool has_tcp_layer(uint8_t* packet);
bool has_udp_layer(uint8_t* packet);
bool has_client_dns_layer(uint8_t* packet);
bool has_client_tls_layer(uint8_t* packet);

DnsQuestion extract_dns_query_question(DnsHeader* dns_header);
std::string extract_dns_query_qname(DnsHeader* dns_header);
std::string extract_tls_connection_server_name(TlsHandshake* tls_handshake);
