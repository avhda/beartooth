#include "Packets.h"
#include <pcap/pcap.h>

constexpr unsigned char BROADCAST_ADDR[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#define TLS_HANDSHAKE_HELLO_CLIENT_KNOWN_FIELDS_SIZE 39

void craft_arp_request_packet(ArpPacket* packet, macaddr source_mac, uint32_t source_ip, uint32_t target_ip)
{
	// Ethernet Layer
	memcpy(packet->eth_layer.src,	source_mac,		MACADDR_LEN);
	memcpy(packet->eth_layer.dest,	BROADCAST_ADDR,	MACADDR_LEN);

	// ARP Header
	packet->eth_layer.protocol	= htons(PROTOCOL_ARP);
	packet->hardware_type		= htons(HARDWARE_TYPE_ETHERNET);
	packet->protocol			= htons(PROTOCOL_IPV4);
	packet->hrd_len				= MACADDR_LEN;
	packet->proto_len			= IPADDR_LEN;
	packet->opcode				= htons(ARP_REQUEST_OPCODE);
	
	// ARP Request Data
	memcpy(packet->arp_sha,		source_mac,			MACADDR_LEN);
	memset(packet->arp_tha,		0,					MACADDR_LEN);
	memcpy(packet->arp_spa,		&source_ip,			IPADDR_LEN);
	memcpy(packet->arp_tpa,		&target_ip,			IPADDR_LEN);
}

void craft_arp_reply_packet(ArpPacket* packet, macaddr source_mac, macaddr dest_mac, uint32_t source_ip, uint32_t dest_ip)
{
	// Ethernet Layer
	memcpy(packet->eth_layer.src, source_mac, MACADDR_LEN);
	memcpy(packet->eth_layer.dest, dest_mac, MACADDR_LEN);

	// ARP Header
	packet->eth_layer.protocol	= htons(PROTOCOL_ARP);
	packet->hardware_type		= htons(HARDWARE_TYPE_ETHERNET);
	packet->protocol			= htons(PROTOCOL_IPV4);
	packet->hrd_len				= MACADDR_LEN;
	packet->proto_len			= IPADDR_LEN;
	packet->opcode				= htons(ARP_REPLY_OPCODE);

	// ARP Reply Data
	memcpy(packet->arp_sha, source_mac, MACADDR_LEN);
	memcpy(packet->arp_tha, dest_mac,	MACADDR_LEN);
	memcpy(packet->arp_spa, &source_ip, IPADDR_LEN);
	memcpy(packet->arp_tpa, &dest_ip,	IPADDR_LEN);
}

void craft_arp_reply_packet(ArpPacket* packet, macaddr source_mac, macaddr dest_mac, const char* source_ip, const char* dest_ip)
{
	uint32_t src_ip = inet_addr(source_ip);
	uint32_t dst_ip = inet_addr(dest_ip);

	craft_arp_reply_packet(packet, source_mac, dest_mac, src_ip, dst_ip);
}

void craft_eth_header(uint8_t* packet, macaddr src_mac, macaddr dest_mac, int protocol)
{
	EthHeader* eth_header = get_eth_header(packet);

	// Ethernet Layer
	memcpy(eth_header->src, src_mac, MACADDR_LEN);
	memcpy(eth_header->dest, dest_mac, MACADDR_LEN);
	eth_header->protocol = htons(static_cast<uint16_t>(protocol));
}

void craft_ip_header(uint8_t* packet, const char* src_ip, const char* dest_ip)
{
}


EthHeader* get_eth_header(uint8_t* packet)
{
	return reinterpret_cast<EthHeader*>(packet);
}

IpHeader* get_ip_header(uint8_t* packet)
{
	return reinterpret_cast<IpHeader*>(packet + sizeof(EthHeader));
}

TcpHeader* get_tcp_header(uint8_t* packet)
{
	return reinterpret_cast<TcpHeader*>(packet + sizeof(EthHeader) + sizeof(IpHeader));
}

UdpHeader* get_udp_header(uint8_t* packet)
{
	return reinterpret_cast<UdpHeader*>(packet + sizeof(EthHeader) + sizeof(IpHeader));
}

DnsHeader* get_dns_header(uint8_t* packet)
{
	return reinterpret_cast<DnsHeader*>(packet + sizeof(EthHeader) + sizeof(IpHeader) + sizeof(UdpHeader));
}

TlsHeader* get_tls_header(uint8_t* packet)
{
	TcpHeader* tcp_header = get_tcp_header(packet);
	int header_len = ((int)(tcp_header->header_len >> 4)) * 4;
	return reinterpret_cast<TlsHeader*>(packet + sizeof(EthHeader) + sizeof(IpHeader) + header_len);
}

TlsHandshake* get_tls_handshake(TlsHeader* tls_header)
{
	return reinterpret_cast<TlsHandshake*>((uint8_t*)tls_header + sizeof(TlsHeader));
}

bool has_arp_layer(uint8_t* packet)
{
	EthHeader* eth_header = get_eth_header(packet);
	return (ntohs(eth_header->protocol) == PROTOCOL_ARP);
}

bool has_ip_layer(uint8_t* packet)
{
	EthHeader* eth_header = get_eth_header(packet);
	return (ntohs(eth_header->protocol) == PROTOCOL_IPV4);
}

bool has_tcp_layer(uint8_t* packet)
{
	if (!has_ip_layer(packet))
		return false;

	IpHeader* ip_header = get_ip_header(packet);
	return ip_header->protocol == PROTOCOL_TCP;
}

bool has_udp_layer(uint8_t* packet)
{
	if (!has_ip_layer(packet))
		return false;

	IpHeader* ip_header = get_ip_header(packet);
	return ip_header->protocol == PROTOCOL_UDP;
}

bool has_client_dns_layer(uint8_t* packet)
{
	if (!has_udp_layer(packet))
		return false;

	UdpHeader* udp_header = get_udp_header(packet);
	return (ntohs(udp_header->dest_port) == PORT_DNS);
}

bool has_client_tls_layer(uint8_t* packet)
{
	if (!has_tcp_layer(packet))
		return false;

	TcpHeader* tcp_header = get_tcp_header(packet);
	if (ntohs(tcp_header->dest_port) != PORT_TLS)
		return false;

	if (tcp_header->flags != TCP_FLAGS_PSH_ACK)
		return false;

	TlsHeader* tls_header = get_tls_header(packet);
	if (tls_header->content_type != TLS_CONTENT_TYPE_HANDSHAKE)
		return false;

	TlsHandshake* tls_handshake = get_tls_handshake(tls_header);
	if (tls_handshake->type != TLS_HANDSHAKE_TYPE_HELLO_CLIENT)
		return false;

	return true;
}

namespace tls
{
	uint8_t* get_session_id(TlsHandshake* handshake)
	{
		// ptr = handshake->session_id
		uint8_t* ptr = (uint8_t*)handshake + TLS_HANDSHAKE_HELLO_CLIENT_KNOWN_FIELDS_SIZE;

		return ptr;
	}

	uint16_t get_cipher_suites_len(TlsHandshake* handshake)
	{
		// ptr = handshake->session_id
		uint8_t* ptr = (uint8_t*)handshake + TLS_HANDSHAKE_HELLO_CLIENT_KNOWN_FIELDS_SIZE;

		// Get the session id length
		uint8_t session_id_len = handshake->session_id_len;

		// ptr = handshake->cipher_suites_len
		ptr += session_id_len;

		// Get the number of cipher suites
		uint16_t cipher_suites_len = ntohs(*reinterpret_cast<uint16_t*>(ptr));

		return cipher_suites_len;
	}

	void get_cipher_suites(TlsHandshake* handshake, std::vector<uint16_t>& cipher_suites)
	{
		// ptr = handshake->session_id
		uint8_t* ptr = (uint8_t*)handshake + TLS_HANDSHAKE_HELLO_CLIENT_KNOWN_FIELDS_SIZE;

		// Get the session id length
		uint8_t session_id_len = handshake->session_id_len;

		// ptr = handshake->cipher_suites_len
		ptr += session_id_len;

		// Get the number of cipher suites
		uint16_t cipher_suites_len = ntohs(*reinterpret_cast<uint16_t*>(ptr));

		// ptr = handshake->cipher_suites
		ptr += sizeof(uint16_t);

		// Copy the cipher suites to the output buffer
		for (uint16_t i = 0; i < cipher_suites_len / sizeof(uint16_t); ++i)
		{
			uint16_t cipher_suite = ntohs(*reinterpret_cast<uint16_t*>(ptr));
			cipher_suites.push_back(cipher_suite);

			// advance the pointer to the next element
			ptr += sizeof(uint16_t);
		}
	}

	uint8_t get_compression_methods_len(TlsHandshake* handshake)
	{
		// ptr = handshake->session_id
		uint8_t* ptr = (uint8_t*)handshake + TLS_HANDSHAKE_HELLO_CLIENT_KNOWN_FIELDS_SIZE;

		// Get the session id length
		uint8_t session_id_len = handshake->session_id_len;

		// ptr = handshake->cipher_suites_len
		ptr += session_id_len;

		// Get the number of cipher suites
		uint16_t cipher_suites_len = ntohs(*reinterpret_cast<uint16_t*>(ptr));

		// ptr = handshake->cipher_suites
		ptr += sizeof(uint16_t);

		// ptr = handshake->compression_methods_len
		ptr += cipher_suites_len;

		// Get the number of compression methods
		uint8_t compression_methods_len = *ptr;

		return compression_methods_len;
	}

	void get_compression_methods(TlsHandshake* handshake, std::vector<uint8_t>& compression_methods)
	{
		// ptr = handshake->session_id
		uint8_t* ptr = (uint8_t*)handshake + TLS_HANDSHAKE_HELLO_CLIENT_KNOWN_FIELDS_SIZE;

		// Get the session id length
		uint8_t session_id_len = handshake->session_id_len;

		// ptr = handshake->cipher_suites_len
		ptr += session_id_len;

		// Get the number of cipher suites
		uint16_t cipher_suites_len = ntohs(*reinterpret_cast<uint16_t*>(ptr));

		// ptr = handshake->cipher_suites
		ptr += sizeof(uint16_t);

		// ptr = handshake->compression_methods_len
		ptr += cipher_suites_len;

		// Get the number of compression methods
		uint8_t compression_methods_len = *ptr;

		// ptr = handshake->compression_methods
		ptr += sizeof(uint8_t);

		// Copy the compression methods to the output buffer
		for (uint8_t i = 0; i < compression_methods_len; ++i)
		{
			compression_methods.push_back(*ptr);

			// advance the pointer to the next element
			ptr += sizeof(uint8_t);
		}
	}

	uint16_t get_extensions_len(TlsHandshake* handshake)
	{
		// ptr = handshake->session_id
		uint8_t* ptr = (uint8_t*)handshake + TLS_HANDSHAKE_HELLO_CLIENT_KNOWN_FIELDS_SIZE;

		// Get the session id length
		uint8_t session_id_len = handshake->session_id_len;

		// ptr = handshake->cipher_suites_len
		ptr += session_id_len;

		// Get the number of cipher suites
		uint16_t cipher_suites_len = ntohs(*reinterpret_cast<uint16_t*>(ptr));

		// ptr = handshake->cipher_suites
		ptr += sizeof(uint16_t);

		// ptr = handshake->compression_methods_len
		ptr += cipher_suites_len;

		// Get the number of compression methods
		uint8_t compression_methods_len = *ptr;

		// ptr = handshake->compression_methods
		ptr += sizeof(uint8_t);

		// ptr = handshake->extensions_len
		ptr += compression_methods_len;

		// Get number of extensions
		uint16_t extensions_len = ntohs(*reinterpret_cast<uint16_t*>(ptr));

		return extensions_len;
	}

	uint32_t get_extension_reserved(TlsHandshake* handshake)
	{
		// ptr = handshake->session_id
		uint8_t* ptr = (uint8_t*)handshake + TLS_HANDSHAKE_HELLO_CLIENT_KNOWN_FIELDS_SIZE;

		// Get the session id length
		uint8_t session_id_len = handshake->session_id_len;

		// ptr = handshake->cipher_suites_len
		ptr += session_id_len;

		// Get the number of cipher suites
		uint16_t cipher_suites_len = ntohs(*reinterpret_cast<uint16_t*>(ptr));

		// ptr = handshake->cipher_suites
		ptr += sizeof(uint16_t);

		// ptr = handshake->compression_methods_len
		ptr += cipher_suites_len;

		// Get the number of compression methods
		uint8_t compression_methods_len = *ptr;

		// ptr = handshake->compression_methods
		ptr += sizeof(uint8_t);

		// ptr = handshake->extensions_len
		ptr += compression_methods_len;

		// ptr = handshake->extension_reserved
		ptr += sizeof(uint16_t);

		// Get reserved extension
		uint32_t extension_reserved = *reinterpret_cast<uint32_t*>(ptr);

		return extension_reserved;
	}

	TlsServerNameExtension* get_extension_server_name(TlsHandshake* handshake)
	{
		// ptr = handshake->session_id
		uint8_t* ptr = (uint8_t*)handshake + TLS_HANDSHAKE_HELLO_CLIENT_KNOWN_FIELDS_SIZE;

		// Get the session id length
		uint8_t session_id_len = handshake->session_id_len;

		// ptr = handshake->cipher_suites_len
		ptr += session_id_len;

		// Get the number of cipher suites
		uint16_t cipher_suites_len = ntohs(*reinterpret_cast<uint16_t*>(ptr));

		// ptr = handshake->cipher_suites
		ptr += sizeof(uint16_t);

		// ptr = handshake->compression_methods_len
		ptr += cipher_suites_len;

		// Get the number of compression methods
		uint8_t compression_methods_len = *ptr;

		// ptr = handshake->compression_methods
		ptr += sizeof(uint8_t);

		// ptr = handshake->extensions_len
		ptr += compression_methods_len;

		// ptr = handshake->extension_reserved
		ptr += sizeof(uint16_t);

		// ptr = handshake->extension_server_name
		ptr += sizeof(uint32_t);

		return reinterpret_cast<TlsServerNameExtension*>(ptr);
	}
}

DnsQuestion extract_dns_query_question(DnsHeader* dns_header)
{
	DnsQuestion question;
	question.qname = extract_dns_query_qname(dns_header);

	char* type_address = (((char*)dns_header + sizeof(DnsHeader)) + question.qname.size() + 2);
	char* class_address = type_address + 2;

	question.qtype = ntohs(*((uint16_t*)type_address));
	question.qclass = ntohs(*((uint16_t*)class_address));

	return question;
}

std::string extract_dns_query_qname(DnsHeader* dns_header)
{
	std::string result;

	char* data = ((char*)dns_header + sizeof(DnsHeader));
	int section_size = (int)*data;
	++data;
	
	while (section_size != 0)
	{
		// Read the specified number of bytes as characters before the dot
		for (int i = 0; i < section_size; ++i, ++data)
			result += *data;

		section_size = (int)*data;

		// Add a dot at the end if there is more sections to read
		if (section_size != 0)
		{
			result += '.';
			++data;
		}
	}

	return result;
}

std::string extract_tls_connection_server_name(TlsHandshake* tls_handshake)
{
	TlsServerNameExtension* extension_server_name = tls::get_extension_server_name(tls_handshake);

	return std::string(
		(const char*)extension_server_name->server_name,
		(size_t)extension_server_name->server_name_len
	);
}
