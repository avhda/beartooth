#include "Packets.h"
#include <pcap/pcap.h>

constexpr unsigned char BROADCAST_ADDR[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

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
