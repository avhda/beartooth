#pragma once
#include <functional>
#include <vector>
#include <mitm/Packets.h>

#define PACKET_ID_COLUMN_OFFSET				18.0f
#define PACKET_TIME_COLUMN_OFFSET			PACKET_ID_COLUMN_OFFSET				+ 70.0f
#define PACKET_PROTOCOL_COLUMN_OFFSET		PACKET_TIME_COLUMN_OFFSET			+ 120.0f
#define PACKET_SOURCE_COLUMN_OFFSET			PACKET_PROTOCOL_COLUMN_OFFSET		+ 150.0f
#define PACKET_DESTINATION_COLUMN_OFFSET	PACKET_SOURCE_COLUMN_OFFSET			+ 200.0f
#define PACKET_INFO_COLUMN_OFFSET			PACKET_DESTINATION_COLUMN_OFFSET	+ 200.0f

using GenericPacketRef = std::shared_ptr<GenericPacket>;

struct PacketNode
{
	PacketHeader header = {};
	GenericPacketRef packet_ref;
	uint64_t packet_id = 0;
	float timestamp = 0;
};

struct PacketFilterOptions
{
	bool arp_filter = true;
	bool tcp_filter = true;
	bool udp_filter = true;
	bool dns_filter = true;
	bool tls_filter = true;
};

class PacketFilterManager
{
public:
	static bool filter_packet(uint8_t* packet, PacketFilterOptions* filters);
};

class TlsPacketRenderer
{
public:
	static void render_packet_selection_header(PacketNode& node);
	static void render_packet_inspection_tree(uint8_t* packet);
};

class DnsPacketRenderer
{
public:
	static void render_packet_selection_header(PacketNode& node);
	static void render_packet_inspection_tree(uint8_t* packet);
};

class TcpPacketRenderer
{
public:
	static void render_packet_selection_header(PacketNode& node);
	static void render_packet_inspection_tree(uint8_t* packet);
};

class UdpPacketRenderer
{
public:
	static void render_packet_selection_header(PacketNode& node);
	static void render_packet_inspection_tree(uint8_t* packet);
};

class IpPacketRenderer
{
public:
	static void render_packet_inspection_tree(uint8_t* packet);
};

class ArpPacketRenderer
{
public:
	static void render_packet_selection_header(PacketNode& node);
	static void render_packet_inspection_tree(uint8_t* packet);
};

class MainPacketRenderer
{
public:
	static void render_packet_selection_header(PacketNode& node, PacketFilterOptions* filters);
	static void render_packet_inspection_tree(uint8_t* packet);
};
