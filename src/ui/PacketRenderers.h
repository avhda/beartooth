#pragma once
#include <functional>
#include <vector>
#include <mitm/Packets.h>

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
	static void render_packet_selection_header(uint8_t* packet);
	static void render_packet_inspection_tree(uint8_t* packet);
};

class DnsPacketRenderer
{
public:
	static void render_packet_selection_header(uint8_t* packet);
	static void render_packet_inspection_tree(uint8_t* packet);
};

class TcpPacketRenderer
{
public:
	static void render_packet_selection_header(uint8_t* packet);
	static void render_packet_inspection_tree(uint8_t* packet);
};

class UdpPacketRenderer
{
public:
	static void render_packet_selection_header(uint8_t* packet);
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
	static void render_packet_selection_header(uint8_t* packet);
	static void render_packet_inspection_tree(uint8_t* packet);
};

class MainPacketRenderer
{
public:
	static void render_packet_selection_header(uint8_t* packet, PacketFilterOptions* filters);
	static void render_packet_inspection_tree(uint8_t* packet);
};
