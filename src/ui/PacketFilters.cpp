#include "PacketFilters.h"
#include "imgui/imgui.h"
#include <WS2spi.h>

bool PacketFilterManager::filter_packet(uint8_t* packet, PacketFilterOptions* filters)
{
	// Check for Layer 5 filters (Session Layer) i.e. TLS, DNS, etc.
	//
	// TLS
	if (filters->tls_filter)
		if (has_client_tls_layer(packet))
			return true;

	// DNS
	if (filters->dns_filter)
		if (has_client_dns_layer(packet))
			return true;

	// Check for Layer 4 filters (Transport Layer) i.e. TCP, UDP, ICMP
	//
	// TCP
	if (filters->tcp_filter)
		if (has_tcp_layer(packet))
			return true;

	// UDP
	if (filters->udp_filter)
		if (has_udp_layer(packet))
			return true;

	// Check for Layer 2 (Data Link Layer) i.e. ARP
	//
	// ARP
	if (filters->arp_filter)
		if (has_arp_layer(packet))
			return true;

	// If no filters passed, don't capture the packet
	return false;
}

void TlsPacketRenderer::render_packet(uint8_t* packet)
{
	TlsHandshake* tls_handshake = get_tls_handshake(get_tls_header(packet));
	ImGui::Text("TLS Connection: ");
	ImGui::SameLine();
	ImGui::Text(extract_tls_connection_server_name(tls_handshake).c_str());
}

void DnsPacketRenderer::render_packet(uint8_t* packet)
{
	DnsHeader* dns_header = get_dns_header(packet);
	if (ntohs(dns_header->qdcount) == 1)
	{
		ImGui::Text("DNS Query: ");
		ImGui::SameLine();
		ImGui::Text(extract_dns_query_qname(dns_header).c_str());
	}
}

void TcpPacketRenderer::render_packet(uint8_t* packet)
{
	if (has_client_tls_layer(packet))
		return TlsPacketRenderer::render_packet(packet);

	TcpHeader* tcp_header = get_tcp_header(packet);
	ImGui::Text("TCP: %i --> %i", (int)ntohs(tcp_header->src_port), (int)ntohs(tcp_header->dest_port));
}

void UdpPacketRenderer::render_packet(uint8_t* packet)
{
	if (has_client_dns_layer(packet))
		return DnsPacketRenderer::render_packet(packet);

	UdpHeader* udp_header = get_udp_header(packet);
	ImGui::Text("UDP: %i --> %i", (int)ntohs(udp_header->src_port), (int)ntohs(udp_header->dest_port));
}

void ArpPacketRenderer::render_packet(uint8_t* packet)
{
	ArpPacket* arp_packet = reinterpret_cast<ArpPacket*>(packet);
	ImGui::Text("ARP %s", (ntohs(arp_packet->opcode) == ARP_REQUEST_OPCODE) ? "Request" : "Reply");
}

void MainPacketRenderer::render_packet(uint8_t* packet, PacketFilterOptions* filters)
{
	// Check if the packet is valid
	if (!packet) return;

	// Check for Layer 2 filters to pass
	//
	// ARP
	if (filters->arp_filter && has_arp_layer(packet))
		return ArpPacketRenderer::render_packet(packet);

	// Check for Layer 4 filters to pass
	//
	// TCP
	if (filters->tcp_filter && has_tcp_layer(packet))
		return TcpPacketRenderer::render_packet(packet);

	// UDP
	if (filters->udp_filter && has_udp_layer(packet))
		return UdpPacketRenderer::render_packet(packet);

	// Check for Layer 5 filters to pass
	//
	// TLS
	if (filters->tls_filter && has_client_tls_layer(packet))
		return TlsPacketRenderer::render_packet(packet);

	// DNS
	if (filters->dns_filter && has_client_dns_layer(packet))
		return DnsPacketRenderer::render_packet(packet);
}
