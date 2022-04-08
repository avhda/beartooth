#include "PacketRenderers.h"
#include "imgui/imgui.h"
#include <WS2spi.h>
#include <map>
#include <algorithm>

static std::string convert_ip_to_string(uint32_t ip)
{
	struct sockaddr_in sa;
	memcpy(&sa.sin_addr, &ip, sizeof(uint32_t));

	return std::string(inet_ntoa(sa.sin_addr));
}

static std::string binary_to_hex_string(
	const uint8_t* inBinaryData,
	size_t inBinaryDataLength
)
{
	static const char* hexDigits = "0123456789ABCDEF";

	// Create a string and give a hint to its final size (twice the size
	// of the input binary data)
	std::string hexString;
	hexString.reserve(inBinaryDataLength * 2);

	// Run through the binary data and convert to a hex string
	std::for_each(
		inBinaryData,
		inBinaryData + inBinaryDataLength,
		[&hexString](uint8_t inputByte) {
			hexString.push_back(hexDigits[inputByte >> 4]);
			hexString.push_back(hexDigits[inputByte & 0x0F]);
		});

	return hexString;
}

static void render_inspector_tree_node_field(
	const char* title,
	uint32_t value,
	bool value_is_hex,
	int value_indent,
	const std::map<int, std::string>& clarifications = {}
)
{
	ImGui::Text(title);
	ImGui::SameLine(); ImGui::SetCursorPosX((float)value_indent);

	if (value_is_hex)
		ImGui::Text("0x%x ", value);
	else
		ImGui::Text("%u ", value);

	for (auto& [clarify_val, msg] : clarifications)
	{
		if (value == clarify_val)
		{
			ImGui::SameLine();
			ImGui::Text(msg.c_str());
			break;
		}
	}
}

bool PacketFilterManager::filter_packet(uint8_t* packet, PacketFilterOptions* filters)
{
	// Check if packet is valid
	if (!packet) return false;

	// Higher layer filters i.e. TLS, DNS, etc.
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

void TlsPacketRenderer::render_packet_selection_header(uint8_t* packet)
{
	TlsHandshake* tls_handshake = get_tls_handshake(get_tls_header(packet));
	ImGui::Text("TLS Connection: ");
	ImGui::SameLine();
	ImGui::Text(extract_tls_connection_server_name(tls_handshake).c_str());
}

void TlsPacketRenderer::render_packet_inspection_tree(uint8_t* packet)
{
	TlsHeader* tls_header = get_tls_header(packet);
	if (ImGui::TreeNode("Transport Layer Security"))
	{
		int value_indent = 160;

		render_inspector_tree_node_field(
			"Content Type: ",
			(uint32_t)tls_header->content_type,
			false,
			value_indent,
			{ { TLS_CONTENT_TYPE_HANDSHAKE, "(Handshake)" } }
		);

		render_inspector_tree_node_field(
			"Version: ",
			(uint32_t)ntohs(tls_header->version),
			true,
			value_indent
		);

		render_inspector_tree_node_field(
			"Length: ",
			(uint32_t)ntohs(tls_header->length),
			false,
			value_indent
		);

		ImGui::Spacing();

		// If the content type is a handshake,
		// then render the handshake info.
		if (tls_header->content_type == TLS_CONTENT_TYPE_HANDSHAKE)
		{
			int value_indent_handshake = 200;

			TlsHandshake* tls_handshake = get_tls_handshake(tls_header);
			if (ImGui::TreeNode("TLS Handshake"))
			{
				render_inspector_tree_node_field(
					"Type: ",
					(uint32_t)tls_handshake->type,
					false,
					value_indent_handshake,
					{ { TLS_HANDSHAKE_TYPE_HELLO_CLIENT, "(Hello client)" } }
				);

				render_inspector_tree_node_field(
					"Version: ",
					(uint32_t)ntohs(tls_handshake->version),
					true,
					value_indent_handshake
				);

				ImGui::Text("%s", "Random (key): ");
				ImGui::SameLine(); ImGui::SetCursorPosX((float)value_indent_handshake);
				ImGui::Text("%s", binary_to_hex_string(tls_handshake->random, sizeof(tls_handshake->random)).c_str());

				render_inspector_tree_node_field(
					"Session ID Length: ",
					(uint32_t)tls_handshake->session_id_len,
					false,
					value_indent_handshake
				);

				ImGui::Text("%s", "Session ID: ");
				ImGui::SameLine(); ImGui::SetCursorPosX((float)value_indent_handshake);
				ImGui::Text("%s", binary_to_hex_string(tls::get_session_id(tls_handshake), tls_handshake->session_id_len).c_str());

				auto cipher_suites_length = tls::get_cipher_suites_len(tls_handshake);
				render_inspector_tree_node_field(
					"Cipher Suites Length: ",
					(uint32_t)cipher_suites_length,
					false,
					value_indent_handshake
				);

				uint32_t cipher_suites_count = cipher_suites_length / 2;
				if (ImGui::TreeNode(("Cipher Suites (" + std::to_string(cipher_suites_count) + " suites):").c_str()))
				{
					int value_indent_cipher_suite = 170;

					std::vector<uint16_t> cipher_suites;
					tls::get_cipher_suites(tls_handshake, cipher_suites);

					for (auto& suite : cipher_suites)
					{
						render_inspector_tree_node_field(
							"Cipher Suite: ",
							(uint32_t)suite,
							true,
							value_indent_cipher_suite,
							{
								{ TLS_CIPHER_SUITE_RESERVED,                    "(TLS_CIPHER_SUITE_RESERVED)"                       },
								{ TLS_AES_128_GCM_SHA256,                       "(TLS_AES_128_GCM_SHA256)"                          },
								{ TLS_AES_256_GCM_SHA384,                       "(TLS_AES_256_GCM_SHA384)"                          },
								{ TLS_CHACHA20_POLY1305_SHA256,                 "(TLS_CHACHA20_POLY1305_SHA256)"                    },
								{ TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,      "(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)"         },
								{ TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,        "(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)"           },
								{ TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,      "(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)"         },
								{ TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,        "(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)"           },
								{ TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,"(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)"   },
								{ TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,  "(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)"     },
								{ TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,           "(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)"              },
								{ TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,           "(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)"              },
								{ TLS_RSA_WITH_AES_128_GCM_SHA256,              "(TLS_RSA_WITH_AES_128_GCM_SHA256)"                 },
								{ TLS_RSA_WITH_AES_256_GCM_SHA384,              "(TLS_RSA_WITH_AES_256_GCM_SHA384)"                 },
								{ TLS_RSA_WITH_AES_128_CBC_SHA,                 "(TLS_RSA_WITH_AES_128_CBC_SHA)"                    },
								{ TLS_RSA_WITH_AES_256_CBC_SHA,                 "(TLS_RSA_WITH_AES_256_CBC_SHA)"                    },
							}
						);
					}

					ImGui::TreePop();
					ImGui::Spacing();
				}

				auto compression_methods = tls::get_compression_methods_len(tls_handshake);
				render_inspector_tree_node_field(
					"Compression Methods: ",
					(uint32_t)compression_methods,
					false,
					value_indent_handshake
				);

				if (ImGui::TreeNode("Compression Methods:"))
				{
					int value_indent_compression_method = 220;

					std::vector<uint8_t> compression_methods;
					tls::get_compression_methods(tls_handshake, compression_methods);

					for (auto& method : compression_methods)
					{
						render_inspector_tree_node_field(
							"Method: ",
							(uint32_t)method,
							true,
							value_indent_compression_method,
							{ { 0, "(null)" } }
						);
					}

					ImGui::TreePop();
					ImGui::Spacing();
				}

				render_inspector_tree_node_field(
					"Extensions: ",
					(uint32_t)tls::get_extensions_len(tls_handshake),
					false,
					value_indent_handshake
				);

				// Display the server name extension
				if (ImGui::TreeNode("Server Name Extension"))
				{
					int extension_indent_handshake = 220;
					TlsServerNameExtension* extension_server_name = tls::get_extension_server_name(tls_handshake);

					render_inspector_tree_node_field(
						"Type: ",
						(uint32_t)ntohs(extension_server_name->type),
						false,
						extension_indent_handshake
					);

					render_inspector_tree_node_field(
						"Length: ",
						(uint32_t)ntohs(extension_server_name->length),
						false,
						extension_indent_handshake
					);

					render_inspector_tree_node_field(
						"Name List Length: ",
						(uint32_t)ntohs(extension_server_name->server_name_list_len),
						false,
						extension_indent_handshake
					);

					render_inspector_tree_node_field(
						"Server Name Type: ",
						(uint32_t)extension_server_name->server_name_type,
						false,
						extension_indent_handshake
					);

					render_inspector_tree_node_field(
						"Server Name Length: ",
						(uint32_t)ntohs(extension_server_name->server_name_len),
						false,
						extension_indent_handshake
					);

					ImGui::Text("Server Name: ");
					ImGui::SameLine(); ImGui::SetCursorPosX((float)extension_indent_handshake);
					ImGui::Text("%s", extract_tls_connection_server_name(tls_handshake).c_str());

					ImGui::TreePop();
					ImGui::Spacing();
				}

				ImGui::TreePop();
				ImGui::Spacing();
			}
		}

		ImGui::TreePop();
		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();
	}
}

void DnsPacketRenderer::render_packet_selection_header(uint8_t* packet)
{
	DnsHeader* dns_header = get_dns_header(packet);
	if (ntohs(dns_header->qdcount) == 1)
	{
		ImGui::Text("DNS Query: ");
		ImGui::SameLine();
		ImGui::Text(extract_dns_query_qname(dns_header).c_str());
	}
}

void DnsPacketRenderer::render_packet_inspection_tree(uint8_t* packet)
{
	DnsHeader* dns_header = get_dns_header(packet);
	if (ImGui::TreeNode("Domain Name System"))
	{
		int value_indent = 170;

		render_inspector_tree_node_field(
			"ID: ",
			(uint32_t)ntohs(dns_header->id),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Flags: ",
			(uint32_t)ntohs(dns_header->flags),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Questions: ",
			(uint32_t)ntohs(dns_header->qdcount),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Answers: ",
			(uint32_t)ntohs(dns_header->ancount),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Authority Answers: ",
			(uint32_t)ntohs(dns_header->nscount),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Additional Answers: ",
			(uint32_t)ntohs(dns_header->arcount),
			false,
			value_indent
		);

		ImGui::Spacing();

		// If there were DNS questions,
		// render aseparate "queries" tree node.
		if (dns_header->qdcount > 0)
		{
			DnsQuestion qd = extract_dns_query_question(dns_header);

			if (ImGui::TreeNode("Queries"))
			{
				render_inspector_tree_node_field(
					"Type: ",
					(uint32_t)qd.qtype,
					false,
					190,
					{ { DNS_QUERY_TYPE_IPV4, "A  (IPv4)" }, { DNS_QUERY_TYPE_IPV6, "AAAA  (IPv6)" } }
				);

				render_inspector_tree_node_field(
					"Class: ",
					(uint32_t)qd.qclass,
					false,
					190,
					{ { DNS_QUERY_CLASS_IN, "(In)" } }
				);

				ImGui::Text("Name: ");
				ImGui::SameLine(); ImGui::SetCursorPosX(190);
				ImGui::Text("%s", qd.qname.c_str());

				ImGui::TreePop();
				ImGui::Spacing();
			}
		}

		ImGui::TreePop();
		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();
	}
}

void TcpPacketRenderer::render_packet_selection_header(uint8_t* packet)
{
	if (has_client_tls_layer(packet))
		return TlsPacketRenderer::render_packet_selection_header(packet);

	TcpHeader* tcp_header = get_tcp_header(packet);
	ImGui::Text("TCP: %i --> %i", (int)ntohs(tcp_header->src_port), (int)ntohs(tcp_header->dest_port));
}

void TcpPacketRenderer::render_packet_inspection_tree(uint8_t* packet)
{
	TcpHeader* tcp_header = get_tcp_header(packet);
	if (ImGui::TreeNode("Transmission Control Protocol"))
	{
		int value_indent = 164;

		render_inspector_tree_node_field(
			"Source Port: ",
			(uint32_t)ntohs(tcp_header->src_port),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Destination Port: ",
			(uint32_t)ntohs(tcp_header->dest_port),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Sequence Number: ",
			(uint32_t)tcp_header->sequence_number,
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"ACK: ",
			(uint32_t)tcp_header->ack_number,
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Header Length: ",
			(uint32_t)((int)(tcp_header->header_len >> 4)) * 4,
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Flags: ",
			(uint32_t)tcp_header->flags,
			true,
			value_indent,
			{ { TCP_FLAGS_PSH_ACK, "(PSH ACK)" } }
		);

		render_inspector_tree_node_field(
			"Window: ",
			(uint32_t)ntohs(tcp_header->window),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Checksum: ",
			(uint32_t)ntohs(tcp_header->checksum),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Urgent Pointer: ",
			(uint32_t)ntohs(tcp_header->urgent_pointer),
			false,
			value_indent
		);

		ImGui::TreePop();
		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();
	}

	if (has_client_tls_layer(packet))
		return TlsPacketRenderer::render_packet_inspection_tree(packet);
}

void UdpPacketRenderer::render_packet_selection_header(uint8_t* packet)
{
	if (has_client_dns_layer(packet))
		return DnsPacketRenderer::render_packet_selection_header(packet);

	UdpHeader* udp_header = get_udp_header(packet);
	ImGui::Text("UDP: %i --> %i", (int)ntohs(udp_header->src_port), (int)ntohs(udp_header->dest_port));
}

void UdpPacketRenderer::render_packet_inspection_tree(uint8_t* packet)
{
	UdpHeader* udp_header = get_udp_header(packet);
	if (ImGui::TreeNode("User Datagram Protocol"))
	{
		int value_indent = 150;

		render_inspector_tree_node_field(
			"Source Port: ",
			(uint32_t)ntohs(udp_header->src_port),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Destination Port: ",
			(uint32_t)ntohs(udp_header->dest_port),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Length: ",
			(uint32_t)ntohs(udp_header->length),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Checksum: ",
			(uint32_t)ntohs(udp_header->checksum),
			false,
			value_indent
		);

		ImGui::TreePop();
		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();
	}

	if (has_client_dns_layer(packet))
		return DnsPacketRenderer::render_packet_inspection_tree(packet);
}

void IpPacketRenderer::render_packet_inspection_tree(uint8_t* packet)
{
	IpHeader* ip_header = get_ip_header(packet);
	if (ImGui::TreeNode("Internet Protocol Version 4"))
	{
		int value_indent = 150;

		render_inspector_tree_node_field(
			"Version: ",
			(uint32_t)(ip_header->ip_verlen >> 4),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Length: ",
			(uint32_t)(ip_header->ip_verlen & 0x0F) * 4,
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"ToS: ",
			(uint32_t)(ip_header->tos),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Total Length: ",
			(uint32_t)(ntohs(ip_header->totallength)),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"ID: ",
			(uint32_t)(ntohs(ip_header->id)),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Flags: ",
			(uint32_t)(ntohs(ip_header->flags)),
			true,
			value_indent
		);

		render_inspector_tree_node_field(
			"Time to Live: ",
			(uint32_t)(ip_header->ttl),
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Protocol: ",
			(uint32_t)(ip_header->protocol),
			false,
			value_indent,
			{ { PROTOCOL_TCP, "(TCP)" }, { PROTOCOL_UDP, "(UDP)" } }
		);

		render_inspector_tree_node_field(
			"Checksum: ",
			(uint32_t)(ntohs(ip_header->checksum)),
			false,
			value_indent
		);

		ImGui::Spacing();

		auto src_ip = convert_ip_to_string(ip_header->srcaddr);
		auto dest_ip = convert_ip_to_string(ip_header->destaddr);

		ImGui::Text("Sender IP: ");
		ImGui::SameLine(); ImGui::SetCursorPosX((float)value_indent);
		ImGui::Text("%s", src_ip.c_str());

		ImGui::Text("Destination IP: ");
		ImGui::SameLine(); ImGui::SetCursorPosX((float)value_indent);
		ImGui::Text("%s", dest_ip.c_str());

		ImGui::TreePop();
		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();
	}

	if (has_tcp_layer(packet))
		return TcpPacketRenderer::render_packet_inspection_tree(packet);

	if (has_udp_layer(packet))
		return UdpPacketRenderer::render_packet_inspection_tree(packet);
}

void ArpPacketRenderer::render_packet_selection_header(uint8_t* packet)
{
	ArpPacket* arp_packet = reinterpret_cast<ArpPacket*>(packet);
	ImGui::Text("ARP %s", (ntohs(arp_packet->opcode) == ARP_REQUEST_OPCODE) ? "Request" : "Reply");
}

void ArpPacketRenderer::render_packet_inspection_tree(uint8_t* packet)
{
	ArpPacket* arp_packet = reinterpret_cast<ArpPacket*>(packet);
	if (ImGui::TreeNode("Address Resolution Protocol"))
	{
		uint16_t hardware_type = ntohs(arp_packet->hardware_type);
		uint16_t protocol = ntohs(arp_packet->protocol);
		uint16_t opcode = ntohs(arp_packet->opcode);

		int value_indent = 160;

		render_inspector_tree_node_field(
			"Hardware Type: ",
			(uint32_t)hardware_type,
			false,
			value_indent,
			{ { HARDWARE_TYPE_ETHERNET, "(Ethernet)" } }
		);

		render_inspector_tree_node_field(
			"Protocol: ",
			(uint32_t)protocol,
			true,
			value_indent,
			{ { PROTOCOL_IPV4, "(IPv4)" } }
		);

		ImGui::Spacing();

		render_inspector_tree_node_field(
			"Hardware Length: ",
			(uint32_t)arp_packet->hrd_len,
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Protocol Length: ",
			(uint32_t)arp_packet->proto_len,
			false,
			value_indent
		);

		render_inspector_tree_node_field(
			"Opcode: ",
			(uint32_t)opcode,
			true,
			value_indent,
			{ { ARP_REQUEST_OPCODE, "(Request)" }, { ARP_REPLY_OPCODE, "(Reply)" }}
		);

		ImGui::Spacing();

		char src_mac_buf[18];
		char dest_mac_buf[18];
		auto src_ip = convert_ip_to_string((*(uint32_t*)arp_packet->arp_spa));
		auto dest_ip = convert_ip_to_string((*(uint32_t*)arp_packet->arp_tpa));

		// Format copy the source MAC
		sprintf_s(
			src_mac_buf,
			sizeof(src_mac_buf),
			"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
			arp_packet->arp_sha[0],
			arp_packet->arp_sha[1],
			arp_packet->arp_sha[2],
			arp_packet->arp_sha[3],
			arp_packet->arp_sha[4],
			arp_packet->arp_sha[5]
		);

		// Format copy the source MAC
		sprintf_s(
			dest_mac_buf,
			sizeof(dest_mac_buf),
			"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
			arp_packet->arp_tha[0],
			arp_packet->arp_tha[1],
			arp_packet->arp_tha[2],
			arp_packet->arp_tha[3],
			arp_packet->arp_tha[4],
			arp_packet->arp_tha[5]
		);

		ImGui::Text("Sender MAC: ");
		ImGui::SameLine(); ImGui::SetCursorPosX((float)value_indent);
		ImGui::Text("%s", src_mac_buf);

		ImGui::Text("Sender IP: ");
		ImGui::SameLine(); ImGui::SetCursorPosX((float)value_indent);
		ImGui::Text("%s", src_ip.c_str());

		ImGui::Text("Target MAC: ");
		ImGui::SameLine(); ImGui::SetCursorPosX((float)value_indent);
		ImGui::Text("%s", dest_mac_buf);

		ImGui::Text("Target IP: ");
		ImGui::SameLine(); ImGui::SetCursorPosX((float)value_indent);
		ImGui::Text("%s", dest_ip.c_str());

		ImGui::TreePop();
		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();
	}
}

void MainPacketRenderer::render_packet_selection_header(uint8_t* packet, PacketFilterOptions* filters)
{
	// Check if the packet is valid
	if (!packet) return;

	// Check for Layer 2 filters to pass
	//
	// ARP
	if (filters->arp_filter && has_arp_layer(packet))
		return ArpPacketRenderer::render_packet_selection_header(packet);

	// Check for Layer 4 filters to pass
	//
	// TCP
	if (filters->tcp_filter && has_tcp_layer(packet))
		return TcpPacketRenderer::render_packet_selection_header(packet);

	// UDP
	if (filters->udp_filter && has_udp_layer(packet))
		return UdpPacketRenderer::render_packet_selection_header(packet);

	// Check for higher layer filters to pass
	//
	// TLS
	if (filters->tls_filter && has_client_tls_layer(packet))
		return TlsPacketRenderer::render_packet_selection_header(packet);

	// DNS
	if (filters->dns_filter && has_client_dns_layer(packet))
		return DnsPacketRenderer::render_packet_selection_header(packet);
}

void MainPacketRenderer::render_packet_inspection_tree(uint8_t* packet)
{
	// Check if the packet is valid
	if (!packet) return;

	// Get the lowest layer ethernet header
	EthHeader* eth_header = get_eth_header(packet);

	if (ImGui::TreeNode("Ethernet II"))
	{
		char src_mac_buf[18];
		char dest_mac_buf[18];

		// Format copy the source MAC
		sprintf_s(
			src_mac_buf,
			sizeof(src_mac_buf),
			"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
			eth_header->src[0],
			eth_header->src[1],
			eth_header->src[2],
			eth_header->src[3],
			eth_header->src[4],
			eth_header->src[5]
		);

		// Format copy the destination MAC
		sprintf_s(
			dest_mac_buf,
			sizeof(dest_mac_buf),
			"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
			eth_header->dest[0],
			eth_header->dest[1],
			eth_header->dest[2],
			eth_header->dest[3],
			eth_header->dest[4],
			eth_header->dest[5]
		);

		ImGui::Text("Source: ");
		ImGui::SameLine(); ImGui::SetCursorPosX(120.0f);
		ImGui::Text("%s", src_mac_buf);
		ImGui::Spacing();

		ImGui::Text("Destination: ");
		ImGui::SameLine(); ImGui::SetCursorPosX(120.0f);
		ImGui::Text("%s", dest_mac_buf);
		ImGui::Spacing();

		render_inspector_tree_node_field(
			"Protocol: ",
			(uint32_t)ntohs(eth_header->protocol),
			true,
			120,
			{ { PROTOCOL_ARP, "(ARP)" }, { PROTOCOL_IPV4, "(IPv4)" }}
		);

		ImGui::TreePop();
		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();
	}

	if (has_arp_layer(packet))
		return ArpPacketRenderer::render_packet_inspection_tree(packet);

	if (has_ip_layer(packet))
		return IpPacketRenderer::render_packet_inspection_tree(packet);
}
