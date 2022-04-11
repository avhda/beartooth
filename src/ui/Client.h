#pragma once
#include <mitm/AdapterList.h>
#include <mitm/NetUtils.h>
#include "PacketRenderers.h"
#include "ConfigLoader.h"
#include "Texture.h"

class ClientApplication
{
public:
	void init();
	void render();

private:
	void set_dark_theme_colors();
	void set_light_theme_colors();
	void load_textures();
	
	void render_menu_bar();
	void render_settings_window();

	void render_adapters_list();
	void render_attack_window();
	void render_arp_poisoning_attack_data();
	void render_port_scanning_attack_data();

	void render_mitm_target_selection_window();
	void render_portscan_target_selection_window();
	void render_mitm_gateway_selection_window();
	void render_generic_host_selection_window(const char* popup_target_id, std::string& ip_buffer, macaddr mac_buffer);

	void render_intercepted_traffic_window();
	void render_portscan_results_window();
	void render_packet_inspection_window();
	void render_independent_inspection_windows();

private:
	void apply_user_settings();

	void start_arp_spoofing_loop();
	void stop_attack_and_restore_arp_tables();
	void start_traffic_interception_loop();

private:
	ConfigLoader		m_config;
	AdapterList			m_adapter_list;
	Adapter				m_selected_adapter;
	PacketFilterOptions m_filter_options;
	MacVendorDecoder	m_vendor_decoder;

	enum class AttackType_
	{
		ArpPoisoning,
		PortScanning
	};

	AttackType_ m_attack_type = AttackType_::ArpPoisoning;

	struct MITM_data
	{
		macaddr local_mac_address;
		macaddr target_mac_address;
		macaddr gateway_mac_address;

		std::string local_ip;
		std::string target_ip;
		std::string gateway_ip;

		bool attack_in_progress = false;
		bool packet_capture_paused = false;
		bool rearping_in_progress = false;
	};

	MITM_data m_mitm_data;

	struct PORTSCAN_data
	{
		macaddr						target_mac_address;
		std::string					target_ip;
		bool						attack_in_progress = false;
		std::vector<PortScanNode>	scanned_nodes;
	};

	PORTSCAN_data m_portscan_data;

	// Used in packet inspection window
	uint64_t m_selected_packet_id = 0;
	GenericPacketRef m_selected_packet = nullptr;
	std::vector<std::pair<bool, GenericPacketRef>> m_double_clicked_packets;

private:
	bool m_display_settings_window = false;
	bool m_is_settings_window_opened = false;

	bool m_mitm_local_data_opened_flag = true;
	bool m_mitm_target_data_opened_flag = true;
	bool m_mitm_gateway_data_opened_flag = true;

	bool m_portscan_target_data_opened_flag = true;
	bool m_display_select_portscan_target_window = false;

	bool m_display_select_mitm_target_window = false;
	bool m_display_select_mitm_gateway_window = false;
	bool m_is_host_selection_window_opened = false;
	
	bool m_scanning_network = false;

	const char* m_select_mitm_target_window_id			= "Select target host";
	const char* m_select_portscan_target_window_id		= "Select target host##portscan";
	const char* m_select_mitm_gateway_window_id			= "Select gateway host";
	const char* m_settings_window_id					= "Settings window";

private:
	Texture m_hacker_texture;
	Texture m_healthy_computer_texture;
	Texture m_poisoned_computer_texture;

	Texture m_pause_capture_texture;
	Texture m_resume_capture_texture;
};
