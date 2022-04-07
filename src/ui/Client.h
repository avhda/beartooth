#pragma once
#include <mitm/AdapterList.h>
#include <mitm/NetUtils.h>
#include "PacketFilters.h"

class ClientApplication
{
public:
	void init();
	void render();

private:
	void set_dark_theme_colors();

	void render_adapters_list();
	void render_mitm_attack_data();

	void render_target_selection_window();
	void render_gateway_selection_window();
	void render_generic_host_selection_window(const char* popup_target_id, std::string& ip_buffer, macaddr mac_buffer);

	void render_intercepted_traffic_window();
	void render_packet_filters_window();

private:
	void start_arp_spoofing_loop();
	void stop_attack_and_restore_arp_tables();
	void start_traffic_interception_loop();

private:
	AdapterList			m_adapter_list;
	Adapter				m_selected_adapter;
	PacketFilterOptions m_filter_options;
	MacVendorDecoder	m_vendor_decoder;

	struct MITM_data
	{
		macaddr local_mac_address;
		macaddr target_mac_address;
		macaddr gateway_mac_address;

		std::string local_ip;
		std::string target_ip;
		std::string gateway_ip;

		bool attack_in_progress = false;
		bool rearping_in_progress = false;
	};

	MITM_data m_mitm_data;

private:
	bool m_mitm_local_data_opened_flag = true;
	bool m_mitm_target_data_opened_flag = true;
	bool m_mitm_gateway_data_opened_flag = true;

	bool m_display_select_target_window = false;
	bool m_display_select_gateway_window = false;
	bool m_is_host_selection_window_opened = false;
	
	bool m_scanning_network = false;

	const char* m_select_target_window_id = "Select target host";
	const char* m_select_gateway_window_id = "Select gateway host";
};
