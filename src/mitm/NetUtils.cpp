#include "NetUtils.h"
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <pcap.h>
#include <iphlpapi.h>
#pragma comment(lib, "WS2_32")
#pragma comment(lib, "iphlpapi")

static Adapter					s_adapter					= {};
static pcap_t*					s_pcap_handle				= nullptr;
static pcap_dumper_t*			s_pcap_dumper_handle		= nullptr;
static char						s_errbuf[PCAP_ERRBUF_SIZE];
static std::string				s_dump_filepath				= "";

std::map<std::string, network_scanner::netscan_node> network_scanner::s_network_scan_map;

#define MAX_ARP_PACKETS_TO_WAIT 32
#define MAX_ARP_REQUEST_RETRY_COUNT 8

void net_utils::close_handles()
{
	if (s_pcap_dumper_handle) pcap_dump_close(s_pcap_dumper_handle);
	if (s_pcap_handle) pcap_close(s_pcap_handle);
}

void net_utils::print_packet_bytes(const char* title, const uint8_t* data, size_t dataLen, bool format)
{
	std::cout << title << std::endl;
	std::cout << std::setfill('0');
	for (size_t i = 0; i < dataLen; ++i) {
		std::cout << std::hex << std::setw(2) << (int)data[i];
		if (format) {
			std::cout << (((i + 1) % 16 == 0) ? "\n" : " ");
		}
	}
	std::cout << std::endl;
}

void net_utils::print_mac_address(macaddr addr, bool newline)
{
	printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	if (newline)
		printf("\n");
}

bool net_utils::set_system_ip_forwarding(bool forward)
{
	std::wstring cmd = L"Set-NetIPInterface -Forwarding ";
	std::wstring option = forward ? L"Enabled" : L"Disabled";
	cmd += option;

	SHELLEXECUTEINFO ShExecInfo = { 0 };
	ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.hwnd = NULL;
	ShExecInfo.lpVerb = L"runas";
	ShExecInfo.lpFile = L"powershell.exe";
	ShExecInfo.lpParameters = cmd.c_str();
	ShExecInfo.lpDirectory = NULL;
	ShExecInfo.nShow = SW_HIDE;
	ShExecInfo.hInstApp = NULL;
	BOOL result = ShellExecuteExW(&ShExecInfo);

	if (!ShExecInfo.hProcess)
		return false;

	WaitForSingleObject(ShExecInfo.hProcess, INFINITE);
	CloseHandle(ShExecInfo.hProcess);

	return result;
}

bool net_utils::set_adapter(const Adapter& adapter)
{
	s_adapter = adapter;

	if ((s_pcap_handle = pcap_open(adapter.name.c_str(),
		MAX_PACKET_SIZE,
		PCAP_OPENFLAG_PROMISCUOUS,
		1000,
		NULL,
		s_errbuf
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", adapter.name.c_str());
		return false;
	}

	reopen_dump_file();

	return true;
}

void* net_utils::get_native_pcap_handle()
{
	return s_pcap_handle;
}

bool net_utils::retrieve_local_mac_address(macaddr out_buffer)
{
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	char* mac_addr = (char*)malloc(18);

	AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		free(mac_addr);
		return false;
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			free(mac_addr);
			return false;
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		// Contains pointer to current adapter info
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		do {
			// The right local MAC address has been found
			if (s_adapter.address.to_string() == pAdapterInfo->IpAddressList.IpAddress.String)
			{
				memcpy(out_buffer, pAdapterInfo->Address, MACADDR_LEN);
				break;
			}

			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
	}

	free(AdapterInfo);
	return true;
}

int net_utils::send_packet(void* packet, size_t size)
{
	return pcap_sendpacket(s_pcap_handle, (uint8_t*)packet, (int)size);
}

int net_utils::recv_packet(PacketHeader* header, void* packet, size_t size)
{
	struct pcap_pkthdr* pkthdr;
	const uint8_t* pkt_data;

	// Intersepting the packet
	int result = pcap_next_ex(s_pcap_handle, &pkthdr, &pkt_data);
	if (!result)
		return 0;

	int bytes_received = pkthdr->len;

	// Copying the header
	memcpy(header, pkthdr, sizeof(PacketHeader));

	// Copying the packet
	size_t bytes_to_copy = min(bytes_received, size);
	memcpy(packet, pkt_data, bytes_to_copy);

	return (int)bytes_to_copy;
}

bool net_utils::send_arp_request(macaddr source_mac, macaddr target_mac_buffer, const char* source_ip, const char* target_ip)
{
	const uint32_t source_ip_addr = inet_addr(source_ip);
	const uint32_t target_ip_addr = inet_addr(target_ip);

	ArpPacket request;
	craft_arp_request_packet(&request, source_mac, source_ip_addr, target_ip_addr);

	send_packet(&request, sizeof(ArpPacket));

	ArpPacket reply;
	ZeroMemory(&reply, sizeof(ArpPacket));

	PacketHeader header;
	ZeroMemory(&header, sizeof(PacketHeader));

	size_t intercepted_packet_count = 0;
	size_t retry_count = 0;
	for (;;) {
		++intercepted_packet_count;
		int result = recv_packet(&header, &reply, sizeof(ArpPacket));
		if (!result)
			return false;

		if (intercepted_packet_count > MAX_ARP_PACKETS_TO_WAIT)
		{
			if (retry_count > MAX_ARP_REQUEST_RETRY_COUNT)
				return false;

			++retry_count;
			intercepted_packet_count = 0;
		}

		EthHeader eth_layer;
		memcpy(&eth_layer, &reply, sizeof(EthHeader));

		// Check if the packet is an ARP packet
		if (eth_layer.protocol != htons(PROTOCOL_ARP))
			continue;

		// Make sure the packet is an ARP reply
		bool is_reply = htons(reply.opcode) == 2;
		if (!is_reply)
			continue;

		// Make sure that the reply's sender IP is the
		// original target IP.
		const uint32_t reply_sender_ip =
			  (reply.arp_spa[3] << 24)
			| (reply.arp_spa[2] << 16)
			| (reply.arp_spa[1] << 8)
			| (reply.arp_spa[0] << 0);

		if (reply_sender_ip != target_ip_addr)
			continue;

		// At this point, the desired ARP reply has been captured
		// and we need to copy the target MAC address to the output buffer.
		memcpy(target_mac_buffer, reply.arp_sha, sizeof(macaddr));

		// Break out of the packet interception loop
		break;
	}

	return true;
}

void net_utils::set_packet_dump_path(const std::string& path)
{
	s_dump_filepath = path;
}

void net_utils::reopen_dump_file()
{
	if (s_pcap_dumper_handle) pcap_dump_close(s_pcap_dumper_handle);

	if (s_pcap_handle && !s_dump_filepath.empty())
	{
		s_pcap_dumper_handle = pcap_dump_open(s_pcap_handle, s_dump_filepath.c_str());
	}
}

void net_utils::dump_packet_to_file(PacketHeader* header, void* packet)
{
	pcap_pkthdr pkt_hdr;
	pkt_hdr.caplen = header->caplen;
	pkt_hdr.len = header->len;
	pkt_hdr.ts.tv_sec = header->timeval_sec;
	pkt_hdr.ts.tv_usec = header->timeval_usec;

	pcap_dump((u_char*)s_pcap_dumper_handle, &pkt_hdr, (const u_char*)packet);
}

void network_scanner::scan_network(macaddr source_mac, const std::string& source_ip, const std::string& ip_address_prefix, MacVendorDecoder* vendor_decoder, int range_start, int range_end)
{
	// Delete any already existing entries
	s_network_scan_map.clear();

	// Send out all ARP requests
	for (int i = range_start; i < range_end; ++i)
	{
		auto ip = ip_address_prefix + std::to_string(i);

		const uint32_t source_ip_addr = inet_addr(source_ip.c_str());
		const uint32_t target_ip_addr = inet_addr(ip.c_str());

		// Craft the request packet
		ArpPacket request;
		craft_arp_request_packet(&request, source_mac, source_ip_addr, target_ip_addr);

		// Send the packet
		net_utils::send_packet(&request, sizeof(ArpPacket));
	}

	// Scan and filter through potential replies
	ArpPacket reply;
	ZeroMemory(&reply, sizeof(ArpPacket));

	PacketHeader header;
	ZeroMemory(&header, sizeof(PacketHeader));

	size_t  intercepted_packet_count = 0;
	size_t  retry_count = 0;
	int32_t matched_entries = 0;
	for (;;) {
		++intercepted_packet_count;
		int result = net_utils::recv_packet(&header, &reply, sizeof(ArpPacket));
		if (!result)
			break;

		if (intercepted_packet_count > ((int)MAX_ARP_PACKETS_TO_WAIT * (range_end - range_start)))
		{
			if (retry_count > MAX_ARP_REQUEST_RETRY_COUNT)
				break;

			++retry_count;
			intercepted_packet_count = 0;
		}

		EthHeader eth_layer;
		memcpy(&eth_layer, &reply, sizeof(EthHeader));

		// Check if the packet is an ARP packet
		if (eth_layer.protocol != htons(PROTOCOL_ARP))
			continue;

		// Make sure the packet is an ARP reply
		bool is_reply = htons(reply.opcode) == 2;
		if (!is_reply)
			continue;

		// Make sure that the reply's sender IP is the
		// original target IP.
		const uint32_t reply_sender_ip =
			  (reply.arp_spa[3] << 24)
			| (reply.arp_spa[2] << 16)
			| (reply.arp_spa[1] << 8)
			| (reply.arp_spa[0] << 0);

		// Loop through all the desired entries in the scan map
		// and see which IP the arp replies belongs to.
		for (int i = range_start; i < range_end; ++i)
		{
			auto target_ip = ip_address_prefix + std::to_string(i);;
			const uint32_t target_ip_addr = inet_addr(target_ip.c_str());

			if (reply_sender_ip != target_ip_addr)
				continue;

			// Create a new entry in the scan map
			s_network_scan_map[target_ip] = netscan_node();
			auto& node = s_network_scan_map.at(target_ip);

			// At this point, the desired ARP reply has been captured
			// and we need to copy the target MAC address to the output buffer.
			memcpy(node.physical_address, reply.arp_sha, sizeof(macaddr));

			// Mark the node as an online host
			node.is_online = true;

			// Attempt to decode the host's MAC adapter manufacturer
			if (vendor_decoder)
			{
				char mac_str_buffer[18];
				sprintf_s(
					mac_str_buffer,
					18,
					"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
					node.physical_address[0],
					node.physical_address[1],
					node.physical_address[2],
					node.physical_address[3],
					node.physical_address[4],
					node.physical_address[5]
				);

				node.vendor = vendor_decoder->get_vendor(mac_str_buffer);
			}	

			// Confirm matched entry
			++matched_entries;
		}

		// If all entries have been satisfied, break out of the loop
		if (matched_entries == (range_end - range_start))
			break;
	}
}

void port_scanner::scan_target(const std::string& target_ip, std::vector<PortScanNode>& scanned_nodes, uint16_t start_port, uint16_t end_port)
{
	const uint32_t target_ip_addr = inet_addr(target_ip.c_str());


}
