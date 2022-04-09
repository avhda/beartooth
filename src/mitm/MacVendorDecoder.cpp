#include "MacVendorDecoder.h"
#include <filesystem>
#include <fstream>

void MacVendorDecoder::load_vendor_list()
{
	const char* vendor_list_path = "config/manuf.txt";

	// Check if manufactorer list file is present
	if (!std::filesystem::is_regular_file(vendor_list_path))
		return;

	std::ifstream file(vendor_list_path);
	std::string line;

	while (std::getline(file, line))
	{
		// Skip empty lines
		if (line.empty())
			continue;

		// Skip comments
		if (line.find("#") == 0)
			continue;

		size_t first_space_idx = line.find("\t");
		size_t second_space_idx = line.find("\t", first_space_idx + 1);
		
		auto mac = line.substr(0, first_space_idx);
		auto vendor = line.substr(first_space_idx + 1, second_space_idx - first_space_idx - 1);
		
		// Remove unnecessary comma at the end of the name if present
		if (vendor.at(vendor.size() - 1) == ',')
			vendor = vendor.substr(0, vendor.size() - 1);

		m_vendor_list.push_back({ mac, vendor });
	}

	file.close();
}

std::string MacVendorDecoder::get_vendor(const std::string& mac)
{
	auto& first_3_bytes = mac.substr(0, 8);

	// Checking against the common 3 byte entries
	for (auto& [mac, vendor] : m_vendor_list)
	{
		if (first_3_bytes == mac)
			return vendor;
	}

	// Checking against the 5 byte values
	auto& first_5_bytes = mac.substr(0, 14);

	for (auto& [mac, vendor] : m_vendor_list)
	{
		if (first_5_bytes == mac)
			return vendor;
	}

	// If nothing matched the target mac, return a constant
	return "Unknown";
}
