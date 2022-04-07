#pragma once
#include <string>
#include <vector>

class MacVendorDecoder
{
public:
	// Loads the (MAC -> vendor) map from a file
	void load_vendor_list();

	std::string get_vendor(const std::string& mac);

private:
	using mac_vendor_pair = std::pair<std::string, std::string>;

	std::vector<mac_vendor_pair> m_vendor_list;
};
