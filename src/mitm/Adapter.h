#pragma once
#include <string>

struct address_info {
	union {
		struct { unsigned char s_b1, s_b2, s_b3, s_b4; } S_un_b;
		struct { unsigned short s_w1, s_w2; } S_un_w;
		unsigned long S_addr;
	} S_un;
};

struct Address
{
	address_info info_data;
	std::string to_string();
};

struct Adapter
{
	std::string name;
	std::string description;
	bool		is_online = false;
	Address		address;
	Address		broadcast;
	Address		netmask;
};
