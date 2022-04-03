#pragma once
#include "Adapter.h"
#include <vector>

class AdapterList
{
public:
	AdapterList() = default;
	~AdapterList() = default;

	// Reads in adapter information for each found network adapter.
	// Returns the number of adapters found.
	size_t find_adapters();
	
	std::vector<Adapter> adapters;
};
