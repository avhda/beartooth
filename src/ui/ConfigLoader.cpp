#include "ConfigLoader.h"
#include <filesystem>
#include <fstream>

bool ConfigLoader::read_config(const std::string& path)
{
	if (!std::filesystem::is_regular_file(path))
		return false;

	m_config_path = path;

	std::ifstream config_file(path);
	std::string line;
	size_t comment_idx = 0;

	while (std::getline(config_file, line))
	{
		// Skip empty lines
		if (line.empty())
			continue;

		// Process comments
		if (line.find("#") == 0)
		{
			std::string comment_key = "#" + std::to_string(++comment_idx);
			m_loaded_properties[comment_key] = line;
			continue;
		}

		// Remove all spaces from the line
		line.erase(std::remove(line.begin(), line.end(), ' '), line.end());

		// Find the equal sign
		size_t equal_sign_idx = line.find('=');

		// Make sure the entry is valid
		if (equal_sign_idx == std::string::npos)
			continue;

		auto key = line.substr(0, equal_sign_idx);
		auto value = line.substr(equal_sign_idx + 1);

		m_loaded_properties.insert({ key, value });
	}

	config_file.close();
	return true;
}

std::string& ConfigLoader::get_string_value(const std::string& key)
{
	static std::string s_error_entry;

	if (m_loaded_properties.find(key) == m_loaded_properties.end())
		return s_error_entry;

	return m_loaded_properties.at(key);
}

int ConfigLoader::get_int_value(const std::string& key)
{
	if (m_loaded_properties.find(key) == m_loaded_properties.end())
		return 0;

	int result = 0;
	try {
		result = std::stoi(m_loaded_properties.at(key));
	}
	catch (...) {}

	return result;
}

bool ConfigLoader::get_bool_value(const std::string& key)
{
	if (m_loaded_properties.find(key) == m_loaded_properties.end())
		return false;

	bool result = false;
	try {
		result = (bool)std::stoi(m_loaded_properties.at(key));
	}
	catch (...) {}

	return result;
}

bool ConfigLoader::write_value(const std::string& key, const std::string& value)
{
	if (m_loaded_properties.find(key) == m_loaded_properties.end())
		return false;
	
	m_loaded_properties[key] = value;

	write_runtime_properties_to_file();
	return true;
}

bool ConfigLoader::write_value(const std::string& key, int value)
{
	if (m_loaded_properties.find(key) == m_loaded_properties.end())
		return false;

	m_loaded_properties[key] = std::to_string(value);

	write_runtime_properties_to_file();
	return true;
}

bool ConfigLoader::write_value(const std::string& key, bool value)
{
	if (m_loaded_properties.find(key) == m_loaded_properties.end())
		return false;

	m_loaded_properties[key] = std::to_string((int)value);

	write_runtime_properties_to_file();
	return true;
}

void ConfigLoader::write_runtime_properties_to_file()
{
	std::ofstream config_file(m_config_path);

	if (config_file.is_open())
	{
		for (auto& [key, value] : m_loaded_properties)
		{
			// Special case for comments
			if (value.find("#") == 0)
			{
				config_file << "\n" << value << "\n";
				continue;
			}

			config_file << key << " = " << value << "\n";
		}

		config_file.close();
	}
}
