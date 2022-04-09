#pragma once
#include <string>
#include <map>
#include <fstream>

#define DEFAULT_USER_SETTINGS_PATH "config/user_settings.cfg"

#define CONFIG_KEY_IP_FORWARDING "ip_forwarding"

class ConfigLoader
{
public:
	bool read_config(const std::string& path = DEFAULT_USER_SETTINGS_PATH);

	std::string& get_string_value(const std::string& key);
	int			 get_int_value(const std::string& key);
	bool		 get_bool_value(const std::string& key);

	bool		 write_value(const std::string& key, const std::string& value);
	bool		 write_value(const std::string& key, int value);
	bool		 write_value(const std::string& key, bool value);

private:
	std::string							m_config_path;
	std::map<std::string, std::string>	m_loaded_properties;

	void write_runtime_properties_to_file();
};
