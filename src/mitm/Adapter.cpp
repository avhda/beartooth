#include "Adapter.h"
#include <winsock.h>

std::string Address::to_string()
{
	return std::string(inet_ntoa(*(in_addr*)&info_data));
}
