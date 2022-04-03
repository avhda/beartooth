#include "AdapterList.h"
#include <pcap/pcap.h>

size_t AdapterList::find_adapters()
{
    pcap_if_t*  found_devices = nullptr;
    pcap_if_t*  current_device = nullptr;

    char errbuf[PCAP_ERRBUF_SIZE];

    // Retrieve the device list from the local machine
    if (pcap_findalldevs(&found_devices, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        return 0;
    }

    // Parse adapter information
    for (pcap_if_t* current_device = found_devices; current_device != NULL; current_device = current_device->next)
    {
        Adapter adapter;
        adapter.name = current_device->name;
        adapter.description = current_device->description;

        // Get address information for the adapter
        for (pcap_addr_t* addr_info = current_device->addresses; addr_info != NULL; addr_info = addr_info->next)
        {
            Address main_address;
            main_address.info_data = *((address_info*)&((sockaddr_in*)addr_info->addr)->sin_addr);

            // Check if address is valid
            if (main_address.to_string() == "0.0.0.0")
                continue;

            Address broadcast_address;
            broadcast_address.info_data = *((address_info*)&((sockaddr_in*)addr_info->broadaddr)->sin_addr);

            Address netmask_address;
            netmask_address.info_data = *((address_info*)&((sockaddr_in*)addr_info->netmask)->sin_addr);

            adapter.is_online   = true;
            adapter.address     = main_address;
            adapter.broadcast   = broadcast_address;
            adapter.netmask     = netmask_address;
        }

        // Skip the adapter if it's offline
        if (!adapter.is_online)
            continue;

        // Add adapter to the list
        adapters.push_back(adapter);
    }

    if (adapters.size() == 0)
    {
        printf("No interfaces found! Make sure Npcap is installed.\n");
        return 0;
    }

    // Free the device list
    pcap_freealldevs(found_devices);

    return adapters.size();
}
