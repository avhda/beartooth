#pragma once
#include <string>

class Texture
{
public:
    static void set_d3d11_device_ptr(void* device);

public:
    bool load_from_file(const std::string& path);

    inline int get_width() const { return m_width; }
    inline int get_height() const { return m_height; }
    inline void* get_resource_handle() const { return m_native_resource_handle; }

private:
    void* m_native_resource_handle = nullptr;

    int m_width = 0, m_height = 0;
};
