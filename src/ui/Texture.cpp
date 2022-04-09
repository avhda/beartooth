#include "Texture.h"
#include <d3d11.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

static ID3D11Device* g_pd3dDevice = NULL;

void Texture::set_d3d11_device_ptr(void* device)
{
    g_pd3dDevice = reinterpret_cast<ID3D11Device*>(device);
}

bool Texture::load_from_file(const std::string& path)
{
    // Load from disk into a raw RGBA buffer
    unsigned char* image_data = stbi_load(path.c_str(), &m_width, &m_height, NULL, 4);
    if (image_data == NULL)
        return false;

    // Create texture
    D3D11_TEXTURE2D_DESC desc;
    ZeroMemory(&desc, sizeof(desc));
    desc.Width = m_width;
    desc.Height = m_height;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    desc.CPUAccessFlags = 0;

    ID3D11Texture2D* pTexture = NULL;
    D3D11_SUBRESOURCE_DATA subResource;
    subResource.pSysMem = image_data;
    subResource.SysMemPitch = desc.Width * 4;
    subResource.SysMemSlicePitch = 0;
    g_pd3dDevice->CreateTexture2D(&desc, &subResource, &pTexture);

    // Create texture view
    D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc;
    ZeroMemory(&srvDesc, sizeof(srvDesc));
    srvDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
    srvDesc.Texture2D.MipLevels = desc.MipLevels;
    srvDesc.Texture2D.MostDetailedMip = 0;
    g_pd3dDevice->CreateShaderResourceView(pTexture, &srvDesc, reinterpret_cast<ID3D11ShaderResourceView**>(&m_native_resource_handle));
    pTexture->Release();

    stbi_image_free(image_data);
    return true;
}
