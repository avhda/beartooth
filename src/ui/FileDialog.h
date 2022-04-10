#pragma once
#include <string>
#include <map>
#include <shobjidl_core.h>

class FileDialogFilter
{
public:
    /// Registers a filter for specific file format(s).
    /// @param name Describes the file formats being filtered.
    /// @param formats String of file formats separated by a semicolon, (i.e "*.png;*.jpg;*.jpeg;*.psd").
    virtual void AddFilter(const std::wstring& name, const std::wstring& formats);

    /// @returns Tells whether any filters have been registered.
    bool HasFilters();

    /// Returns the list of all filters in a map form.
    std::map<std::wstring, std::wstring>& GetFilters() { return m_FilterMap; };

private:
    std::map<std::wstring, std::wstring> m_FilterMap;
};

class FileDialog
{
public:
    std::string ChooseDirectoryDialog();
    std::string ChooseFileDialog();
    std::string SaveFileDialog();
    std::string CreateFileDialog();

    void SetFilter(FileDialogFilter filter) { m_Filter = filter; };

private:
    FileDialogFilter m_Filter;

    IFileOpenDialog* m_pFileOpenDialogue = nullptr;
    std::string FireOpenFileDialogue(FILEOPENDIALOGOPTIONS options, bool open_dialogue);
};
