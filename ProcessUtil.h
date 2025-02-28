#include <windows.h>
#include <cstdint>
#include <io.h>
#include <fcntl.h>
#ifdef _WIN32
typedef uint32_t  PID_T;
#else
typedef pid_t PID_T;
#endif

class ProcessUtil {
public:
    #ifdef _WIN32
    static FILE* PopenEx(std::string command, PID_T* pidOut = nullptr) {
    
            HANDLE hReadPipe, hWritePipe;
            SECURITY_ATTRIBUTES saAttr;
            PROCESS_INFORMATION piProcInfo;
            STARTUPINFO siStartInfo;
            FILE* pipeFp = nullptr;
    
            // 设置安全属性，允许管道句柄继承
            saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
            saAttr.bInheritHandle = TRUE;
            saAttr.lpSecurityDescriptor = nullptr;
    
            // 创建匿名管道
            if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
                perror("CreatePipe");
                return nullptr;
            }
    
            // 确保写句柄不被子进程继承
            if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
                perror("SetHandleInformation");
                CloseHandle(hReadPipe);
                CloseHandle(hWritePipe);
                return nullptr;
            }
    
            // 初始化 STARTUPINFO 结构体
            ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
            ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
            siStartInfo.cb = sizeof(STARTUPINFO);
            siStartInfo.hStdError = hWritePipe;
            siStartInfo.hStdOutput = hWritePipe;
            siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
    
            // 创建子进程
            if (!CreateProcess(
                nullptr,                        // No module name (use command line)
                (LPSTR)command.data(),          // Command line
                nullptr,                        // Process handle not inheritable
                nullptr,                        // Thread handle not inheritable
                TRUE,                           // Set handle inheritance
                CREATE_NO_WINDOW,               // No window
                nullptr,                        // Use parent's environment block
                nullptr,                        // Use parent's starting directory 
                &siStartInfo,                   // Pointer to STARTUPINFO structure
                &piProcInfo                     // Pointer to PROCESS_INFORMATION structure
            )) {
                perror("CreateProcess");
                CloseHandle(hReadPipe);
                CloseHandle(hWritePipe);
                return nullptr;
            }
    
            // 关闭写端句柄（父进程不使用）
            CloseHandle(hWritePipe);
    
            // 返回子进程 PID
            if (pidOut) {
                *pidOut = piProcInfo.dwProcessId;
            }
    
            // 将管道的读端转换为 FILE* 并返回
            pipeFp = _fdopen(_open_osfhandle(reinterpret_cast<intptr_t>(hReadPipe), _O_RDONLY), "r");
            if (!pipeFp) {
                CloseHandle(hReadPipe);
            }
    
            // 关闭进程句柄（不需要等待子进程）
            CloseHandle(piProcInfo.hProcess);
            CloseHandle(piProcInfo.hThread);
    
            return pipeFp;
        }
    #endif
    #ifdef _WIN32
        static int Kill(PID_T pid) {

        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            // 打开指定进程
        if (hProcess == nullptr) {
        std::cout << "Failed to open process with PID " << pid << ", error: " << GetLastError() << std::endl;
            return -1;
        }

        // 终止进程
        if (!TerminateProcess(hProcess, 0)) {
            std::cout << "Failed to terminate process with PID " << pid << ", error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return -1;
        }

        // 成功终止进程
        CloseHandle(hProcess);
        return 0;
    }
    #endif
    static bool Exec(std::string cmdline) {
        #ifdef _WIN32
                PROCESS_INFORMATION piProcInfo;
                STARTUPINFO siStartInfo;
        
                // 初始化 STARTUPINFO 结构体
                ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
                ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
        
                // 创建子进程
                if (CreateProcess(
                    nullptr,                        // No module name (use command line)
                    (LPSTR)cmdline.data(),          // Command line
                    nullptr,                        // Process handle not inheritable
                    nullptr,                        // Thread handle not inheritable
                    TRUE,                           // Set handle inheritance
                    CREATE_NO_WINDOW,               // No window
                    nullptr,                        // Use parent's environment block
                    nullptr,                        // Use parent's starting directory
                    &siStartInfo,                   // Pointer to STARTUPINFO structure
                    &piProcInfo                     // Pointer to PROCESS_INFORMATION structure
                )) {
                    WaitForSingleObject(piProcInfo.hProcess, INFINITE);
                    CloseHandle(piProcInfo.hProcess);
                    CloseHandle(piProcInfo.hThread);
                    return true;
                }
                else {
                    return false;
                }
        #else
                return std::system(cmdline.c_str()) == 0;
        #endif
            }
};