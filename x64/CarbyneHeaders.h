#pragma once
#include "windows.h"
#include "Tlhelp32.h"
#include "winternl.h"

#include <winnt.h>
#include <thread>
#include <string>
#include <future>
#include <string>    // for debugging
#include <iostream>  // for debugging

namespace carbyne {
    extern "C" {
        int _firstWatchdog();
        int _secondWatchdog();
    	
    }
    void killProcess(std::string error = "");
    [[noreturn]] void firstDebuggerDetector(std::thread* watchdog);
    [[noreturn]] void secondDebuggerDetector(std::thread* watchdog);
    void crashOllyDbg();
    static BOOL CALLBACK EnumWindowsProc(HWND  window_handle, LPARAM lParam);

	// your blacklist
    const std::wstring debuggers_file_name[5]{ L"Cheat Engine", L"ollydbg", L"ida", L"radare2", L"HxD" };
    const std::wstring debuggers_window_name[5]{ L"Cheat Engine", L"OllyDbg", L"ida", L"radare2", L"HxD" };

}
