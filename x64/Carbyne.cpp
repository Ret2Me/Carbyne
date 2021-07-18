#include "CarbyneHeaders.h"
#include <windowsx.h>

#ifdef _DEBUG

#define info(x) std::cout << "[i] " << x << "[i]" << std::endl;
#define warning(x) std::cout << "[!]" << x << "[!]" << std::endl;
#define critical(x) std::cout << "[!!!]" << x << "[!!!]" << std::endl;

#else

#define info(x)
#define warning(x)
#define critical(x)

#endif




namespace carbyne
{
	void killProcess(std::string error)
	{

		// Add your own process killing 
		// remember to destroy stack
	    std::cout << "Detected debugger by: " << error;
	}

	static BOOL CALLBACK EnumWindowsProc(HWND  window_handle, LPARAM lParam) {
	    int length = GetWindowTextLengthW(window_handle);
	    wchar_t* buffer = new wchar_t[length + 1];
	    GetWindowTextW(window_handle, buffer, length + 1);
	    std::wstring window_title(buffer);

	    if (IsWindowVisible(window_handle) && length != 0)
	    {
	        for (std::wstring debugger_window : carbyne::debuggers_window_name) {
	            if (window_title.find(debugger_window) != std::wstring::npos)
					carbyne::killProcess();
	        }
	    }
	    delete[] buffer;
	    return TRUE;
	}


	void crashOllyDbg()
	{
	    // crash OllyDbg v1.0 by exploit
	    __try {
	        OutputDebugString(TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"));
	    }
	    __except (EXCEPTION_EXECUTE_HANDLER) { ; }
	}

	void timeBasedProtection(unsigned __int64& first_tick, unsigned __int64& second_tick)
	{
	    // declarations
	    int* bugged_pointer = NULL;
		//////////

		// Time based detection (cpu tick count)
	    first_tick = __rdtsc();
	    __try {
	        *bugged_pointer = 0x4141;  // will print error in debugger
	    }
	    __except (EXCEPTION_EXECUTE_HANDLER) { ; }
	    second_tick = __rdtsc();
	}




	[[noreturn]] void secondDebuggerDetector(std::thread* watchdog)
	{
	    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	    int time_1;
		int time_2;
	    unsigned __int64 first_tick;
	    unsigned __int64 second_tick;
	    NTSTATUS status;
	    DWORD dwProcessDebugPort, dwReturned;
	    typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
	        IN HANDLE           ProcessHandle,
	        IN PROCESSINFOCLASS ProcessInformationClass,
	        OUT PVOID           ProcessInformation,
	        IN ULONG            ProcessInformationLength,
	        OUT PULONG          ReturnLength
	        );

	    while (true)
	    {
	        // run protections written in asm
	        if (carbyne::_secondWatchdog())
	            killProcess("asm second ");



	        // check is second watchdog working
	        if (watchdog->joinable())
	            killProcess("missing thread");


	        // Detect debugger by window name
	        EnumWindows(EnumWindowsProc, NULL);

    		
	        // Time based detection (cpu tick count)
	        timeBasedProtection(first_tick, second_tick);

    		// normally delta time needed to execute try-expect operation
			// while using debugger in step-by-step mode is  ~1993232626 (10^9)
	        if (second_tick - first_tick > 1000000000)
	            killProcess("time");


	        // Time based detection with GetTickCount() function provided by kernel32.dll
			time_1 = GetTickCount64();
			time_2 = GetTickCount64();
			if (time_2 - time_1 > 20)
			    killProcess("second time");



    		// detected build ind kern
	        if (hNtdll)
	        {
	            auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
	                hNtdll, "NtQueryInformationProcess");


	            //DWORD dwProcessDebugFlags, dwReturned;
	            //_PROCESSINFOCLASS ProcessDebugFlags; //= 0x1f;
	            if (pfnNtQueryInformationProcess)
	            {
	                dwProcessDebugPort = 0;
            		dwReturned = 0;
	                status = pfnNtQueryInformationProcess(
	                    GetCurrentProcess(),
	                    ProcessDebugPort,
	                    &dwProcessDebugPort,
	                    sizeof(DWORD),
	                    &dwReturned);
            	            		
	                if (NT_SUCCESS(status) && -1 == dwProcessDebugPort)
	                    killProcess("kernel mode detection");
	            }

	        }
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}
	}


	//ToDo: Timeouts, SoftICE (local kernel debugger), NtQuerySystemInformation, procesors ticks
	[[noreturn]] void firstDebuggerDetector(std::thread* watchdog)
	{
	    // declarations
	    std::wstring process_name;
	    BOOL debugger_connected;
	    PROCESSENTRY32W process_information{ sizeof(PROCESSENTRY32W) };
	    HANDLE process_list;
	    ////////


	    while (true) {


	        if (carbyne::_firstWatchdog())
	            killProcess("asm_first");

	        // check is second watchdog is working
	        if (watchdog->joinable())
	            killProcess("missing thread");


	        // basic Winapi protection
	        debugger_connected = false;
	        if (!CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugger_connected))
	            if (IsDebuggerPresent() || debugger_connected)
	                killProcess("Remote debugger");
	        else
	            std::cout << GetLastError();



    		// uses exploit to break OllyDbg
	        crashOllyDbg();


	        // detect debugger by process file (for example: ollydbg.exe)
	        process_list = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	        process_information = { sizeof(PROCESSENTRY32W) };
	        if (!(Process32FirstW(process_list, &process_information)))
	            killProcess("it is impossible to run api funciton");
	        else 
	        {
	            do 
	            {
	                for (std::wstring debugger : carbyne::debuggers_file_name)
	                {
	                    process_name = process_information.szExeFile;
	                    if (process_name.find(debugger) != std::string::npos)
	                        killProcess("illegal process found");
	                }
	            } while (Process32NextW(process_list, &process_information));
	        }
	        CloseHandle(process_list);

    		

	        // check is anti anti-debugger working
	        // 1. set isDebuggerPresent to true
	        // 2. check if isDebuggerPresent value changed to zero
	        // 3. if yes killProcess
	        // [redirected to asmCore.asm]

    		
	        //Detach Debugger
	        DebugActiveProcessStop(GetProcessId(GetCurrentProcess()));

			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	    }
	}

	// environment for assembler debugging
	[[noreturn]] void asmTest() {
	    std::cout << std::endl
				  << std::string(100, '=') << std::endl << "asm started" << std::endl << std::string(100, '=')
				  << std::endl;

		
		PTEB tebPtr = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
		info("PEB address is: " << tebPtr->ProcessEnvironmentBlock);
		
	    std::cout.unsetf(std::ios::hex);
	    info("BeingDebugged: " << std::hex << (int)tebPtr->ProcessEnvironmentBlock->BeingDebugged);

		
	    PPEB pPeb = (PPEB)__readgsqword(0x60);
		info("NtGlobalFlag: " << std::hex << *(PDWORD)((PBYTE)pPeb + 0xBC));
		
		while (true) {

			// tested functions
	        int tmp_func_val = carbyne::_firstWatchdog();
	        int sec_tmp_func_val = carbyne::_secondWatchdog();

	        if (tmp_func_val > 0) {
	            warning("DEBUGGER DETECTED");
	            system("pause");
	        }
	    }
	}	
}
[[noreturn]] int main()
{
	// For debugging
	//std::thread asm_test;
	//asm_test = std::thread(asmTest);
	//asm_test.detach();


	std::thread first_watchdog;
	std::thread second_watchdog;

	first_watchdog = std::thread(carbyne::firstDebuggerDetector, &second_watchdog);
	second_watchdog = std::thread(carbyne::secondDebuggerDetector, &first_watchdog);

	first_watchdog.detach();
	second_watchdog.detach();


	while (true)
	{
		std::cout << "[+] some operation [+]" << std::endl;
		Sleep(1000);
	}
}