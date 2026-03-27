/* CLARIFICATION

	RESEARCH CODE
 
	CREATED BY civ

*/ 


#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN
#define _WIN32_DCOM
#define WINVER 0x0600


#define DISK_THRESHOLD 50 // default for vms
#define PROCESSOR_THRESHOLD 4 // for vms
#define RAM_THRESHOLD_GB 4 // for vms

#include <winsock2.h> // mac check
#include <windows.h>
#include <iphlpapi.h> // mac check
#include <ws2tcpip.h>
#include <tlhelp32.h> // ProcessScan()
#include <iostream>
#include <intrin.h> // __cpuid
#include <winreg.h>
#include <string.h>
#include <debugapi.h> // debug checks
#include <sysinfoapi.h> // ram check
#include <objbase.h> // wmi
#include <wbemidl.h> // IWbem*
#include <comdef.h>
#include <memoryapi.h> // virtual alloc, virtual free

#define TRUE 1
#define FALSE 0

#define VM_LIST_COUNT 9
#define MAX_PROCESS_COUNT 512

// EXPERIMENTAL VM REGISTRY CHECK
#define SCSI_REGCHECK 0x1
#define SYSTEMDESCRIPTION_REGCHECK 0x2
#define SYSTEMINFORMATION_REGCHECK 0x3

#define SMALL_SIGNAL 3
#define MODERATE_SIGNAL 5
#define BIG_SIGNAL 10
#define GIANT_SIGNAL 20
#define DETECTED 25

#define PERFECT 5
#define HM 10
#define SUSPICOUS 15
#define VERY_SUSPICOUS 20
#define DEFINITELY 25

struct mode{
	bool coreCheck=false;
	bool debugCheck=false;
	bool resourceCheck=false;
	bool timingCheck=false;
	bool sandboxCheck=false;
};



class Helpers{
	public:
	int PrintError(){
		int error = GetLastError();
		char buf[1024] = {0};
		FormatMessageA( FORMAT_MESSAGE_FROM_SYSTEM | 
			FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr,
			error,
			0,
			buf,
			sizeof(buf),
			nullptr
		);
		std::cout << "[-] Failed WITH ERROR CODE " << error << " : " << buf;
		return error;
	}
	
	HRESULT PrintErrorCOM(HRESULT err){
		char buf[1024] = {0};
		FormatMessageA( FORMAT_MESSAGE_FROM_SYSTEM | 
			FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr,
			err,
			0,
			buf,
			sizeof(buf),
			nullptr
		);
		std::cout << "[-] Failed WITH ERROR CODE " << err << " : " << buf << std::endl;
		return err;
	}
	
	bool compareToCommonVMMACs(BYTE prMAC[6]){
		BYTE hyperV1[3] = {0x0, 0x1D, 0xD8}; // 00:1D:D8
		BYTE hyperV2[3] = {0x0, 0x15, 0x5D}; // 00:15:5D
		BYTE vmware[3] = {0x0, 0x50, 0x56}; // 00:50:56
		BYTE vmware2[3] = {0x0, 0x0C, 0x29}; // 00:0C:29
		BYTE vmware3[3] = {0x0, 0x1C, 0x14}; // 00:1C:14 
		BYTE vmware4[3] = {0x0, 0x05, 0x69}; // 00:05:69
		BYTE virtualbox[3] = {0x08, 0x0, 0x27}; // 08:00:27
		BYTE kvm[3] = {0x54, 0x52, 0x0}; // 54:52:00
		BYTE xen[3] = {0x0, 0x16, 0x3E}; // 00:16:3E
		
		BYTE* linked[VM_LIST_COUNT] = {hyperV1, hyperV2, vmware, vmware2, vmware3, vmware4, virtualbox, kvm, xen};
		BYTE* curr = nullptr;
		
		for(int i = 0; i < VM_LIST_COUNT; i++){
			curr = linked[i];
			if(curr[0] == prMAC[0] && curr[1] == prMAC[1] && curr[2] == prMAC[2]) return true;
		}
		return false;
	}
	
	void printReadableTypeCheck(mode md){
		std::cout << "The selected type check is: " << std::endl;
		if(md.coreCheck) std::cout << "CORE + " << std::endl;
		if(md.debugCheck) std::cout << "DEBUG + " << std::endl;
		if(md.resourceCheck) std::cout << "RESOURCE + " << std::endl;
		if(md.timingCheck) std::cout << "TIMING" << std::endl;
	}
	
	// EXPERIMENTAL FEATURE: REGISTRY BASED VM DETECTION
	bool searchBuff(char* buff, DWORD dataType){
		const char* names[] = {"oracle", "vbox", "vmware", "hyper v", "xen", "qemu", nullptr};
		if(dataType == REG_SZ){
			for(char* p = buff; *p; p++){
				*p = (char)tolower((unsigned char)*p);
			}
			for(int i = 0; names[i]; i++){
				if(strstr(buff, names[i])) return true;
			}
		}
		
		else if(dataType == REG_MULTI_SZ){
			char* ptr = buff;
			while(*ptr != '\0'){
				for(char* p = ptr; *p; p++){
					*p = (char)tolower((unsigned char)*p);
				}
				for(int i = 0; names[i]; i++){
					if(strstr(ptr, names[i])) return true;
				}
				ptr += strlen(ptr) + 1;
			}
		}
		
		return false;
	}
	
	// EXPERIMENTAL FEATURE: REGISTRY BASED VM DETECTION
	bool fillBufferUp(HKEY key, char** buff, DWORD* buffSize, DWORD* dataType, LPCSTR str){
		DWORD status = 0;
		status = RegQueryValueExA(key, str, nullptr, nullptr, nullptr, buffSize);
		if(status != ERROR_SUCCESS) return false;
		if(*buffSize <= 0) return false;
		*buff = (char*)malloc(*buffSize+1);
		if(!*buff) return false;
		if(RegQueryValueExA(key, str, nullptr, dataType, (LPBYTE)*buff, buffSize) != ERROR_SUCCESS) return false;
		*buff[*buffSize] = '\0';
		if(*dataType != REG_SZ && *dataType != REG_MULTI_SZ) return false;
		return true;
	}
	
	// EXPERIMENTAL FEATURE: REGISTRY BASED VM DETECTION
	int compareToVMRegKeys(HKEY key, int WHAT_REGCHECK, int* score){
		DWORD dataType = 0;
		DWORD buffSize = 0;
		char* buff = nullptr;

		if(WHAT_REGCHECK == SCSI_REGCHECK){
			if(!fillBufferUp(key, &buff, &buffSize, &dataType, "Identifier")){
				if(buff) free(buff);
				return FALSE;
		}

        std::cout << "SCSI buffer read\n";

        if(searchBuff(buff, dataType)){
            *score += 20;
            free(buff);
            return TRUE;
        }

        free(buff);
        return FALSE;
    }

    else if(WHAT_REGCHECK == SYSTEMDESCRIPTION_REGCHECK){
        DWORD dataType2 = 0;
        DWORD buffSize2 = 0;
        char* buff2 = nullptr;

        if(!fillBufferUp(key, &buff, &buffSize, &dataType, "SystemBiosVersion")){
            if(buff) free(buff);
            return FALSE;
        }

        if(!fillBufferUp(key, &buff2, &buffSize2, &dataType2, "VideoBiosDate")){
            free(buff);
            if(buff2) free(buff2);
            return FALSE;
        }

        std::cout << "SYSTEM DESCRIPTION buffers read\n";

        int tempScore = *score;

        if(searchBuff(buff, dataType)) *score += 20;
        if(searchBuff(buff2, dataType2)) *score += 20;

        free(buff);
        free(buff2);

        return (*score != tempScore);
    }

    else if(WHAT_REGCHECK == SYSTEMINFORMATION_REGCHECK){
        DWORD dataType2 = 0;
        DWORD buffSize2 = 0;
        char* buff2 = nullptr;

        if(!fillBufferUp(key, &buff, &buffSize, &dataType, "SystemManufacturer")){
            if(buff) free(buff);
            return FALSE;
        }

        if(!fillBufferUp(key, &buff2, &buffSize2, &dataType2, "SystemProductName")){
            free(buff);
            if(buff2) free(buff2);
            return FALSE;
        }

        std::cout << "SYSTEM INFORMATION buffers read\n";

        int tempScore = *score;

        if(searchBuff(buff, dataType)) *score += 20;
        if(searchBuff(buff2, dataType2)) *score += 20;

        free(buff);
        free(buff2);

        return (*score != tempScore);
    }

    return FALSE;
}
};

class WMISetup{
	public:
	
	IWbemLocator* ptrLoc = nullptr;
	IWbemServices* ptrProxy = nullptr;
	IEnumWbemClassObject* enumerator = nullptr;
	Helpers help;
	
	HRESULT WMIStart(){
		HRESULT res = 0;
		
		res = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
		if(FAILED(res)) return help.PrintErrorCOM(res);
		res = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, 
				 RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
			
		if(FAILED(res)) return help.PrintErrorCOM(res);
		res = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, 
				 IID_IWbemLocator, (LPVOID*)&ptrLoc);
				 
		if(FAILED(res)) return help.PrintErrorCOM(res);
		
		BSTR path = SysAllocString(L"ROOT\\CIMV2");
	
		res = ptrLoc->ConnectServer(path, nullptr, nullptr, 0, 0, 0, 0, &ptrProxy);
		if(FAILED(res)){
			SysFreeString(path);
			return help.PrintErrorCOM(res);
		}
		SysFreeString(path);
		
		res = CoSetProxyBlanket(ptrProxy, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
				 RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
		if(FAILED(res)) return help.PrintErrorCOM(res);
		
		return 0;
	}
	
	HRESULT Query(BSTR query){
		BSTR wql = SysAllocString(L"WQL");
		HRESULT res = 0;
		
		res = ptrProxy->ExecQuery(wql, query, WBEM_FLAG_FORWARD_ONLY, 
				 nullptr, &enumerator);
	
		SysFreeString(query);

		SysFreeString(wql);
				   
		if(FAILED(res)) return res;
	
		return 0;
	}
	
	void destroyCOM(){
		if(ptrProxy) ptrProxy->Release();
		if(ptrLoc) ptrLoc->Release();
		if(enumerator) enumerator->Release();
		CoUninitialize();
	}

};

class AntiAnalysis{
		mode md;
		int score = 0;
		Helpers help;
		char* detectedProcesses[MAX_PROCESS_COUNT] = {0};
		int count = 0;
		long mode = 0;
		WMISetup wmi;
		// CORE CHECKS
		void addSuspicousProcesses(LPCSTR src){
			int i = 0;
			while(src[i]){
				detectedProcesses[count][i] = src[i];
				i++;
			}
		}
		
		int processScan(){
			int myScore = 0;
			PROCESSENTRY32 processEntry;
			int detectedProcessCount = 0;
			LPCSTR suspicousProcesses[] ={
				"apimonitor-x64.exe", "apimonitor-x86.exe", "x64dbg.exe", "x32dbg.exe",
				"Autoruns64.exe", "Autoruns.exe", "Procmon64.exe", "Procmon.exe",
				"procexp.exe", "procexp64.exe", "Wireshark.exe", "dumpcap.exe", "windbg.exe", 
				"ida.exe", "ida64.exe", "idag.exe", "idag64.exe", "idaw.exe", "idaw64.exe",
				"scylla.exe", "scylla_x64.exe", "scylla_x86.exe", "protection_id.exe","x96dbg.exe",
				"immunitydebugger.exe", "ImportREC.exe","MegaDumper.exe", "reshacker.exe", 
				"processhacker.exe", "filemon.exe", "regmon.exe", "hookexplorer.exe", "PETools.exe",
				"LordPE.exe","SysInspector.exe","proc_analyzer.exe","sysAnalyzer.exe","sniff_hit.exe",
				"joeboxcontrol.exe","joeboxserver.exe","ResourceHacker.exe","fiddler.exe","httpdebugger.exe"
			};
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if(snapshot == INVALID_HANDLE_VALUE) return help.PrintError();
			processEntry.dwSize = sizeof(PROCESSENTRY32);
			if(Process32First(snapshot, &processEntry)){
				do{		
					int i = 0;			
					while(i < (int)(sizeof(suspicousProcesses) / sizeof(LPCSTR))){
						if(!lstrcmpi(processEntry.szExeFile, suspicousProcesses[i])){
							myScore += BIG_SIGNAL;
							addSuspicousProcesses(suspicousProcesses[i]);
							detectedProcessCount++;
						}
						i++;
					}
				} while(Process32Next(snapshot, &processEntry));
			}
			else{
				CloseHandle(snapshot);
				return help.PrintError(); 
			}
			CloseHandle(snapshot);
			score += myScore;
			detectedProcesses[detectedProcessCount] = nullptr;
			if(detectedProcessCount != 0){
				std::cout << "[-] Detected suspicous process names. [+5]\nProcesses are:" << std::endl;
					int i = 0;
					while(detectedProcesses[i]){
						std::cout << "[-] " << detectedProcesses[i] << " [+5]" << std::endl;
						free((void*)detectedProcesses[i]);
						i++;
					}
			}
			else{ std::cout << "[+] No suspicous processes found" << std::endl; }
			return 0;
		}
		
		void cpuidCheckOne(){
			int cpuInfo[4] = {0};
			__cpuid(cpuInfo, 0x40000000);
			for(int i = 1; i < 4; i++){
				if(cpuInfo[i] != 0){
					score += DETECTED;
					std::cout << "[-] CPUID Hypervisor vendor name detected, definitely VM. [+25]" << std::endl;
					return;
				}
			}
			std::cout << "[+] No CPUID Hypervisor vendor name detected" << std::endl;
			return;
		}
		
		void cpuidCheckTwo(){
			int cpuInfo[4] = {0};
			__cpuid(cpuInfo, 1);
			if(cpuInfo[2] >> 31 & 1){
				score += DETECTED;
				std::cout << "[-] CPUID Hypervisor Bit in ECX set, definitely VM. [+25]" << std::endl;
			}
			std::cout << "[+] CPUID Hypervisor Bit in ECX is not set" << std::endl;
		}
		
		int checkMACs(){
			IP_ADAPTER_ADDRESSES* macs = nullptr;
			
			ULONG len = sizeof(IP_ADAPTER_ADDRESSES);
			macs = (IP_ADAPTER_ADDRESSES *)malloc(len); // allocate 1 IP_ADAPTER_ADDRESSES
			int res = 0;
			res = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
			nullptr, macs, &len
			);
			
			do{
				free(macs);
				macs = (IP_ADAPTER_ADDRESSES *)malloc(len);
				if(macs==nullptr) return help.PrintError();
				res = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
			nullptr, macs, &len);
				if(res != ERROR_BUFFER_OVERFLOW && res != NO_ERROR){
					free(macs);
					return help.PrintError();
				}
			} while(res == ERROR_BUFFER_OVERFLOW);	
				
			IP_ADAPTER_ADDRESSES* currMac = macs;
				
			while(currMac){
				if(currMac->PhysicalAddressLength == 6){
					if(help.compareToCommonVMMACs(currMac->PhysicalAddress)){
						score += DETECTED;
						free(macs);
						std::cout << "[-] MAC Is a hypervisor OUI, definitely VM. [+25]" << std::endl;
						return 0;
					}
				}
				currMac = currMac->Next;
			}
			std::cout << "[+] MAC does not match any hypervisor OUI" << std::endl;
			return 0;
		}
	
	
	// DEBUG CHECKS
	
	int checkDebugSimple(){
		BOOL dbg = FALSE;
		if(IsDebuggerPresent() != 0){
			score += DETECTED;
			std::cout << "[-] Debugger Detected. [+25] (IsDebuggerPresent)" << std::endl;
			return 0;
		}
		if(!CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg)) return help.PrintError();
		if(dbg){
			score += DETECTED;
			std::cout << "[-] Debugger Detected. [+25] (CheckRemoteDebuggerPresent)" << std::endl;
			return 0;
		}
		std::cout << "[+] No Debugger Detected. (Used CheckRemoteDebuggerPresent & IsDebuggerPresent)" << std::endl;
		return 0;
	}
	
	int checkHardwareBreakpoints(){
		PCONTEXT ctx = PCONTEXT(VirtualAlloc(nullptr, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE));
		if(!ctx) return help.PrintError();
		
		if(SecureZeroMemory(ctx, sizeof(CONTEXT)) == nullptr){
			VirtualFree(ctx, 0, MEM_RELEASE);
			return help.PrintError();
		}
		
		ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;
		
		if(GetThreadContext(GetCurrentThread(), ctx)){
			
			if(ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0){
				std::cout << "[-] Debug register nonzero / hardware breakpoint detected. [+25]" << std::endl;
				score += DETECTED;
				VirtualFree(ctx, 0, MEM_RELEASE);
				return 0;
			}
			
			else{
				std::cout << "[+] No Debug register value / hardware breakpoint detected." << std::endl;
				VirtualFree(ctx, 0, MEM_RELEASE);
				return 0;
			}
			
		}
		
		else{
			VirtualFree(ctx, 0, MEM_RELEASE);
			return help.PrintError();
		}
	}
	
	// RESOURCE CHECK
	
	int smallDiskCheck(){
			ULARGE_INTEGER totalBytes;
			totalBytes.QuadPart = 0;
			if(!GetDiskFreeSpaceExA("\\\\?\\c:\\", nullptr,  &totalBytes, nullptr)) return help.PrintError();
			int diskSize = totalBytes.QuadPart / 1024 / 1024 / 1024;
			if(diskSize <= DISK_THRESHOLD ){
				score += MODERATE_SIGNAL;
				std::cout << "[-] Small disk size, sign of vm. [+5] (<=50)" << std::endl;
				return 0;
			}  
			std::cout << "[+] Normal disk size. (>50)" << std::endl;
			return 0;
		}
		
	void lowProcessorCount(){
			SYSTEM_INFO sysInfo = {0};
			GetSystemInfo(&sysInfo);
			if(sysInfo.dwNumberOfProcessors < PROCESSOR_THRESHOLD){
				score += MODERATE_SIGNAL;
				std::cout << "[-] Low processor count, sign of vm. [+5] (<4)" << std::endl;
				return;
			}
			std::cout << "[+] Normal processor count. (>4)" << std::endl;
		}
		
	int lowRAM(){
		ULONGLONG RAMTotal;
		if(!GetPhysicallyInstalledSystemMemory(&RAMTotal)) return help.PrintError();
		long gbRAMTotal = RAMTotal / (1024 * 1024);
		if(gbRAMTotal < RAM_THRESHOLD_GB){
			score += MODERATE_SIGNAL;
			std::cout << "[-] Low RAM size, sign of vm. [+5] (<4)" << std::endl;
			return 0;
		}
		std::cout << "[+] Normal RAM size. (>4)" << std::endl;
		return 0;
	}
	
	void checkScreenRes(){
		int x = GetSystemMetrics(SM_CXSCREEN);
		int y = GetSystemMetrics(SM_CYSCREEN);
		
		int normalScreenRes[] = {1600,900, 1920,1080, 1920,1200, 2560,1440, 3840,2160, 
											1366,768, 1440,900, 1536,864, 0};
											
		bool normal = false;
		for(int i = 0; normalScreenRes[i] != 0; i += 2){
			if(x == normalScreenRes[i] && y == normalScreenRes[i+1]) normal=true;
		}
		
		if(normal){
			std::cout << "[+] Normal screen resolution choice." << std::endl;
			return;
		}
		else{
			score += SMALL_SIGNAL;
			std::cout << "[-] Weird screen resolution choice. [+3]" << std::endl;
			return;
		}
	}	

	int wmiCheckCacheMemory(){
			IWbemClassObject* obj = nullptr;
			ULONG ret = 0;
			BSTR query = SysAllocString(L"Select * from Win32_CacheMemory");
			ret = wmi.Query(query);
			if(!wmi.enumerator) return help.PrintErrorCOM(ret);
			wmi.enumerator->Next(WBEM_INFINITE, 1, &obj, &ret);
			if(obj==nullptr){
					score += SMALL_SIGNAL;
					std::cout << "[-] Win32_CacheMemory returned invalid value, can be a sign of VM. [+3]" << std::endl;
			}
			else{ 
				std::cout << "[+] Win32_CacheMemory returned valid value." << std::endl;
			}
			if(obj) obj->Release();
			if(wmi.enumerator) wmi.enumerator->Release();
			return 0;
		}
		
	int wmiCheckCIMMemory(){
		IWbemClassObject* obj = nullptr;
		ULONG ret = 0;
		BSTR query = SysAllocString(L"Select * from CIM_MEMORY");
		ret = wmi.Query(query);
		if(!wmi.enumerator) return help.PrintErrorCOM(ret);
		wmi.enumerator->Next(WBEM_INFINITE, 1, &obj, &ret);
		if(obj==nullptr){
			score += SMALL_SIGNAL;
			std::cout << "[-] CIM_Memory returned invalid value, can be a sign of VM. [+3]" << std::endl;
		}
		else{
			std::cout << "[+] CIM_Memory returned valid value." << std::endl;
		}
		if(obj) obj->Release();
		if(wmi.enumerator) wmi.enumerator->Release();
		return 0;
	}	
		
	// TIMING CHECKS
		
	void rdtscHeapHandleCheck(){
		ULONGLONG tsc1 = 0;
		ULONGLONG tsc2 = 0;
		ULONGLONG tsc3 = 0;
		bool y = false;
		for(int i = 0; i < 10; i++){
			tsc1 = __rdtsc();
			GetProcessHeap(); // waste cycles, is faster than CloseHandle(0) at any times
			tsc2 = __rdtsc(); // so, tsc1 - tsc2 is how long it took to do GetProcessHeap().
			CloseHandle(0); // waste cycles, should be longer than GetProcessHeap() in bare metal.
			tsc3 = __rdtsc(); // so, tsc3 - tsc2 is how long it took to do CloseHandle(0)
			if(((tsc3 - tsc2) / (tsc2 - tsc1)) < 10){
				y = true;
				continue;
			}
			y = false;
		}
			
		if(y){
			score += MODERATE_SIGNAL;
			std::cout << "[-] HeapHandle check took a too short amount of time. [+5]" << std::endl;
		}
		else{ 
			std::cout << "[+] HeapHandle check took a long amount of time, good." << std::endl; }
			return;
		}
		
	void rdtscCpuidCheck(){
		ULONGLONG tsc1 = 0;
		ULONGLONG tsc2 = 0;
		ULONGLONG average = 0;
		INT cpuInfo[4] = {0};
		for(int i = 0; i < 10; i++){
			tsc1 = __rdtsc();
			__cpuid(cpuInfo, 0); // __cpuid takes longer in a vm.
			tsc2 = __rdtsc();
			average += (tsc2 - tsc1); // get the delta, selisih lah ya. wkwk
		}
		average /= 10;
		if(average < 1000 && average > 0) std::cout << "[+] __cpuid check took a short time. (<1000)" << std::endl;
		else{ 
			score += BIG_SIGNAL;
			std::cout << "[-] __cpuid check took too long. [+10] (>1000)" << std::endl;
		}
	}
	
	// Sandbox check
	
	// EXPERIMENTAL FEATURE: REGISTRY BASED VM DETECTION
	int checkRegistryValue(){
		HKEY key = 0;

		const char* subRegs[] = {
        "HARDWARE\\DEVICEMAP\\SCSI\\SCSI PORT 0\\SCSI BUS 0\\TARGET ID 0\\LOGICAL UNIT ID 0",
        "HARDWARE\\DEVICEMAP\\SCSI\\SCSI PORT 1\\SCSI BUS 0\\TARGET ID 0\\LOGICAL UNIT ID 0",
        "HARDWARE\\DEVICEMAP\\SCSI\\SCSI PORT 2\\SCSI BUS 0\\TARGET ID 0\\LOGICAL UNIT ID 0",
        "HARDWARE\\DESCRIPTION\\SYSTEM",
        "SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SYSTEMINFORMATION",
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        "HARDWARE\\ACPI\\FADT\\VBOX__",
        "HARDWARE\\ACPI\\RSDT\\VBOX__",
        "HARDWARE\\ACPI\\SSDT\\VBOX__",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SYSTEM\\CURRENTCONTROLSET\\Services\\VBoxGuest",
        "SYSTEM\\CURRENTCONTROLSET\\Services\\VBoxMouse",
        "SYSTEM\\CURRENTCONTROLSET\\Services\\VBoxService",
        "SYSTEM\\CURRENTCONTROLSET\\Services\\VBoxWddm",
        nullptr
    };

    int count = 0;

    while(subRegs[count] != nullptr){
        LSTATUS status = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            subRegs[count],
            0,
            KEY_READ,
            &key
        );

        int WHAT_REGCHECK = 0;

        if(count < 3) WHAT_REGCHECK = SCSI_REGCHECK;
        else if(count == 3) WHAT_REGCHECK = SYSTEMDESCRIPTION_REGCHECK;
        else if(count == 4) WHAT_REGCHECK = SYSTEMINFORMATION_REGCHECK;

        if(status == ERROR_SUCCESS){

            // existence-based checks
            if(count > 4){
                score += DETECTED;
                RegCloseKey(key);
                return TRUE;
            }
            if(help.compareToVMRegKeys(key, WHAT_REGCHECK, &score)){
                score += DETECTED;
                RegCloseKey(key);
                return TRUE;
            }
            RegCloseKey(key);
        }

        count++;
    }

    return FALSE;
	}
	public:
		
		void printBanner(){
			 std::cout << R"(   #    #     #    #    #     # #######
  # #   ##    #   # #   ##    #    #   
 #   #  # #   #  #   #  # #   #    #   
#     # #  #  # #     # #  #  #    #   
####### #   # # ####### #   # #    #   
#     # #    ## #     # #    ##    #   
#     # #     # #     # #     #    #   )" << std::endl;
			std::cout << "\n\n============================================================" << std::endl;
			std::cout << "Anti Analysis Tool" << std::endl;
			std::cout << "============================================================\n" << std::endl;
			std::cout << "Created by civ" << std::endl;
			std::cout << "============================================================\n" << std::endl;
			std::cout << "ANANT Alpha Version 1.0" << std::endl;
			std::cout << "============================================================\n\n" << std::endl;
		}
		
		void _runAntiAnalysis(){
			std::cout << "Starting...\n" << std::endl;
			if(md.coreCheck){
				std::cout << "\n=== CORE CHECKS ===\n" << std::endl;
				processScan();
				cpuidCheckOne();
				cpuidCheckTwo();
				checkMACs();
			}
			if(md.debugCheck){
				std::cout << "\n=== DEBUG CHECKS ===\n" << std::endl;
				checkDebugSimple();
				checkHardwareBreakpoints();
			}
			if(md.resourceCheck){
				std::cout << "\n=== RESOURCE CHECKS ===\n" << std::endl;
				smallDiskCheck();
				lowProcessorCount();
				lowRAM();
				checkScreenRes();
				wmi.WMIStart();
				wmiCheckCacheMemory();
				wmiCheckCIMMemory();
				wmi.destroyCOM();
			}
			if(md.timingCheck){
				std::cout << "\n=== TIMING CHECKS ===\n" << std::endl;
				rdtscHeapHandleCheck();
				rdtscCpuidCheck();
			}
			if(md.sandboxCheck){
				std::cout << "\n=== SANDBOX CHECKS ===\n" << std::endl;
			}
			return;
		}
		
		void _evaluate(){
			std::cout << "\n\nEvaluating..." << std::endl;
			std::cout << "[!] Score -> " << score << std::endl;
			if(score <= PERFECT){
				std::cout << "[++] Perfect!" << std::endl;
			}
			else if(score <= HM){
				std::cout << "[+?] Hm..." << std::endl;
			}
			else if(score <= SUSPICOUS){
				std::cout << "[??] Very suspicious..." << std::endl;
			}
			else if(score <= VERY_SUSPICOUS){
				std::cout << "[-?] Suspicous" << std::endl;		
			}
			else if(score <= DETECTED){
				std::cout << "[--] Analysis Detected!" << std::endl;	
			}
		}
	
	void getCheckType() {	
		std::string choice;
		std::cout << "BULID CHECK TYPE:\n(y for yes, enter for skip)";
		std::cout << "\nCore Check? ==> ";
		std::getline(std::cin, choice);
		if(choice == "y") md.coreCheck = true;
		else if(choice == "\n"){}
		std::cout << "\nDebug Check? ==> ";
		std::getline(std::cin, choice);
		if(choice == "y") md.debugCheck = true;
		else if(choice == "\n"){}
		std::cout << "\nResource Check? ==> ";
		std::getline(std::cin, choice);
		if(choice == "y") md.resourceCheck = true;
		else if(choice == "\n"){}
		std::cout << "\nTiming Check? ==> ";
		std::getline(std::cin, choice);
		if(choice == "y") md.timingCheck = true;
		else if(choice == "\n"){}
		std::cout << "\nSandbox Check? ==> ";
		std::getline(std::cin, choice);
		if(choice == "y") md.sandboxCheck = true;
		else if(choice == "\n"){}
	}
};

int main(){
	AntiAnalysis anant;
	anant.printBanner();
	anant.getCheckType();
	anant._runAntiAnalysis();
	anant._evaluate();
	return 0;
}

/* TODO for Alpha v1.1
 * 1. Check software breakpoints (DEBUG)
 * 2. Mouse movement & Recents directory check (SANDBOX)
 * 3. More WMI Checks (RESOURCE)
 * 4. System firmware table check (VM)
 * 5. VM Registry & File artifacts (VM)
 */

