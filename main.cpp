/* CLARIFICATION

	RESEARCH CODE
 
	CREATED BY civ

*/ 

#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN
#define _WIN32_DCOM

#define DISK_THRESHOLD 60 // default for vms
#define PROCESSOR_THRESHOLD 4 // for vms
#define RAM_THRESHOLD_GB 4.0 // for vms

#include <winsock2.h> // mac check
#include <windows.h> // debug check, // ram check
#include <iphlpapi.h> // mac check
#include <ws2tcpip.h>
#include <tlhelp32.h> // ProcessScan()
#include <iostream>
#include <intrin.h> // __cpuid
#include <string.h>
#include <objbase.h> // wmi
#include <wbemidl.h> // IWbem*
#include <comdef.h>
#include <shlobj.h> // Recents probing
#include <knownfolders.h> // known folders
#include <shlguid.h> //guid definitions


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
#define GIANT_SIGNAL 15
#define DETECTED 20

#define PERFECT 0
#define HM 5
#define SUSPICOUS 10
#define VERY_SUSPICOUS 15
#define DEFINITELY 20

struct Conf{
	bool vmCheck=false;
	bool debugCheck=false;
	bool resourceCheck=false;
	bool timingCheck=false;
	bool sandboxCheck=false;
	bool verbose=true;
	int score=0;
};

namespace Utils{
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
	
	void printReadableTypeCheck(Conf conf){
		std::cout << "The selected type check is: " << std::endl;
		if(conf.vmCheck) std::cout << "VM + " << std::endl;
		if(conf.debugCheck) std::cout << "DEBUG + " << std::endl;
		if(conf.resourceCheck) std::cout << "RESOURCE + " << std::endl;
		if(conf.timingCheck) std::cout << "TIMING +" << std::endl;
		if(conf.sandboxCheck) std::cout << "SANDBOX +" << std::endl;
	}
	
	void getCheckType(Conf* conf) {	
		if(!conf->verbose){
			// default to all checks
			conf->vmCheck = true;
			conf->debugCheck = true;
			conf->resourceCheck = true;
			conf->timingCheck = true;
			conf->sandboxCheck = true;
			return;
		}
		
		std::string choice;
		std::cout << "BULID CHECK TYPE:\n(y for yes, enter for skip)";
		
		std::cout << "\nVM Check? ==> ";
		std::getline(std::cin, choice);
		if(choice == "y") conf->vmCheck = true;
		else if(choice == "\n"){}
		
		std::cout << "\nDebug Check? ==> ";
		std::getline(std::cin, choice);
		if(choice == "y") conf->debugCheck = true;
		else if(choice == "\n"){}
		
		std::cout << "\nResource Check? ==> ";
		std::getline(std::cin, choice);
		if(choice == "y") conf->resourceCheck = true;
		else if(choice == "\n"){}
		
		std::cout << "\nTiming Check? ==> ";
		std::getline(std::cin, choice);
		if(choice == "y") conf->timingCheck = true;
		else if(choice == "\n"){}
		
		std::cout << "\nSandbox Check? ==> ";
		std::getline(std::cin, choice);
		if(choice == "y") conf->sandboxCheck = true;
		else if(choice == "\n"){}
		
		printReadableTypeCheck(*conf);
		
		if(conf->verbose) std::cout << "\n[NOTICE] Verbose Mode is ON\n" << std::endl;
	}
	
	void note(Conf* conf, const char* failMsg, const char* successMsg, bool detected, int signalWeight){
		if(detected && conf->verbose){
			std::cout << "[-] " << successMsg << "	[+" << std::to_string(signalWeight) << "]" << std::endl;
		}
		else if(!detected && conf->verbose){
			std::cout << "[+] " << failMsg << std::endl;
		}
		if(detected) conf->score += signalWeight;
	}
	
	namespace WMI{
		IWbemLocator* ptrLoc = nullptr;
		IWbemServices* ptrProxy = nullptr;
		IEnumWbemClassObject* enumerator = nullptr;
		bool init = false;
		
		HRESULT WMIStart(){
			HRESULT res = 0;
			res = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
			if(FAILED(res)) return Utils::PrintErrorCOM(res);
			res = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, 
				 RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
			
			if(FAILED(res)) return Utils::PrintErrorCOM(res);
			res = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, 
				 IID_IWbemLocator, (LPVOID*)&ptrLoc);
				 
			if(FAILED(res)) return Utils::PrintErrorCOM(res);
		
			BSTR path = SysAllocString(L"ROOT\\CIMV2");
	
			res = ptrLoc->ConnectServer(path, nullptr, nullptr, 0, 0, 0, 0, &ptrProxy);
			if(FAILED(res)){
				SysFreeString(path);
				return Utils::PrintErrorCOM(res);
			}
			SysFreeString(path);
		
			res = CoSetProxyBlanket(ptrProxy, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
				 RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
			if(FAILED(res)) return Utils::PrintErrorCOM(res);
			
			init = true;
			return TRUE;
		}
	
		HRESULT Query(BSTR query){
			BSTR wql = SysAllocString(L"WQL");
			HRESULT res = 0;
			// asumming enumerator is freed.
			res = ptrProxy->ExecQuery(wql, query, WBEM_FLAG_FORWARD_ONLY, 
				 nullptr, &enumerator);

			SysFreeString(wql);
				   
			if(FAILED(res)) return Utils::PrintErrorCOM(res);
	
			return 0;
		}
	
		void destroyCOM(){
			if(ptrProxy) ptrProxy->Release();
			if(ptrLoc) ptrLoc->Release();
			if(enumerator) enumerator->Release();
			CoUninitialize();
		}
	};
	
};

namespace AntiVMChecks{
	
	// ANTI VM CHECKS
	int checkMACs(Conf* conf){
			IP_ADAPTER_ADDRESSES* macs = nullptr;
			static const BYTE hyperV1[3] = {0x0, 0x1D, 0xD8}; // 00:1D:D8
			static const BYTE hyperV2[3] = {0x0, 0x15, 0x5D}; // 00:15:5D
			static const BYTE vmware[3] = {0x0, 0x50, 0x56}; // 00:50:56
			static const BYTE vmware2[3] = {0x0, 0x0C, 0x29}; // 00:0C:29
			static const BYTE vmware3[3] = {0x0, 0x1C, 0x14}; // 00:1C:14 
			static const BYTE vmware4[3] = {0x0, 0x05, 0x69}; // 00:05:69
			static const BYTE virtualbox[3] = {0x08, 0x0, 0x27}; // 08:00:27
			static const BYTE kvm[3] = {0x54, 0x52, 0x0}; // 54:52:00
			static const BYTE xen[3] = {0x0, 0x16, 0x3E}; // 00:16:3E
			static const BYTE* linked[] = {hyperV1, hyperV2, vmware, vmware2, vmware3, vmware4, virtualbox, kvm, xen, nullptr, };
			bool caught = false;
			ULONG len = sizeof(IP_ADAPTER_ADDRESSES);
			macs = (IP_ADAPTER_ADDRESSES *)malloc(len); // allocate 1 IP_ADAPTER_ADDRESSES
			int res = 0;
			res = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
			nullptr, macs, &len
			);
			
			do{
				free(macs);
				macs = (IP_ADAPTER_ADDRESSES *)malloc(len);
				if(macs==nullptr) return Utils::PrintError();
				res = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
				nullptr, macs, &len);
				if(res != ERROR_BUFFER_OVERFLOW && res != NO_ERROR){
					free(macs);
					return Utils::PrintError();
			}
		} while(res == ERROR_BUFFER_OVERFLOW);	
				
		IP_ADAPTER_ADDRESSES* currMac = macs;
				
		while(currMac){
			if(currMac->PhysicalAddressLength == 6){
			for(int i = 0; linked[i]; i++){
				if(currMac->PhysicalAddress[0] == linked[i][0] && currMac->PhysicalAddress[1] == linked[i][1]
					&& currMac->PhysicalAddress[2] == linked[i][2]){
					caught = true;
					break;
					}
			}
		}
		currMac = currMac->Next;
		}
		free(macs);
		Utils::note(conf, "No VM Mac OUI Detected.", "VM Mac OUI Detected.", caught, BIG_SIGNAL);
		return TRUE;
	}

	int processScan(Conf* conf){		
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
		int whichDetectedProcesses[sizeof(suspicousProcesses)/sizeof(LPCSTR)] = {0};
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if(snapshot == INVALID_HANDLE_VALUE) return Utils::PrintError();
		processEntry.dwSize = sizeof(PROCESSENTRY32);
		if(Process32First(snapshot, &processEntry)){
			do{		
				int i = 0;			
				while(i < int(sizeof(suspicousProcesses) / sizeof(LPCSTR))){ // to remove the warnings
					if(!lstrcmpi(processEntry.szExeFile, suspicousProcesses[i])){
						myScore += BIG_SIGNAL;
						whichDetectedProcesses[i] = TRUE;
						detectedProcessCount++;
					}	
					i++;
				} 
			} while(Process32Next(snapshot, &processEntry));
		}
		else{
			CloseHandle(snapshot);
			return Utils::PrintError(); 
		}
		CloseHandle(snapshot);
		bool caught = (detectedProcessCount != 0);
		Utils::note(conf, "No suspicous processes detected.", "Suspicous processes detected", caught, myScore);
		if(caught && conf->verbose){
			std::cout << "[-] Found processes such as: " << std::endl;
			for(int i = 0; i < int(sizeof(suspicousProcesses)/sizeof(LPCSTR)); i++){
				if(whichDetectedProcesses[i]){
					std::cout << "[-] " << suspicousProcesses[i] << std::endl;
				}
			}
		}
		return TRUE;
	}	
	
	void cpuidVendorCheck(Conf* conf){
		int cpuInfo[4] = {0};
		__cpuid(cpuInfo, 0x40000000);
		bool caught = false;
		for(int i = 1; i < 4; i++){
			if(cpuInfo[i] != 0) caught = true;
		}
		Utils::note(conf, "No CPUID Hypervisor vendor name detected", "CPUID Hypervisor vendor name detected" , caught, DETECTED);	
		if(caught){
			char vendor[13] = {0};
			memcpy(vendor, &cpuInfo[1], 4);
			memcpy(vendor, &cpuInfo[2], 4);
			memcpy(vendor, &cpuInfo[3], 4);
			std::cout << "[Vendor: " << vendor << "]" << std::endl;
		}
		return;
	}
	
	void cpuidHypervisorBitCheck(Conf* conf){
		int cpuInfo[4] = {0};
		__cpuid(cpuInfo, 1);
		bool caught = false;
		if(cpuInfo[2] >> 31 & 1) caught = true;
		Utils::note(conf, "CPUID Hypervisor Bit in ECX is not set", "CPUID Hypervisor Bit in ECX set.", caught, DETECTED);
		return;
	}
};

namespace AntiDebugChecks{
	int checkDebugSimple(Conf* conf){
		BOOL dbg = FALSE;
		bool caught = false;
		if(IsDebuggerPresent() != 0){
			caught = true;
		}
		if(!CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg)) return Utils::PrintError();
		if(dbg){
			caught = true;
		}
		Utils::note(conf, "No debugger detected with CheckRemoteDebuggerPresent and present IsDebuggerPresent.", "Debugger detected with CheckRemoteDebuggerPresent and present IsDebuggerPresent.",
				caught, DETECTED);
		return TRUE;
	}
	
	int checkHardwareBreakpoints(Conf* conf){
		bool caught = false;
		PCONTEXT ctx = PCONTEXT(VirtualAlloc(nullptr, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE));
		if(!ctx) return Utils::PrintError();
		
		if(SecureZeroMemory(ctx, sizeof(CONTEXT)) == nullptr){
			VirtualFree(ctx, 0, MEM_RELEASE);
			return Utils::PrintError();
		}
		
		ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;
		
		if(GetThreadContext(GetCurrentThread(), ctx)){
			if(ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0) caught = true;
			Utils::note(conf, "No Debug register value / hardware breakpoint detected.", "Debug register nonzero / hardware breakpoint detected.",
					caught, DETECTED);
			VirtualFree(ctx, 0, MEM_RELEASE);
			return TRUE;
		}
		return FALSE;
	}
	
	void checkPEBBeingDebugged(Conf* conf){
		bool caught = false;
		uintptr_t PEB;
		__asm__ volatile(
			"movq %%gs:0x60, %0"
			:"=r"(PEB)
			:
			:
		);
		
		unsigned char beingDebugged = *(unsigned char*)(PEB + 0x02);
		
		if(beingDebugged) caught = true;
		Utils::note(conf, "BeingDebugged flag is not set in PEB block", "BeingDebugged flag is set in PEB block", caught, DETECTED);
		return;
		
	}
};

namespace ResourcesChecks{
	int smallDiskCheck(Conf* conf){
		bool caught = false;
		ULARGE_INTEGER totalBytes;
		totalBytes.QuadPart = 0;
		if(!GetDiskFreeSpaceExA("\\\\?\\c:\\", nullptr,  &totalBytes, nullptr)) return Utils::PrintError();
		ULONGLONG diskSize = totalBytes.QuadPart / 1024 / 1024 / 1024;
		if(diskSize <= DISK_THRESHOLD ) caught = true;
		Utils::note(conf, "Normal disk size. (>50)", "Small disk size. (<=50)", caught, MODERATE_SIGNAL);
		if(conf->verbose) std::cout << "[" << diskSize << "GB]" << std::endl;
		return TRUE;
	}
		
	void lowProcessorCount(Conf* conf){
		bool caught = false;
		SYSTEM_INFO sysInfo = {0};
		GetSystemInfo(&sysInfo);
		if(sysInfo.dwNumberOfProcessors <= PROCESSOR_THRESHOLD) caught = true;
		Utils::note(conf,"Normal processor count. (>4)","Low processor count. (<=4)", caught, MODERATE_SIGNAL);
		if(conf->verbose) std::cout << "[" << sysInfo.dwNumberOfProcessors << "]" << std::endl;
		return;
	}
		
	int lowRAM(Conf* conf){
		bool caught = false;
		MEMORYSTATUSEX totalMem;
		totalMem.dwLength = sizeof(MEMORYSTATUSEX);
		if(GlobalMemoryStatusEx(&totalMem) == 0) return Utils::PrintError();
		double gbRAMTotal = (double)totalMem.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
		if(gbRAMTotal <= RAM_THRESHOLD_GB) caught = true;
		Utils::note(conf, "Normal RAM size. (>=4GB)", "Low RAM size. (<4GB)", caught, MODERATE_SIGNAL);
		if(conf->verbose) std::cout << "[" << (int)gbRAMTotal << "GB]" << std::endl;
		return TRUE;
	}
	
	void checkScreenRes(Conf* conf){
		int x = GetSystemMetrics(SM_CXSCREEN);
		int y = GetSystemMetrics(SM_CYSCREEN);
		bool caught = true;
		int normalScreenRes[] = {1600,900, 1920,1080, 1920,1200, 2560,1440, 3840,2160, 
											1366,768, 1440,900, 1536,864, 0};						
		for(int i = 0; normalScreenRes[i] != 0; i += 2){
			if(x == normalScreenRes[i] && y == normalScreenRes[i+1]) caught=false;
		}
		Utils::note(conf, "Normal screen resolution choice.", "Weird screen resolution choice.", caught, SMALL_SIGNAL);
		if(conf->verbose) std::cout << "[" << x << "x" << y << "]" << std::endl;
	}	

	int wmiCheckCacheMemory(Conf* conf){
		if(Utils::WMI::init == false) return FALSE;
		bool caught = false;
		IWbemClassObject* obj = nullptr;
		ULONG ret = 0;
		BSTR query = SysAllocString(L"Select * from Win32_CacheMemory");
		ret = Utils::WMI::Query(query);
		if(!Utils::WMI::enumerator){
			SysFreeString(query);
			return Utils::PrintErrorCOM(ret);
		}	
		Utils::WMI::enumerator->Next(WBEM_INFINITE, 1, &obj, &ret);
		if(obj==nullptr) caught = true;
		Utils::note(conf, "Win32_CacheMemory returned valid value.", "Win32_CacheMemory returned invalid value", caught, SMALL_SIGNAL);
		if(obj) obj->Release();
		if(Utils::WMI::enumerator) Utils::WMI::enumerator->Release();
		SysFreeString(query);
		return TRUE;
	}
		
	int wmiCheckCIMMemory(Conf* conf){
		if(Utils::WMI::init == false) return FALSE;
		bool caught = false;
		IWbemClassObject* obj = nullptr;
		ULONG ret = 0;
		BSTR query = SysAllocString(L"Select * from CIM_MEMORY");
		ret = Utils::WMI::Query(query);
		if(!Utils::WMI::enumerator){
			SysFreeString(query);
			return Utils::PrintErrorCOM(ret);
		}
		Utils::WMI::enumerator->Next(WBEM_INFINITE, 1, &obj, &ret);
		if(obj==nullptr) caught = true;
		Utils::note(conf, "CIM_Memory returned valid value.", "CIM_Memory returned invalid value", caught, SMALL_SIGNAL);
		if(obj) obj->Release();
		if(Utils::WMI::enumerator) Utils::WMI::enumerator->Release();
		SysFreeString(query);
		return TRUE;
	}	
};

namespace SandboxChecks{
	int checkRecentsFolder(Conf* conf){
		int filesCount = 0;
		int res = 0;
		PWSTR recentsPath = nullptr;
		res = SHGetKnownFolderPath(FOLDERID_Recent, 0, nullptr, &recentsPath);
		bool caught = false;
		if(FAILED(res)){
			if(recentsPath) CoTaskMemFree(recentsPath);
			return Utils::PrintErrorCOM(res);
		}
		std::wstring searchPath = std::wstring(recentsPath) + L"\\*";

        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
        
        if(hFind != INVALID_HANDLE_VALUE){
			do{
				if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    filesCount++;
                }
			} while(FindNextFileW(hFind, &fd));
			FindClose(hFind);
		}
		else{
			CoTaskMemFree(recentsPath);
			return Utils::PrintErrorCOM(res); 
		}
		CoTaskMemFree(recentsPath);
        if(filesCount < 10) caught = true;
        Utils::note(conf, "More than 10 files detected in Recents folder.", "Less than 10 files detected in Recents folder.", caught, BIG_SIGNAL);
        if(conf->verbose) std::cout << "[Found " << filesCount << " files]" << std::endl;
        return TRUE;
	}
};

namespace TimingChecks{
	void rdtscCpuidCheck(Conf* conf){
		ULONGLONG tsc1 = 0;
		ULONGLONG tsc2 = 0;
		ULONGLONG average = 0;
		INT cpuInfo[4] = {0};
		bool caught = false;
		for(int i = 0; i < 10; i++){
			tsc1 = __rdtsc();
			__cpuid(cpuInfo, 0); // __cpuid takes longer in a vm.
			tsc2 = __rdtsc();
			average += (tsc2 - tsc1); // get the delta.
		}
		average /= 10;
		if(average < 1000 && average > 0) caught = false;
		else{ caught = true; }
		Utils::note(conf, "__cpuid check took a short time. (<1000)", "__cpuid check took too long. (>1000)", 
		caught, BIG_SIGNAL);
		if(conf->verbose) std::cout << "[Average " << average << " cycles]" << std::endl;
	}
};

class AntiAnalysisMain{
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
	
	Conf conf;
	public:
	void startNow(){
		if(conf.verbose) printBanner();
		Utils::getCheckType(&conf);
		if(conf.vmCheck == 0 && conf.debugCheck == 0 && conf.resourceCheck == 0 
		   && conf.timingCheck == 0 && conf.sandboxCheck == 0){
			if(conf.verbose) std::cout << "Please put atleast one check." << std::endl;
			ExitProcess(-1);
		}
		if(conf.vmCheck){
			if(conf.verbose) std::cout << "\n === ANTI VM CHECK ===" << std::endl;
			AntiVMChecks::processScan(&conf);
			AntiVMChecks::checkMACs(&conf);
			AntiVMChecks::cpuidVendorCheck(&conf);
			AntiVMChecks::cpuidHypervisorBitCheck(&conf);
		}
		if(conf.debugCheck){
			if(conf.verbose) std::cout << "\n === ANTI DEBUG CHECK ===" << std::endl;
			AntiDebugChecks::checkDebugSimple(&conf);
			AntiDebugChecks::checkHardwareBreakpoints(&conf);
			AntiDebugChecks::checkPEBBeingDebugged(&conf);
		}
		if(conf.resourceCheck){
			if(conf.verbose) std::cout << "\n === RESOURCES CHECK ===" << std::endl;
			Utils::WMI::WMIStart();
			ResourcesChecks::smallDiskCheck(&conf);
			ResourcesChecks::lowRAM(&conf);
			ResourcesChecks::lowProcessorCount(&conf);
			ResourcesChecks::checkScreenRes(&conf);
			ResourcesChecks::wmiCheckCacheMemory(&conf);
			ResourcesChecks::wmiCheckCIMMemory(&conf);
			Utils::WMI::destroyCOM();
		}
		if(conf.timingCheck){
			if(conf.verbose) std::cout << "\n === TIMING CHECK ===" << std::endl;
			TimingChecks::rdtscCpuidCheck(&conf);
		}
		if(conf.sandboxCheck){
			if(conf.verbose) std::cout << "\n === SANDBOX CHECK ===" << std::endl;
			SandboxChecks::checkRecentsFolder(&conf);
		}
		
		if(conf.verbose){
			std::cout << "\n\nEvaluating..." << std::endl;
			std::cout << "[!] Score -> " << conf.score << std::endl;
		
			if(conf.score == PERFECT){
					std::cout << "[+] Perfect!" << std::endl;
			}
			else if(conf.score <= HM){
					std::cout << "[?] Hm.." << std::endl;
			}
			else if(conf.score <= SUSPICOUS){
				std::cout << "[-] Suspicious." << std::endl;		
			}
			else if(conf.score <= VERY_SUSPICOUS){
				std::cout << "[?] Very Suspicious." << std::endl;
			}
			else if(conf.score <= DETECTED){
				std::cout << "[!] Analysis Detected!" << std::endl;	
			}
			else{
				std::cout << "[!!] ANALYSIS VERY DETECTED!! (did you even try)" << std::endl;
			}
		}
		else{
			if(conf.score == DETECTED){
				std::cout << "FAKE BEHAVIOR GOES HERE" << std::endl;
				return;
			}
			else{ 
				std::cout << "REAL BEHAVIOR GOES HERE" << std::endl;
				return; 
			}
		}
		std::cin.get();
		return;
	}
};
	
int main(){
	AntiAnalysisMain anant;
	anant.startNow();
	return 0;
}

