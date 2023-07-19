#include <iostream>
#include <Windows.h>
#include <vector>

#pragma comment(lib, "Version.lib")

#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

typedef LONG NTSTATUS, *PNTSTATUS;
#define STATUS_SUCCESS (0x00000000)

typedef NTSTATUS (WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOEXW);

void GetRealOSVersion() {
    HMODULE hMod = ::GetModuleHandleW(L"ntdll.dll");
    if (hMod) {
        auto fxPtr = (RtlGetVersionPtr) ::GetProcAddress(hMod, "RtlGetVersion");
        if (fxPtr != nullptr) {
            RTL_OSVERSIONINFOEXW osvi = {0};
            osvi.dwOSVersionInfoSize = sizeof(osvi);
            if (STATUS_SUCCESS == fxPtr(&osvi)) {
                // Print the OS version details
                std::cout << "Operating System Version: " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion
                          << std::endl;
                std::cout << "Build Number: " << osvi.dwBuildNumber << std::endl;
                std::cout << "Service Pack: " << osvi.szCSDVersion << std::endl;
                std::cout << "Service Pack Major: " << osvi.wServicePackMajor << std::endl;
                std::cout << "Service Pack Minor: " << osvi.wServicePackMinor << std::endl;
                return;
            }
        }
    }

    std::cout << "Failed to call RtlGetVersion" << std::endl;
}

#include <LM.h>

#pragma comment(lib, "netapi32.lib")

void GetWithNetServer() {

    LPSERVER_INFO_101 pServerInfo = nullptr;

    DWORD dwResult;
    NET_API_STATUS nStatus = NetServerGetInfo(nullptr, 101, (LPBYTE *) &pServerInfo);
    if (nStatus == NERR_Success) {
        std::cout << "Server Name: " << pServerInfo->sv101_name << std::endl;
        std::cout << "Platform ID: " << pServerInfo->sv101_platform_id << std::endl;
        std::cout << "Version Major: " << pServerInfo->sv101_version_major << std::endl;
        std::cout << "Version Minor: " << pServerInfo->sv101_version_minor << std::endl;
    } else {
        std::cout << "Error: " << nStatus << std::endl;
    }

    if (pServerInfo != nullptr) {
        NetApiBufferFree(pServerInfo);
    }
}

void GetWithProductInfo() {
    DWORD majorVersion = 6;
    DWORD minorVersion = 0;
    DWORD buildNumber = 0;
    DWORD platformId = 0;

    if (GetProductInfo(
            majorVersion, minorVersion, buildNumber, 0, &platformId)) {
        std::wcout << L"Operating System Version: " << majorVersion << L"." << minorVersion << std::endl;
        std::wcout << L"Build Number: " << buildNumber << std::endl;
        std::wcout << L"Platform ID: " << platformId << std::endl;

        if (platformId == VER_PLATFORM_WIN32_NT) {
            // Additional information for Windows NT-based systems
            DWORD servicePackMajor = 0;
            DWORD servicePackMinor = 0;

            if (GetProductInfo(
                    majorVersion, minorVersion, buildNumber, 0, nullptr)) {
                std::wcout << L"Service Pack Major: " << servicePackMajor << std::endl;
                std::wcout << L"Service Pack Minor: " << servicePackMinor << std::endl;
            } else {
                std::cout << "Failed to get service pack information." << std::endl;
            }
        }
    } else {
        std::cout << "Failed to get OS version information." << std::endl;
    }
}

// Function to retrieve the operating system version
void GetOSVersion() {
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (!GetVersionExA(reinterpret_cast<LPOSVERSIONINFOA>(&osvi))) {
        // Handle error if GetVersionEx fails
        std::cerr << "Failed to retrieve OS version" << std::endl;
        return;
    }

    // Print the OS version details
    std::cout << "Operating System Version: " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion << std::endl;
    std::cout << "Build Number: " << osvi.dwBuildNumber << std::endl;
    std::cout << "Service Pack: " << osvi.szCSDVersion << std::endl;
    std::cout << "Service Pack Major: " << osvi.wServicePackMajor << std::endl;
    std::cout << "Service Pack Minor: " << osvi.wServicePackMinor << std::endl;
}

// Function to retrieve the operating system version using WMI
void GetOSVersionFromWMI() {
    HRESULT hres;

    // Initialize COM
    hres = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM" << std::endl;
        return;
    }

    // Initialize security for COM
    hres = CoInitializeSecurity(
            nullptr,
            -1,
            nullptr,
            nullptr,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE,
            nullptr);
    if (FAILED(hres)) {
        CoUninitialize();
        std::cerr << "Failed to initialize security" << std::endl;
        return;
    }

    IWbemLocator *pLoc = nullptr;
    hres = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            reinterpret_cast<LPVOID *>(&pLoc));
    if (FAILED(hres)) {
        CoUninitialize();
        std::cerr << "Failed to create IWbemLocator object" << std::endl;
        return;
    }

    IWbemServices *pSvc = nullptr;
    hres = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),
            nullptr,
            nullptr,
            nullptr,
            0,
            nullptr,
            nullptr,
            &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        std::cerr << "Failed to connect to WMI" << std::endl;
        return;
    }

    hres = CoSetProxyBlanket(
            pSvc,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            nullptr,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        std::cerr << "Failed to set proxy blanket" << std::endl;
        return;
    }

    IEnumWbemClassObject *pEnumerator = nullptr;
    hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM Win32_OperatingSystem"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr,
            &pEnumerator);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        std::cerr << "Failed to execute WMI query" << std::endl;
        return;
    }

    IWbemClassObject *pclsObj = nullptr;
    ULONG uReturn = 0;

    // Retrieve the data from the query
    while (pEnumerator) {
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (uReturn == 0) {
            break;
        }

        VARIANT vtProp;
        VariantInit(&vtProp);

        // Retrieve the properties
        hres = pclsObj->Get(L"Caption", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres)) {
            std::wstring caption(vtProp.bstrVal);
            std::wcout << "Operating System: " << caption << std::endl;
        }
        VariantClear(&vtProp);

        hres = pclsObj->Get(L"Version", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres)) {
            std::wstring version(vtProp.bstrVal);
            std::wcout << "Version: " << version << std::endl;
        }
        VariantClear(&vtProp);

        hres = pclsObj->Get(L"BuildNumber", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres)) {
            std::wstring buildNumber(vtProp.bstrVal);
            std::wcout << "Build Number: " << buildNumber << std::endl;
        }
        VariantClear(&vtProp);

        hres = pclsObj->Get(L"CSDVersion", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres) && vtProp.vt != VT_NULL) {
            std::wstring servicePack(vtProp.bstrVal);
            std::wcout << "Service Pack: " << servicePack << std::endl;
        }
        VariantClear(&vtProp);

        pclsObj->Release();
    }

    // Cleanup
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();
}

void GetWithKernel32() {
    DWORD dwHandle;
    DWORD dwSize = GetFileVersionInfoSizeW(L"kernel32.dll", &dwHandle);
    if (dwSize == 0) {
        std::cerr << "Failed to retrieve file version information size." << std::endl;
        return;
    }

    std::vector<BYTE> buffer(dwSize);
    if (!GetFileVersionInfoW(L"kernel32.dll", dwHandle, dwSize, buffer.data())) {
        std::cerr << "Failed to retrieve file version information." << std::endl;
        return;
    }

    VS_FIXEDFILEINFO *pFileInfo;
    UINT uLen;
    if (!VerQueryValueW(buffer.data(), L"\\", reinterpret_cast<LPVOID *>(&pFileInfo), &uLen)) {
        std::cerr << "Failed to retrieve version information from the buffer." << std::endl;
        return;
    }

    DWORD dwMajorVersion = HIWORD(pFileInfo->dwProductVersionMS);
    DWORD dwMinorVersion = LOWORD(pFileInfo->dwProductVersionMS);
    DWORD dwBuildNumber = HIWORD(pFileInfo->dwProductVersionLS);
    DWORD dwRevisionNumber = LOWORD(pFileInfo->dwProductVersionLS);

    std::cout << "Operating System Version: " << dwMajorVersion << "." << dwMinorVersion << std::endl;
    std::cout << "Build Number: " << dwBuildNumber << std::endl;
    std::cout << "Revision Number: " << dwRevisionNumber<< std::endl;
    std::cout << std::endl;
}

int main() {

    std::cout << "Kernel32 variant:" << std::endl;
    GetWithKernel32();
    std::cout << std::endl;

    std::cout << "GetVersionEx variant:" << std::endl;
    GetOSVersion();
    std::cout << std::endl;

    std::cout << "RtlGetVersion variant:" << std::endl;
    GetRealOSVersion();
    std::cout << std::endl;

    std::cout << "WMI variant:" << std::endl;
    GetOSVersionFromWMI();
    std::cout << std::endl;

    std::cout << "GetProductInfo variant:" << std::endl;
    GetWithProductInfo();
    std::cout << std::endl;

    std::cout << "GetNetServer variant:" << std::endl;
    GetWithNetServer();
    std::cout << std::endl;

    return 0;
}