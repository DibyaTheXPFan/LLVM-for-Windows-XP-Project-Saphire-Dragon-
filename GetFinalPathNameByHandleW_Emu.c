//#include <windows.h>
#pragma comment(lib, "kernel32.lib") //
#pragma comment(lib, "ntdll.lib")    //
//#pragma comment(lib, "userenv.lib")    //

#define far
typedef void *PVOID;
typedef unsigned short USHORT;
typedef unsigned short WCHAR;
typedef WCHAR *NWPSTR, *LPWSTR, *PWSTR;
typedef unsigned short WORD;
typedef void *HANDLE;
typedef unsigned char BYTE;
typedef unsigned long ULONG;
typedef unsigned long DWORD;
typedef long LONG;
typedef unsigned long ULONG_PTR, *PULONG_PTR;
typedef long LONG_PTR, *PLONG_PTR;
typedef WCHAR *LPCWSTR, *PCWSTR;
typedef void far *LPVOID;
typedef ULONG *PULONG;
typedef int BOOL;
typedef char CHAR;
typedef CHAR *NPSTR, *LPSTR, *PSTR;
#define LPCSTR LPSTR
typedef DWORD far *LPDWORD;
#define VOID void

#define DECLARE_HANDLE(name)                                                   \
  struct name##__ {                                                            \
    int unused;                                                                \
  };                                                                           \
  typedef struct name##__ *name
DECLARE_HANDLE(HINSTANCE);
typedef HINSTANCE HMODULE; 

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#define FAR far
typedef int(FAR __stdcall *FARPROC)();

__declspec(dllimport) HMODULE
    __stdcall LoadLibraryW(LPCWSTR lpLibFileName);

__declspec(dllimport) HMODULE
    __stdcall 
    GetModuleHandleW(LPCWSTR lpModuleName);

__declspec(dllimport)
FARPROC
    __stdcall GetProcAddress(HMODULE hModule, LPCSTR lpProcName);


DWORD(__stdcall *GetFinalPathNameByHandleW_var)
(HANDLE hFile, 
LPWSTR lpszFilePath, 
DWORD cchFilePath,
DWORD dwFlags) = 0x00000000;

HMODULE hModule_kernelbase_GetFinalPathNameByHandleW_Switch =
    0x00000000; // own var for independency

__declspec(noinline)
DWORD
__stdcall GetFinalPathNameByHandleWX(HANDLE hFile, 
LPWSTR lpszFilePath, 
DWORD cchFilePath,
DWORD dwFlags) 
{
  if (GetFinalPathNameByHandleW_var) 
  {
    return GetFinalPathNameByHandleW_var(hFile, lpszFilePath, cchFilePath, dwFlags);
  }

  hModule_kernelbase_GetFinalPathNameByHandleW_Switch = LoadLibraryW(L"llvmxp.dll");

  GetFinalPathNameByHandleW_var = (DWORD(__stdcall *)(HANDLE, LPWSTR, DWORD, DWORD))GetProcAddress(hModule_kernelbase_GetFinalPathNameByHandleW_Switch, "GetFinalPathNameByHandleWX");

  if (!hModule_kernelbase_GetFinalPathNameByHandleW_Switch) 
  {
    hModule_kernelbase_GetFinalPathNameByHandleW_Switch = GetModuleHandleW(L"llvmxp.dll");
    GetFinalPathNameByHandleW_var = (DWORD(__stdcall *)(HANDLE, LPWSTR, DWORD, DWORD))GetProcAddress(hModule_kernelbase_GetFinalPathNameByHandleW_Switch, "GetFinalPathNameByHandleWX");
  }

  if (GetFinalPathNameByHandleW_var) 
  {
    return GetFinalPathNameByHandleW_var(hFile, lpszFilePath, cchFilePath, dwFlags);
  }

  return FALSE;
}