//
// GetFinalPathNameByHandleW_Emu Begin
// NtQueryInformationFile begin
// vars begin
//#include <windows.h>


typedef struct _OVERLAPPED_01 {
  unsigned long Internal_01;
  unsigned long InternalHigh_01;
  union {
    struct {
      unsigned long Offset_01;
      unsigned long OffsetHigh_01;
    } DUMMYSTRUCTNAME_01;
    unsigned long Pointer_01;
  } DUMMYUNIONNAME_01;

  unsigned long hEvent_01;
} OVERLAPPED_01, *LPOVERLAPPED_01;


#define INVALID_HANDLE_VALUE_01 ((long)-1)
#define ERROR_INVALID_PARAMETER_01 87L // dderror

#define FILE_SHARE_READ_01 0x00000001
#define FILE_SHARE_WRITE_01 0x00000002
#define FILE_SHARE_DELETE_01 0x00000004
#define OPEN_EXISTING_01 3
#define FILE_ATTRIBUTE_NORMAL_01 0x00000080



typedef struct _UNICODE_STRING_01 {
  unsigned short Length;
  unsigned short MaximumLength;
  unsigned short * Buffer;
} UNICODE_STRING_01;
typedef UNICODE_STRING_01 *PUNICODE_STRING_01;
typedef const UNICODE_STRING_01 *PCUNICODE_STRING_01;


typedef struct _IO_STATUS_BLOCK_01 {
#pragma warning(push)
#pragma warning(disable : 4201) // we'll always use the Microsoft compiler
  union {
    long Status_01;
    unsigned long Pointer_01;
  } DUMMYUNIONNAME_01;
#pragma warning(pop)
  unsigned long Information_01;
} IO_STATUS_BLOCK_01, *PIO_STATUS_BLOCK_01;


  typedef enum _OBJECT_INFORMATION_CLASS_01 {
  ObjectBasicInformation_01,
  ObjectNameInformation_01,
  ObjectTypeInformation_01,
  ObjectAllTypesInformation_01,
  ObjectHandleInformation_01
} OBJECT_INFORMATION_CLASS_01,
    *POBJECT_INFORMATION_CLASS_01;

typedef enum _FILE_INFORMATION_CLASS_01 {
  FileDirectoryInformation_01 = 1,
  FileFullDirectoryInformation_01,
  FileBothDirectoryInformation_01,
  FileBasicInformation_01,
  FileStandardInformation_01,
  FileInternalInformation_01,
  FileEaInformation_01,
  FileAccessInformation_01,
  FileNameInformation_01,
  FileRenameInformation_01,
  FileLinkInformation_01,
  FileNamesInformation_01,
  FileDispositionInformation_01,
  FilePositionInformation_01,
  FileFullEaInformation_01,
  FileModeInformation_01,
  FileAlignmentInformation_01,
  FileAllInformation_01,
  FileAllocationInformation_01,
  FileEndOfFileInformation_01,
  FileAlternateNameInformation_01,
  FileStreamInformation_01,
  FilePipeInformation_01,
  FilePipeLocalInformation_01,
  FilePipeRemoteInformation_01,
  FileMailslotQueryInformation_01,
  FileMailslotSetInformation_01,
  FileCompressionInformation_01,
  FileObjectIdInformation_01,
  FileCompletionInformation_01,
  FileMoveClusterInformation_01,
  FileQuotaInformation_01,
  FileReparsePointInformation_01,
  FileNetworkOpenInformation_01,
  FileAttributeTagInformation_01,
  FileTrackingInformation_01,
  FileIdBothDirectoryInformation_01,
  FileIdFullDirectoryInformation_01,
  FileValidDataLengthInformation_01,
  FileShortNameInformation_01,
  FileIoCompletionNotificationInformation_01,
  FileIoStatusBlockRangeInformation_01,
  FileIoPriorityHintInformation_01,
  FileSfioReserveInformation_01,
  FileSfioVolumeInformation_01,
  FileHardLinkInformation_01,
  FileProcessIdsUsingFileInformation_01,
  FileNormalizedNameInformation_01,
  FileNetworkPhysicalNameInformation_01,
  FileIdGlobalTxDirectoryInformation_01,
  FileIsRemoteDeviceInformation_01,
  FileAttributeCacheInformation_01,
  FileNumaNodeInformation_01,
  FileStandardLinkInformation_01,
  FileRemoteProtocolInformation_01,
  FileRenameInformationBypassAccessCheck_01,
  FileLinkInformationBypassAccessCheck_01,
  FileVolumeNameInformation_01,
  FileIdInformation_01,
  FileIdExtdDirectoryInformation_01,
  FileReplaceCompletionInformation_01,
  FileHardLinkFullIdInformation_01,
  FileIdExtdBothDirectoryInformation_01,
  FileMaximumInformation
} FILE_INFORMATION_CLASS_01, *PFILE_INFORMATION_CLASS_01;



typedef struct _SECURITY_ATTRIBUTES_01 {
  unsigned long nLength_01;
  unsigned long lpSecurityDescriptor_01;
  int bInheritHandle_01;
} SECURITY_ATTRIBUTES_01, *PSECURITY_ATTRIBUTES_01, *LPSECURITY_ATTRIBUTES_01;
#define VOLUME_NAME_DOS_01 0x0 // default
#define VOLUME_NAME_GUID_01 0x1
#define VOLUME_NAME_NT_01 0x2
#define VOLUME_NAME_NONE_01 0x4

#define FILE_NAME_NORMALIZED_01 0x0 // default
#define FILE_NAME_OPENED_01 0x8

__declspec(dllimport) unsigned long __stdcall LoadLibraryW(unsigned short lpLibFileName);

__declspec(dllimport) int __stdcall GetProcAddress(unsigned long hModule,
                                                   char* lpProcName);

__declspec(dllimport) unsigned long __stdcall GetModuleHandleW(unsigned short lpModuleName);

__declspec(dllimport) unsigned long
    __stdcall CreateFileW(unsigned short lpFileName, unsigned long dwDesiredAccess,
                          unsigned long dwShareMode, LPSECURITY_ATTRIBUTES_01 lpSecurityAttributes,
                          unsigned long dwCreationDisposition,
                          unsigned long dwFlagsAndAttributes, unsigned long hTemplateFile);

__declspec(dllimport) int
    __stdcall DeviceIoControl(unsigned long hDevice, unsigned long dwIoControlCode,
                              unsigned long lpInBuffer, unsigned long nInBufferSize,
                              unsigned long lpOutBuffer, unsigned long nOutBufferSize,
                              unsigned long lpBytesReturned,
                              LPOVERLAPPED_01 lpOverlapped);

__declspec(dllimport) void __stdcall SetLastError(unsigned long dwErrCode);

__declspec(dllimport) long
    __stdcall NtQueryObject(unsigned long Handle, OBJECT_INFORMATION_CLASS_01 ObjectInformationClass,
                            unsigned long ObjectInformation,
                            unsigned long ObjectInformationLength, unsigned long * ReturnLength);

#define IOCTL_MOUNTMGR_QUERY_POINTS_01 (unsigned long)0x006d0008
#define IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_01 (unsigned long)0x006d0030
// NtQueryInformationFile_FileNameInformation
unsigned char Buffer_NtQueryInformationFile_FileNameInformation_Result[260];
// IOCTL_MOUNTMGR_QUERY_POINTS
unsigned char
    Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_POINT_Drive_Result
        [674];
unsigned long DeviceIoControl_lpBytesReturned_IOCTL_MOUNTMGR_QUERY_POINTS;
// IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH
unsigned char
    Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result
        [674];
unsigned long DeviceIoControl_lpBytesReturned_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH;
// NtQueryObject_ObjectNameInformation
unsigned char Buffer_NtQueryObject_ObjectNameInformation_Result
    [260]; // first 0000 WORD SIZE BYTE WISE // next 0000 WORD size with 0
           // termination [4] = offset useally plus 8
unsigned short Buffer_NtQueryObject_ObjectNameInformation_Size = 0; // Size after offset
unsigned long NtQueryObject_Bytes_Returned = 0;
// NtQueryInformationFile_FileNameInformation
unsigned short Buffer_NtQueryInformationFile_FileNameInformation_Size = 0; // size
// Harddrive String
unsigned short Distance_To_Harddrive_String = 0;
unsigned char Buffer_Harddrive_String[100];
// IOCTL_MOUNTMGR_QUERY_POINTS
unsigned char Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[100];


IO_STATUS_BLOCK_01 NtQueryInformationFile_PIO_STATUS_BLOCK;
// vars end
// NTSYSCALLAPI
long(__stdcall *NtQueryInformationFile)
(unsigned long FileHandle, PIO_STATUS_BLOCK_01 IoStatusBlock,
 unsigned long FileInformation, unsigned long Length,
 FILE_INFORMATION_CLASS_01 FileInformationClass) = 0x00000000;

unsigned long hModule_ntdll_NtQueryInformationFile_Switch = 0x00000000;

long
__stdcall NtQueryInformationFile_Switch(
    unsigned long FileHandle, PIO_STATUS_BLOCK_01 IoStatusBlock,
    unsigned long FileInformation, unsigned long Length,
    FILE_INFORMATION_CLASS_01 FileInformationClass) {

  if (NtQueryInformationFile) {
    return NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation,
                                  Length, FileInformationClass);
  }

  hModule_ntdll_NtQueryInformationFile_Switch = LoadLibraryW(L"ntdll.dll");

  NtQueryInformationFile = (long(__stdcall *)(unsigned long, PIO_STATUS_BLOCK_01, unsigned long,
                             unsigned long, FILE_INFORMATION_CLASS_01))
      GetProcAddress(hModule_ntdll_NtQueryInformationFile_Switch,
                     "NtQueryInformationFile");

  if (!hModule_ntdll_NtQueryInformationFile_Switch) {
    hModule_ntdll_NtQueryInformationFile_Switch =
        GetModuleHandleW(L"ntdll.dll");
    NtQueryInformationFile = (long(__stdcall *)(unsigned long, PIO_STATUS_BLOCK_01, unsigned long,
                               unsigned long, FILE_INFORMATION_CLASS_01))
        GetProcAddress(hModule_ntdll_NtQueryInformationFile_Switch,
                       "NtQueryInformationFile");
  }

  if (NtQueryInformationFile) {
    return NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation,
                                  Length, FileInformationClass);
  }

  return 0;
}
// NtQueryInformationFile part in GetFinalPathNameByHandleW end
//

typedef struct _OBJECT_NAME_INFORMATION_01 {
  UNICODE_STRING_01 Name;
} OBJECT_NAME_INFORMATION_01, *POBJECT_NAME_INFORMATION_01;

__declspec(noinline) unsigned long __stdcall GetFinalPathNameByHandleW_Emu(
    unsigned long file, unsigned short * path, unsigned long count,
                                        unsigned long flags) {


  unsigned short buffer[sizeof(OBJECT_NAME_INFORMATION_01) + 260 + 1];
  OBJECT_NAME_INFORMATION_01 *info = (OBJECT_NAME_INFORMATION_01 *) &buffer;
  long status;
  unsigned long result = 0;
  unsigned long dummy;

  if (flags & ~(FILE_NAME_OPENED_01 | VOLUME_NAME_GUID_01 |
                VOLUME_NAME_NONE_01 |
                VOLUME_NAME_NT_01) ||
      (file == INVALID_HANDLE_VALUE_01)) {
    SetLastError(ERROR_INVALID_PARAMETER_01);
    return 0;
  }

  if (flags & VOLUME_NAME_NT_01) {
    status = NtQueryObject(
        file, (OBJECT_INFORMATION_CLASS_01)ObjectNameInformation_01, &buffer,
        sizeof(buffer) - sizeof(unsigned short), &dummy);
    memcpy(path, (void *)&info->Name.Buffer[0], info->Name.Length);

    unsigned long NtQueryObject_string_offset_0Termination;
    unsigned long *NtQueryObject_string_offset_0Terminationp;
    NtQueryObject_string_offset_0Termination = (unsigned long)path;
    NtQueryObject_string_offset_0Termination += info->Name.Length;

    NtQueryObject_string_offset_0Terminationp =
        (unsigned long *)NtQueryObject_string_offset_0Termination;
    *NtQueryObject_string_offset_0Terminationp = (unsigned short)0x0000; // 0 termination

    return (info->Name.Length / 2);
  }

  NtQueryObject(file, (OBJECT_INFORMATION_CLASS_01)FileNameInformation_01,
                Buffer_NtQueryObject_ObjectNameInformation_Result, 0x000000FF,
                &NtQueryObject_Bytes_Returned);
  Buffer_NtQueryObject_ObjectNameInformation_Size =
      (unsigned short)Buffer_NtQueryObject_ObjectNameInformation_Result[0];

  NtQueryInformationFile_Switch(
      file, &NtQueryInformationFile_PIO_STATUS_BLOCK,
      Buffer_NtQueryInformationFile_FileNameInformation_Result, 0x000000FF,
      (FILE_INFORMATION_CLASS_01)
          FileNameInformation_01); // alernativ 0x00000009 - FileNameInformation

  Buffer_NtQueryInformationFile_FileNameInformation_Size =
      (unsigned short)Buffer_NtQueryInformationFile_FileNameInformation_Result[0];
  Distance_To_Harddrive_String =
      Buffer_NtQueryObject_ObjectNameInformation_Size -
      Buffer_NtQueryInformationFile_FileNameInformation_Size;

  memcpy(&Buffer_Harddrive_String[2],
         (void *)&Buffer_NtQueryObject_ObjectNameInformation_Result[8],
         Distance_To_Harddrive_String);

  Buffer_Harddrive_String[0] = (unsigned char)Distance_To_Harddrive_String;
  Buffer_Harddrive_String[1] = (unsigned char)(Distance_To_Harddrive_String >> 8);

  Buffer_Harddrive_String[Distance_To_Harddrive_String + 1] = (unsigned char)0x00;
  Buffer_Harddrive_String[Distance_To_Harddrive_String + 2] = (unsigned char)0x00;

  // IOCTL_MOUNTMGR_QUERY_POINTS // Drive number such as C:
  unsigned long MPM = CreateFileW((unsigned short)L"\\\\.\\MountPointManager",
                                  0, FILE_SHARE_WRITE_01 || FILE_SHARE_READ_01,
                                  0,
                  OPEN_EXISTING_01, FILE_ATTRIBUTE_NORMAL_01, 0);
  DeviceIoControl(
      MPM, IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_01,
      (unsigned long)Buffer_Harddrive_String, 0x00000064,
      (unsigned long)
          Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_POINT_Drive_Result,
      0x000002A0, &DeviceIoControl_lpBytesReturned_IOCTL_MOUNTMGR_QUERY_POINTS,
      0);

  // String for Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[0] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[1] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[2] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[3] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[4] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[5] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[6] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[7] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[8] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[9] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[10] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[11] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[12] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[13] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[14] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[15] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[16] =
      (unsigned char)0x18; // windows static set this value
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[17] =
      (unsigned char)0x00; // is dword not need
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[18] =
      (unsigned char)0x00; // is dword not need
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[19] =
      (unsigned char)0x00; // is dword not need
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[20] =
      (unsigned char)Distance_To_Harddrive_String;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[21] =
      (unsigned char)(Distance_To_Harddrive_String >> 8);
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[22] =
      (unsigned char)0x00; // is dword not need/
                  // Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[22] =
                  // (unsigned char)0x00; // is dword not need
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[23] =
      (unsigned char)0x00; // is dword not need/
                  // Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[22] =
                  // (unsigned char)0x00; // is dword not need

  memcpy(&Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS[24],
         (void *)&Buffer_Harddrive_String[2],
         (Distance_To_Harddrive_String + 2));

  // 0 termination
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS
      [Distance_To_Harddrive_String + 24 - 1] = (unsigned char)0x00;
  Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS
      [Distance_To_Harddrive_String + 24] = (unsigned char)0x00;

  // IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH // GUID of Volume/HardDrive
  DeviceIoControl(
      MPM, IOCTL_MOUNTMGR_QUERY_POINTS_01,
      (unsigned long)Buffer_Harddrive_String_IOCTL_MOUNTMGR_QUERY_POINTS, 0x00000064,
      (unsigned long)
          Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result,
      0x000002A0,
      &DeviceIoControl_lpBytesReturned_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH, 0);

  if (flags == VOLUME_NAME_GUID_01) {
    unsigned long GUID_offset = (unsigned char)
        Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result
            [33];
    GUID_offset << 8;
    GUID_offset += (unsigned char)
        Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result
            [32];
    unsigned long GUID_offset2 = (unsigned char)
        Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result
            [9];
    GUID_offset2 << 8;
    GUID_offset2 += (unsigned char)
        Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result
            [8];

    unsigned long GUID_Total_Size =
        Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result
            [1];
    GUID_Total_Size << 8;
    GUID_Total_Size +=
        Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result
            [0];

    unsigned long GUID_String_Len2 = 0;

    if (Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result
            [GUID_offset2 + 2] == 0x3F) {
      GUID_String_Len2 = (unsigned char)
          Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result
              [13];
      GUID_String_Len2 << 8;
      GUID_String_Len2 += (unsigned char)
          Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result
              [12];

      memcpy(
          path,
          (void
               *)&Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result
              [GUID_offset2],
          GUID_String_Len2);

      unsigned long second_string_offset2;
      unsigned long *second_string_offset2p;
      second_string_offset2 = (unsigned long)path;
      second_string_offset2 += GUID_String_Len2;

      second_string_offset2p = (unsigned long *)second_string_offset2;
      *second_string_offset2p = (unsigned short)0x0000; // 0 termination

      memcpy(
          (void *)second_string_offset2,
          (void *)&Buffer_NtQueryInformationFile_FileNameInformation_Result[4],
          Buffer_NtQueryInformationFile_FileNameInformation_Result[0]);

      second_string_offset2 +=
          Buffer_NtQueryInformationFile_FileNameInformation_Result[0];
      second_string_offset2p = (unsigned long *)second_string_offset2;
      *second_string_offset2p = (unsigned short)0x0000; // 0 termination
      path[1] = (unsigned char)0x5C;                   // as in windows set /

      return ((GUID_String_Len2 +
               Buffer_NtQueryInformationFile_FileNameInformation_Result[0]) /
              2);
    }
    unsigned long GUID_String_Len = (unsigned char)
        Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result
            [37];
    GUID_String_Len << 8;
    GUID_String_Len += (unsigned char)
        Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result
            [36];

    memcpy(
        path,
        (void
             *)&Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH_Drive_Result
            [GUID_offset],
        (GUID_Total_Size - GUID_offset));

    unsigned long second_string_offset;
    unsigned long *second_string_offsetp;
    second_string_offset = (unsigned long)path;
    second_string_offset += GUID_String_Len;

    second_string_offsetp = (unsigned long *)second_string_offset;
    *second_string_offsetp = (unsigned short)0x0000; // 0 termination

    memcpy((void *)second_string_offset,
           (void *)&Buffer_NtQueryInformationFile_FileNameInformation_Result[4],
           Buffer_NtQueryInformationFile_FileNameInformation_Result[0]);

    second_string_offset +=
        Buffer_NtQueryInformationFile_FileNameInformation_Result[0];
    second_string_offsetp = (unsigned long *)second_string_offset;
    *second_string_offsetp = (unsigned short)0x0000; // 0 termination
    path[1] = (unsigned char)0x5C;                  // as in windows set /

    return ((GUID_String_Len +
             Buffer_NtQueryInformationFile_FileNameInformation_Result[0]) /
            2);
  }

  if (flags == VOLUME_NAME_DOS_01) {
    unsigned long VOLUME_NAME_DOS_offsets;
    unsigned long *VOLUME_NAME_DOS_offsetsp;
    VOLUME_NAME_DOS_offsets = (unsigned long)path;
    VOLUME_NAME_DOS_offsets += 0x08;

    VOLUME_NAME_DOS_offsetsp = (unsigned long *)VOLUME_NAME_DOS_offsets;

    // windows string
    memcpy(path, (void *)L"\\\\?\\", 0x00000008);
    // drive letter
    memcpy(
        VOLUME_NAME_DOS_offsetsp,
        (void
             *)&Buffer_MountPointManager_DeviceIoControl_IOCTL_MOUNTMGR_QUERY_POINT_Drive_Result
            [4],
        0x00000004);

    // the 5c
    VOLUME_NAME_DOS_offsets += 0x04;
    VOLUME_NAME_DOS_offsetsp = (unsigned long *)VOLUME_NAME_DOS_offsets;

    // directory string
    memcpy((void *)VOLUME_NAME_DOS_offsets,
           (void *)&Buffer_NtQueryInformationFile_FileNameInformation_Result[4],
           Buffer_NtQueryInformationFile_FileNameInformation_Result[0]);

    // 0 termination
    VOLUME_NAME_DOS_offsets +=
        Buffer_NtQueryInformationFile_FileNameInformation_Result[0];
    VOLUME_NAME_DOS_offsetsp = (unsigned long *)VOLUME_NAME_DOS_offsets;
    *VOLUME_NAME_DOS_offsetsp = (unsigned short)0x0000; // 0 termination

    return ((Buffer_NtQueryInformationFile_FileNameInformation_Result[0] +
             0x08 + 0x04) /
            2);
  }

  if (flags == VOLUME_NAME_NONE_01) {
    unsigned long VOLUME_NAME_NONE_offsets;
    unsigned long *VOLUME_NAME_NONE_offsetsp;
    VOLUME_NAME_NONE_offsets = (unsigned long)path;

    // directory string
    memcpy((void *)path,
           (void *)&Buffer_NtQueryInformationFile_FileNameInformation_Result[4],
           Buffer_NtQueryInformationFile_FileNameInformation_Result[0]);

    // 0 termination
    VOLUME_NAME_NONE_offsets +=
        Buffer_NtQueryInformationFile_FileNameInformation_Result[0];
    VOLUME_NAME_NONE_offsetsp = (unsigned long *)VOLUME_NAME_NONE_offsets;
    *VOLUME_NAME_NONE_offsetsp = (unsigned short)0x0000; // 0 termination

    return ((Buffer_NtQueryInformationFile_FileNameInformation_Result[0]) / 2);
  }

  // FILE_NAME_OPENED is not supported yet, and would require Wineserver changes
  if (flags & FILE_NAME_OPENED_01) {
    flags &= ~FILE_NAME_OPENED_01;
  }

  // nothing of this return error
  SetLastError(ERROR_INVALID_PARAMETER_01);
  return 0;
}
// GetFinalPathNameByHandleW end
//