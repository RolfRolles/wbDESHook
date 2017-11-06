#include "stdafx.h"
#include <winnt.h>

void StoreDword(unsigned char *Buffer, DWORD What)
{
  Buffer[0] = What;
  Buffer[1] = What>>8;
  Buffer[2] = What>>16;
  Buffer[3] = What>>24;
}

bool WriteJump(unsigned long src_ea, unsigned long dest_ea, HANDLE ProcessTo)
{
  bool retval = true;
  unsigned char write_buffer[5] = {'\xe9', '\0', '\0', '\0', '\0'};
  unsigned long diff = dest_ea - (src_ea + 5);
  DWORD oldProtect, numBytesWritten;

  StoreDword(&write_buffer[1], diff);
  
  if(!VirtualProtect((LPVOID)src_ea, sizeof(write_buffer), PAGE_EXECUTE_READWRITE, &oldProtect))
    return false;

  if(!WriteProcessMemory(ProcessTo, (LPVOID)src_ea, &write_buffer, sizeof(write_buffer), &numBytesWritten) ||
    numBytesWritten != sizeof(write_buffer))
  
    retval = false;
  
  if(!VirtualProtect((LPVOID)src_ea, sizeof(write_buffer), oldProtect, &oldProtect))
    return false;
  
  return retval;
}

