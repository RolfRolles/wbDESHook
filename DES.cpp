#include "stdafx.h"
#include <assert.h>
#include <string.h>
#include <math.h>
#include <cmath>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <exception>
#include <set>
#include <algorithm>

using std::hex;
std::ofstream TraceFile;
using std::max;

typedef unsigned long long u64;
typedef unsigned char u4;
typedef unsigned char u8;
typedef unsigned long u32;

enum LogMessages_t
{
  LogFeistel = 0x01,
  LogRounds  = 0x02,
  LogPermutations = 0x04,
};

class DES
{
  private:
  LogMessages_t m_ToLog;
  u64 m_SubKeys[16];
  
  public:
  static u8 IPTable[64];
  static u8 FPTable[64];
  static u8 PermutationTable[32];
  static u8 InversePermutationTable[32];
  static u4 SBOX[8][64];
  static u8 ExpansionTable[48];
  static u8 PermutationChoice1Table[56];
	static u8 PermutationChoice2Table[48];
	static u8 LeftRotations[16];
  
  void Log(LogMessages_t LogType, const char *Msg)
  {
    if(m_ToLog & LogType)
      TraceFile << Msg << "\n";
  }

  void Log(LogMessages_t LogType, const char *Msg, u32 Value)
  {
    if(m_ToLog & LogType)
      TraceFile << Msg << ": " << std::setfill('0') << std::setw(8) << hex << Value << "\n";
  }

  void Log(LogMessages_t LogType, const char *Msg, u64 Value)
  {
    if(m_ToLog & LogType)
      TraceFile << Msg << ": " << std::setfill('0') << std::setw(16) << hex << Value << "\n";
  }

  void LogU48(LogMessages_t LogType, const char *Msg, u64 Value)
  {
    if(m_ToLog & LogType)
      TraceFile << Msg << ": " << std::setfill('0') << std::setw(12) << hex << Value << "\n";
  }

  void Log(LogMessages_t LogType, const char *Msg, u8 Value)
  {
    if(m_ToLog & LogType)
      TraceFile << Msg << ": " << std::setfill('0') << std::setw(2) << hex << (u32)Value << "\n";
  }

  void LogU4(LogMessages_t LogType, const char *Msg, u8 Value)
  {
    if(m_ToLog & LogType)
      TraceFile << Msg << ": " << std::setfill('0') << std::setw(1) << hex << (u32)Value << "\n";
  }

  public:
  DES(LogMessages_t lm) : m_ToLog(lm) {};
  
  #define GETBIT(x,n) (((x)>>(n))&1)
  #define SETBIT(o,m,b) o |= ((b)<<(m));
  u64 InitialPermutation(u64 Input)
  {
    u64 Output = 0ULL;
    for(int i = 0; i < sizeof(IPTable); ++i)
    {
      SETBIT(Output,i,GETBIT(Input,IPTable[i]));
    }
    return Output;
  }
  u64 FinalPermutation(u64 Input)
  {
    u64 Output = 0ULL;
    for(int i = 0; i < sizeof(FPTable); ++i)
    {
      SETBIT(Output,i,GETBIT(Input,FPTable[i]));
    }
    return Output;
  }
  u64 Expand(u32 Input)
  {
    u64 Output = 0ULL;
    for(int i = 0; i < sizeof(ExpansionTable); ++i)
    {
      SETBIT(Output,i,(u64)GETBIT(Input,ExpansionTable[i]));
    }
    return Output;
  }
  u32 Permute(u32 Input)
  {
    u32 Output = 0ULL;
    for(int i = 0; i < sizeof(PermutationTable); ++i)
    {
      SETBIT(Output,i,GETBIT(Input,PermutationTable[i]));
    }
    return Output;
  }
  u32 PermuteInverse(u32 Input)
  {
    u32 Output = 0ULL;
    for(int i = 0; i < sizeof(InversePermutationTable); ++i)
    {
      SETBIT(Output,i,GETBIT(Input,InversePermutationTable[i]));
    }
    return Output;
  }
  u64 PermutationChoice1(u64 Input)
  {
    u64 Output = 0ULL;
    for(int i = 0; i < sizeof(PermutationChoice1Table); ++i)
    {
      SETBIT(Output,55-i,GETBIT(Input,63-PermutationChoice1Table[i]));
    }
    return Output;
  }
  u64 PermutationChoice2(u64 Input)
  {
    u64 Output = 0ULL;
    for(int i = 0; i < sizeof(PermutationChoice2Table); ++i)
    {
      SETBIT(Output,47-i,GETBIT(Input,55-PermutationChoice2Table[i]));
    }
    return Output;
  }

  u32 RotateLeft(u32 x, u32 n, u32 numBits)
  {
    n %= numBits;
    u32 Mask = (1 << numBits) - 1;
    return ((x << n) | (x >> (numBits - n))) & Mask;
  }

  void GenerateSubkeys(u64 Key)
  {
    u64 PC1 = PermutationChoice1(Key);
    u64 KeyState = PC1;
    u32 KSL = (KeyState >> 28) & 0x0FFFFFFF;
    u32 KSR =  KeyState        & 0x0FFFFFFF;
    for(int i = 0; i < sizeof(LeftRotations); ++i)
    {
      KSL = RotateLeft(KSL, LeftRotations[i], 28);
      KSR = RotateLeft(KSR, LeftRotations[i], 28);
      m_SubKeys[i] = PermutationChoice2(((u64)KSL << 28) | KSR);
    }
  }

  virtual void FeistelBegin(int round, u64 SubKey, u32 R, u32 LInverse)
  {
    Log(LogFeistel, "R", R);
    Log(LogFeistel, "LInverse", LInverse);
    LogU48(LogFeistel, "SubKey", SubKey);
  }
  
  virtual void FeistelAfterInit(int round, u64 Subkey, u32 R, u32 LInverse, u64 ExpandedR, u64 ERxorSubKey)
  {
    LogU48(LogFeistel, "ExpandedR", ExpandedR);
    LogU48(LogFeistel, "ExpandedR ^ SubKey", ERxorSubKey);
  }
  
  // Get rid of PermutedSBIdx
  virtual void FeistelAfterGroup(int round, int group, u8 SBIdx, u8 PermutedSBIdx, u4 SBOut)
  {
    char buf[256];
    sprintf(buf, "SBIdx for bits %d-%d (group %d)", (group*6)+5,group*6, (7-group)+1);
    Log(LogFeistel, buf, SBIdx);
    Log(LogFeistel, "Permuted SBIdx", PermutedSBIdx);
    LogU4(LogFeistel, "SBOut", SBOut);  
  }
  
  virtual void FeistelEnd(int round, u32 SBoxesOut, u32 OxorLInv, u32 FinalOutput)
  {
    Log(LogFeistel, "SBoxes output total", SBoxesOut);
    Log(LogFeistel, "Output ^ LInverse", OxorLInv);
    Log(LogFeistel, "Feistel output (Permute(Output^LInverse))", FinalOutput);
  }

  // So I don't forget: I would like to factor this out into "events" so that I
  // can derive a class off of this to capture the data that I want.
  u32 Feistel(int round, u64 SubKey, u32 R, u32 LInverse)
  {
    FeistelBegin(round, SubKey, R, LInverse);
    u64 ExpandedR = Expand(R);
    u64 ERxorSubKey = ExpandedR ^ SubKey;
    FeistelAfterInit(round, SubKey, R, LInverse, ExpandedR, ERxorSubKey);
    
    u32 Output = 0;
    for(int i = 7; i >= 0; --i)
    {
      u8 SBIdx = (ERxorSubKey >> (i*6)) & 0x3F;
      u4 SBOut = SBOX[7-i][SBIdx];
      Output |= SBOut << 4*i;
      FeistelAfterGroup(round, i, SBIdx, SBIdx, SBOut);
    }
    u32 OxorLInv = Output ^ LInverse;
    u32 FinalOutput = Permute(OxorLInv);
    FeistelEnd(round, Output, OxorLInv, FinalOutput);
    return FinalOutput;
  }
  
  void IsolatedRound(u64 SubKey, u64 Plaintext)
  {
    u64 State = InitialPermutation(Plaintext);
    u32 L = State >> 32, R = State;
    u32 LInverse = PermuteInverse(L);
    u32 NewR = Feistel(1, SubKey, R, LInverse);  	
  }

  u64 EncryptBlock(u64 Key, u64 Block)
  {
    GenerateSubkeys(Key);
    
    Log(LogPermutations, "Original", Block);
    u64 AfterIP  = InitialPermutation(Block);
    Log(LogPermutations, "Initial", AfterIP);

    u64 State = AfterIP;    
    for(int i = 1; i <= 16; ++i)
    {
      u32 L = State >> 32, R = State;
      u32 LInverse = PermuteInverse(L);
      u32 NewR = Feistel(i, m_SubKeys[i-1], R, LInverse);
      if(i != 16)
        State = ((u64)R << 32) | NewR;
      else
        State = ((u64)NewR << 32) | R;
    }
    u64 AfterFP = FinalPermutation(State);
    Log(LogPermutations, "Final", AfterFP);
    return AfterFP;
  }
};

u8 DES::IPTable[64] = 
{
  57, 49, 41, 33, 25, 17, 9,  1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7,
  56, 48, 40, 32, 24, 16, 8,  0,
  58, 50, 42, 34, 26, 18, 10, 2,
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6
};

u8 DES::FPTable[64] = 
{
  39,  7, 47, 15, 55, 23, 63, 31,
  38,  6, 46, 14, 54, 22, 62, 30,
  37,  5, 45, 13, 53, 21, 61, 29,
  36,  4, 44, 12, 52, 20, 60, 28,
  35,  3, 43, 11, 51, 19, 59, 27,
  34,  2, 42, 10, 50, 18, 58, 26,
  33,  1, 41,  9, 49, 17, 57, 25,
  32,  0, 40,  8, 48, 16, 56, 24
};

u8 DES::PermutationTable[32] = {
  7, 28, 21, 10, 26, 2, 19, 13, 
  23, 29, 5, 0, 18, 8, 24, 30, 
  22, 1, 14, 27, 6, 9, 17, 31, 
  15, 4, 20, 3, 11, 12, 25, 16
};

u8 DES::InversePermutationTable[32] = {
11, 17, 5, 27, 25, 10, 20, 0, 
13, 21, 3, 28, 29, 7, 18, 24, 
31, 22, 12, 6, 26, 2, 16, 8, 
14, 30, 4, 19, 1, 9, 15, 23
};

u4 DES::SBOX[8][64] = 
{
  {
    14,  0,  4, 15, 13,  7,  1,  4,  2, 14, 15,  2, 11, 13,  8,  1,
     3, 10, 10,  6,  6, 12, 12, 11,  5,  9,  9,  5,  0,  3,  7,  8,
     4, 15,  1, 12, 14,  8,  8,  2, 13,  4,  6,  9,  2,  1, 11,  7,
    15,  5, 12, 11,  9,  3,  7, 14,  3, 10, 10,  0,  5,  6,  0, 13
  },
  {
    15,  3,  1, 13,  8,  4, 14,  7,  6, 15, 11,  2,  3,  8,  4, 14,
     9, 12,  7,  0,  2,  1, 13, 10, 12,  6,  0,  9,  5, 11, 10,  5,
     0, 13, 14,  8,  7, 10, 11,  1, 10,  3,  4, 15, 13,  4,  1,  2,
     5, 11,  8,  6, 12,  7,  6, 12,  9,  0,  3,  5,  2, 14, 15,  9
  },
  {
    10, 13,  0,  7,  9,  0, 14,  9,  6,  3,  3,  4, 15,  6,  5, 10,
     1,  2, 13,  8, 12,  5,  7, 14, 11, 12,  4, 11,  2, 15,  8,  1,
    13,  1,  6, 10,  4, 13,  9,  0,  8,  6, 15,  9,  3,  8,  0,  7,
    11,  4,  1, 15,  2, 14, 12,  3,  5, 11, 10,  5, 14,  2,  7, 12
  },
  {
     7, 13, 13,  8, 14, 11,  3,  5,  0,  6,  6, 15,  9,  0, 10,  3,
     1,  4,  2,  7,  8,  2,  5, 12, 11,  1, 12, 10,  4, 14, 15,  9,
    10,  3,  6, 15,  9,  0,  0,  6, 12, 10, 11,  1,  7, 13, 13,  8,
    15,  9,  1,  4,  3,  5, 14, 11,  5, 12,  2,  7,  8,  2,  4, 14
  },
  {
     2, 14, 12, 11,  4,  2,  1, 12,  7,  4, 10,  7, 11, 13,  6,  1,
     8,  5,  5,  0,  3, 15, 15, 10, 13,  3,  0,  9, 14,  8,  9,  6,
     4, 11,  2,  8,  1, 12, 11,  7, 10,  1, 13, 14,  7,  2,  8, 13,
    15,  6,  9, 15, 12,  0,  5,  9,  6, 10,  3,  4,  0,  5, 14,  3
  },
  {
    12, 10,  1, 15, 10,  4, 15,  2,  9,  7,  2, 12,  6,  9,  8,  5,
     0,  6, 13,  1,  3, 13,  4, 14, 14,  0,  7, 11,  5,  3, 11,  8,
     9,  4, 14,  3, 15,  2,  5, 12,  2,  9,  8,  5, 12, 15,  3, 10,
     7, 11,  0, 14,  4,  1, 10,  7,  1,  6, 13,  0, 11,  8,  6, 13
  },
  {
     4, 13, 11,  0,  2, 11, 14,  7, 15,  4,  0,  9,  8,  1, 13, 10,
     3, 14, 12,  3,  9,  5,  7, 12,  5,  2, 10, 15,  6,  8,  1,  6,
     1,  6,  4, 11, 11, 13, 13,  8, 12,  1,  3,  4,  7, 10, 14,  7,
    10,  9, 15,  5,  6,  0,  8, 15,  0, 14,  5,  2,  9,  3,  2, 12
  },
  {
    13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4,
    10, 12,  9,  5,  3,  6, 14, 11,  5,  0,  0, 14, 12,  9,  7,  2,
     7,  2, 11,  1,  4, 14,  1,  7,  9,  4, 12, 10, 14,  8,  2, 13,
     0, 15,  6, 12, 10,  9, 13,  0, 15,  3,  3,  5,  5,  6,  8, 11
  }
};

u8 DES::ExpansionTable[48] = 
{
  31,  0,  1,  2,  3,  4,
   3,  4,  5,  6,  7,  8,
   7,  8,  9, 10, 11, 12,
  11, 12, 13, 14, 15, 16,
  15, 16, 17, 18, 19, 20,
  19, 20, 21, 22, 23, 24,
  23, 24, 25, 26, 27, 28,
  27, 28, 29, 30, 31,  0
};

u8 DES::PermutationChoice1Table[56] = 
{
  56, 48, 40, 32, 24, 16,  8,
    0, 57, 49, 41, 33, 25, 17,
    9,  1, 58, 50, 42, 34, 26,
   18, 10,  2, 59, 51, 43, 35,
   62, 54, 46, 38, 30, 22, 14,
    6, 61, 53, 45, 37, 29, 21,
   13,  5, 60, 52, 44, 36, 28,
   20, 12,  4, 27, 19, 11,  3
};

u8 DES::PermutationChoice2Table[48] = 
{
  13, 16, 10, 23,  0,  4,
   2, 27, 14,  5, 20,  9,
  22, 18, 11,  3, 25,  7,
  15,  6, 26, 19, 12,  1,
  40, 51, 30, 36, 46, 54,
  29, 39, 50, 44, 32, 47,
  43, 48, 38, 55, 33, 52,
  45, 41, 49, 35, 28, 31
};

u8 DES::LeftRotations[16] = 
{
  1, 1, 2, 2, 
  2, 2, 2, 2, 
  1, 2, 2, 2, 
  2, 2, 2, 1
};

struct TestVector
{
	u64 Key;
	u64 Input;
	u64 Output;
};

#define WBDES_KEY 0x3032343234363236ULL

TestVector Tests[1] = {
	{
    WBDES_KEY,
    0x1122334455667788ULL,
    0xc403d32e2bc6cfeeULL,
  }
};

static u64 GetRand()
{
  u64 Output = 0;
  for(int i = 0; i < 8; ++i)
  {
    Output <<= 8;
    Output |= rand() & 0xFF	;
  }	
  return Output;
}

int main(int, char **)
{
  //TraceFile.open("trace");
  DES d((LogMessages_t)((int)LogFeistel|(int)LogRounds|(int)LogPermutations));

  u64 pt = 0x5555555555555553ULL;
  //Tests[0].Input;
  u64 perm = d.InitialPermutation(pt);
  u64 deperm = d.FinalPermutation(perm);
  printf("pt = %16llx, perm = %16llx, deperm = %16llx\n", pt, perm, deperm);
  
  for(int i = 0; i < sizeof(DES::IPTable); ++i)
  {
    assert(DES::FPTable[DES::IPTable[i]] == i);
    assert(DES::IPTable[DES::FPTable[i]] == i);
  }
  
  for(int i = 0; i < 10; ++i)
  {
    u64 value = GetRand();
    u64 IP = d.InitialPermutation(value);
    u64 FP = d.FinalPermutation(IP);
    assert(value == FP);
    FP = d.FinalPermutation(value);
    IP = d.InitialPermutation(FP);
    assert(value == IP);
    
    u32 v32 = value;
    u32 P = d.Permute(v32);
    u32 I = d.PermuteInverse(P);
    assert(v32 == I);
    I = d.PermuteInverse(value);
    P = d.Permute(I);
    assert(v32 == P);
    	
  }
  
  for(int i = 0; i < sizeof(Tests)/sizeof(Tests[0]); ++i)
  {
    u64 Output = d.EncryptBlock(Tests[i].Key, Tests[i].Input);
    assert(Output == Tests[i].Output);
  }
  printf("All tests passed\n");
  TraceFile.close();
}
