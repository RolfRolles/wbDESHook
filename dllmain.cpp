// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include "Hook.hpp"

#include <list>
#include <set>

// Include the DES .cpp file to get the tables and not just the DES class
#include "DES.cpp"

// Uncomment to receive thread-related debug messages
//#define THREAD_DEBUG 

// Uncomment to receive verbose debug messages
#define VERBOSE_DEBUG

// wb_init() [inlined] hook locations:
// .text:004011C5                 mov     [ebp+var_4C], 0   <- hook after argument atox converstion
// .text:004011CC                 cmp     [ebp+var_4C], 0Bh <- resume at top of wb_init()
unsigned long g_WBInitHookLocation = 0x004011C5;
unsigned long g_WBInitResumeLocation = 0x004011CC;

// wb_round() [inlined] hook locations:
// .text:004015EC                 cmp     [ebp+var_4C], 0Eh <- instruction not long enough to hook...
// .text:004015F0                 jg      loc_401DE7        <- ... so hook this location instead
// .text:004015F6                 mov     [ebp+var_50], 0   <- resume execution here
unsigned long g_WBRoundHookLocation = 0x004015F0;
unsigned long g_WBRoundResumeLocation = 0x004015F6;

// This gets updated in HookWBRound when doing wb_round differential analysis
// If we need to compute a round of wb_round(), set this to g_WBRoundResumeLocation
// If we need to start over at wb_init(), set this to g_WBInitResumeLocation
unsigned long g_WBRoundNextLocation;

//
// wbDES.exe memory locations of local variables in main()
//
// Where the atox()'ed input is stored
unsigned char *gp_Input;       

// The 96-bit white-box state
unsigned char *gp_WBState;     

// Integer stack variable for round number
unsigned long *gp_RoundNumber; 

//
// Handles to synchronization events, since the attack code runs in its own thread
//
// Signalled by wbDES main thread hooks after argument conversion or wb_round() has completed
HANDLE g_ReadyToComputeEvent;  

// Signalled by wbDES main thread hooks after one wb_round() has completed
HANDLE g_ComputationFinishedEvent;

// Signalled by attack thread when we want to compute a wb_round()
HANDLE g_ComputationRequestedEvent;

// For debugging purposes, print an 8-byte u8 array (e.g., for the input).
void PrintInput(u8 *Input)
{
  for(int i = 0; i < 8; ++i)
    printf("%02Lx ", Input[i]);
  printf("\n");
}

// For debugging purposes, print a 12-byte u8 array (e.g., for the white-box state).
void PrintWBState(u8 *State)
{
  for(int i = 0; i < 12; ++i)
    printf("%02Lx ", State[i]);
  printf("\n");
}

// For debugging purposes, print a 12-byte u8 differential array
void PrintDifferential(u8 nSbox, u8 nBit, u8 *Differential)
{
  printf("Differential for bit %d (SBOX%d): ", nBit, nSbox);
  PrintWBState(Differential);
}

// This is the C portion of the ASM hook for wb_init(). It initializes the
// pointers to the important variables on wbDES!main()'s stack frame, and uses
// events to communicate with the attack thread.
// Must be declared __stdcall.
void __stdcall HookWBInit(unsigned long EBP)
{
  gp_Input       = (unsigned char *)(EBP-0x20);
  gp_WBState     = (unsigned char *)(EBP-0x38);
  gp_RoundNumber = (unsigned long *)(EBP-0x4C);
  memset(gp_Input, 0, 8);

  // This is what we overwrote with our hook
  *gp_RoundNumber = 0;

#ifdef THREAD_DEBUG
  printf("HookWBInit: Ready to compute; waiting...\n");
#endif

  // Signal to the attack thread that we are ready to compute wb_round()
  SetEvent(g_ReadyToComputeEvent);
  // Wait for the attack thread to request a computation
  WaitForSingleObject(g_ComputationRequestedEvent, INFINITE);

#ifdef THREAD_DEBUG
  printf("HookWBInit: Got computation request\n");
#endif
}

// This is the C portion of the ASM hook for wb_round(). It manages the logic
// for determining when round-1 has been computed, and uses events to 
// communicate with the attack thread.
// Must be declared __stdcall.
void __stdcall HookWBRound(int RoundNum)
{
  // Entered after the first wb_round() has completed
  if(RoundNum == 1)
  {
    // Set the round number back to 0 (we overwrite this with our hook)
    *gp_RoundNumber = 0;
    
    // Inform the ASM hook stub that the next location is at wb_init()
    g_WBRoundNextLocation = g_WBInitResumeLocation;

#ifdef THREAD_DEBUG
    printf("HookWBRound: About to send computation finished result\n");
#endif

    // Inform the attack thread that the computation has finished
    SetEvent(g_ComputationFinishedEvent);
    // Inform the attack thread that we are ready to compute the next wb_round()
    SetEvent(g_ReadyToComputeEvent);

#ifdef THREAD_DEBUG
    printf("HookWBRound: Waiting for computation request\n");
#endif
    
    // Wait for the attack thread to request a wb_round() computation
    WaitForSingleObject(g_ComputationRequestedEvent, INFINITE);

#ifdef THREAD_DEBUG
    // Print the input copied from the attack thread
    printf("HookWBRound: about to compute round-1 output for input: ");
    PrintInput(gp_Input);
#endif
  }
  
  // Otherwise, the first iteration of wb_round() has not yet executed, so our
  // hook needs to resume execution at wb_round(), not wb_init()
  else
  {
    g_WBRoundNextLocation = g_WBRoundResumeLocation;
  }
}

// Cygwin caused a major headache when I tried to use standard DLL injection,
// so I ended up having to add an IMAGE_IMPORT_DESCRIPTOR to the binary. Thus,
// my DLL needed an export. This is that export.
void __declspec(dllexport) Blah() {}

// The hook stub for wb_init(). Passes EBP as a parameter.
void __declspec(naked) HookWBInitASM()
{
  __asm {
    pushad
    pushfd
    push ebp
    call HookWBInit
    popfd
    popad
    mov eax, g_WBInitResumeLocation
    jmp eax
  }
}

// The hook stub for wb_round(). Passes the round number as a parameter.
void __declspec(naked) HookWBRoundASM()
{
  __asm {
    pushad
    pushfd
    push dword ptr [ebp-0x4c] // Round number from stack variable
    call HookWBRound
    popfd
    popad
    mov eax, g_WBRoundNextLocation
    jmp eax
  }
}

// Inputs:
// u8 *WhichBits: pointer to bytes which specify bit numbers to set within the plaintext
// u8 nBits: size of the WhichBits array
// u8 nBitValues: a bitmask for setting the bits specified in WhichBits. I.e. if this is 0b10,
//                then WhichBits[0] is not set, and WhichBits[1] is set within the plaintext
// u8 *Output: 12-byte output, the wb_state array copied from wbDES.exe!main()'s stack frame
void ComputeRound1Output(u8 *WhichBits, u8 nBits, u8 nBitValues, u8 *Output)
{
#ifdef THREAD_DEBUG
  printf("ComputeRound1Output: Waiting for ready to compute event...\n");
#endif
  
  // Attack thread waits for the main thread to complete any wb_round() computations
  WaitForSingleObject(g_ReadyToComputeEvent, INFINITE);

#ifdef THREAD_DEBUG
  printf("ComputeRound1Output: About to send computation request...\n");
#endif
  
  // Initialize wbDES's input stack variable to zeroes
  memset(gp_Input, 0, 8);  
  
  // Iterate through WhichBits and set the bits in the plaintext requested by the caller
  for(int i = 0; i < nBits; ++i)
  {
    // Was the bit requested as set?
    if(nBitValues & (1 << i))
    {
      // Then convert it into a byte:bit offset and set it
      int nTranslated = 63-WhichBits[i];
      unsigned char InitDiffByte = nTranslated / 8;
      unsigned char InitDiffBit  = 1 << (7-(nTranslated % 8));
      gp_Input[InitDiffByte] |= InitDiffBit;
    }
  }

#ifdef THREAD_DEBUG
  printf("About to request round-1 output for: \n");
  PrintInput(gp_Input);
#endif
  
  // Attack thread informs wbDES main thread that we want to compute wb_round()
  SetEvent(g_ComputationRequestedEvent);
  
  // Attack thread waits for wbDES main thread to compute wb_round()
  WaitForSingleObject(g_ComputationFinishedEvent, INFINITE);
  
  // Copy the white-box state from wbDES!main() stack frame
  memcpy(Output, gp_WBState, 12);

#ifdef THREAD_DEBUG
  printf("Output was: ");
  PrintWBState(Output);
  printf("ComputeRound1Output: Got computation result!\n");
#endif
}

// First, compute the round-1 output via ComputeRound1Output. Then, compute the
// differential by XORing with the other specified round-1 output.
void ComputeRound1Differential(u8 *WhichBits, u8 nBits, u8 nBitValues, u8 *Output, u8 *OtherOutput)
{
  ComputeRound1Output(WhichBits, nBits, nBitValues, Output);
  for(int i = 0; i < 12; ++i)
    Output[i] ^= OtherOutput[i];
}

// Enum used for comparing two differentials
enum WBDesCompResult 
{
  WBDesComp_Identical,   // Both affected the two nibbles in the same way
  WBDesComp_Unmodified,  // The two nibbles were not affected
  WBDesComp_Incomparable // At least one nibble was affected in an unexpected way
};

// Compare the differential output of two calls to wb_state.
// Inputs:
// u8 lDifferential[12]: "left-hand" differential
// u8 rDifferential[12]: "right-hand" differential
// u8 Mask[12]: generated from lDifferential; if a nibble was affected at position i, 
//              Mask[i] contains 0xF for that nibble
// Output:
// WBDesComp_Identical: the positions in lDifferential specified by Mask matched in rDifferential
// WBDesComp_Unmodified: the positions in rDifferential specified by Mask were all zero
// WBDesComp_Incomparable: the expected values of the affected nibbles differed in rDifferential 
//                         vis-a-vis the ones in lDifferential
WBDesCompResult CompareDifferentialsMasked(u8 *lDifferential, u8 *rDifferential, u8 *Mask)
{
  WBDesCompResult res = WBDesComp_Incomparable;
  bool bFirst = true;
  
  // Iterate through all bytes of the Mask
  for(int i = 0; i < 12; ++i)
  {
    if(Mask[i])
    {
      // Did the mask indicate that a change might occur in one of these two nibbles,
      // and in fact no change occurred?
      if((rDifferential[i] & Mask[i]) == 0)
      {
        // Is this our first time matching? If so, set the result indicating the nibble was not modified
        if(bFirst)
          res = WBDesComp_Unmodified;
        
        // Otherwise, did the previous mask position nibble match? Then we have conflictory results.
        else if(res == WBDesComp_Identical)
          res = WBDesComp_Incomparable;
      }

      // The mask indicated that a change might occur, and a change did in fact occur.
      // Were the modifications identical to those in the other differential?
      else
      if((lDifferential[i] & Mask[i]) == (rDifferential[i] & Mask[i]))
      {
        // Is this our first time matching? If so, set the result indicating the nibble was modified in an identical way
        if(bFirst)
          res = WBDesComp_Identical;
        
        // Otherwise, did the previous mask position nibble not match? Then we have conflictory results.
        else if(res == WBDesComp_Unmodified)
          res = WBDesComp_Incomparable;
      }
      
      // Otherwise, the results conflicted.
      else
        res = WBDesComp_Incomparable;
      
      bFirst = false;
    }
  }
  return res;
}

// Go nibble-by-nibble through the differential array. For any non-zero nibbles,
// mark the output with an 0xF nibble.
void ComputeNibbleBitmask(u8 *Differential, u8 *DifferentialMask)
{
  for(int i = 0; i < 12; ++i)
  {
    if((Differential[i] & 0x0F) != 0) DifferentialMask[i] |= 0x0F;
    if((Differential[i] & 0xF0) != 0) DifferentialMask[i] |= 0xF0;
  }
}

// Inputs:
// KeyPossibilities: a list of not-yet-filtered-out key possibilities
// KeyBit0: those partial keys in 0 <= k < 1<<6 whose SBox output for the specified bit was 0
// KeyBit1: those partial keys in 0 <= k < 1<<6 whose SBox output for the specified bit was 1
// rComb: the XOR mask for the SBOX input (i.e. the bits from the right-hand input)
// bShouldBeInDifferentSets: whether SBOX[k][bit] and SBOX[k^rComb][bit] should differ
// Returns:
// Modifies the KeyPossibilities list to remove those which failed the tests
void FilterKeyPossibilities(std::list<u8> &KeyPossibilities, std::set<u8> &KeyBit0, std::set<u8> &KeyBit1, u8 rComb, bool bShouldBeInDifferentSets)
{
  // Iterate through all keys that have not yet been discarded
  for(std::list<u8>::iterator i = KeyPossibilities.begin(); i != KeyPossibilities.end(); /*update handled in loop*/)
  {
    // Determine in which set the key lies (SBox output was 0 vs. 1)
    bool kInSet0 = KeyBit0.find(*i) != KeyBit0.end();

    // Determine in which set key^rComb lies (SBox output was 0 vs. 1)
    bool rCombInSet0 = KeyBit0.find(*i ^ rComb) != KeyBit0.end();
    
    // Were they in the same set?
    bool bInSameSet = (kInSet0 && rCombInSet0) || (!kInSet0 && !rCombInSet0);
    
    // If they were in the same set and should have been in different sets, or
    // if they were in different sets but should have been in the same set,
    // then differential analysis has discarded this key.
    if((bInSameSet && bShouldBeInDifferentSets) || (!bInSameSet && !bShouldBeInDifferentSets))
    {
#ifdef VERBOSE_DEBUG
      printf("Filtering key %d\n", *i);
#endif
      // Key was bad, remove it
      KeyPossibilities.erase(i++);
    }
    else
      ++i;
  }
}

// Derived from the DES specification: the set of 6 input bits, and 4 output bits,
// involved in a single DES SBOX computation.
struct SBoxInOut
{
  u8 nGroup;
  u8 InputBits[6];
  u8 OutputBits[4];
};

// The real values for the structure just described.
SBoxInOut SBoxBitMappings[8] = 
{
{ 0, { 7, 57, 49, 41, 33, 25, }, { 34, 52, 16, 38 } },
{ 1, { 33, 25, 17, 9, 1, 59, },  { 54, 42, 28, 56 } },
{ 2, { 1, 59, 51, 43, 35, 27, }, { 18, 20, 32, 30 } },
{ 3, { 35, 27, 19, 11, 3, 61, }, { 22, 0, 44, 62 } },
{ 4, { 3, 61, 53, 45, 37, 29, }, { 6, 12, 26, 8 } },
{ 5, { 37, 29, 21, 13, 5, 63, }, { 46, 40, 60, 58 } },
{ 6, { 5, 63, 55, 47, 39, 31, }, { 10, 14, 24, 36 } },
{ 7, { 39, 31, 23, 15, 7, 57, }, { 48, 50, 2, 4 } },
};

// This implements the differential cryptanalysis attack described in SysK's paper.
DWORD WINAPI Attack(LPVOID)
{
  // Begin by computing the whitebox round-1 output for the plaintext of all zeroes.
  u8 nullaryOutput[12];
  ComputeRound1Output(NULL, 0, 0, nullaryOutput);
  
#ifdef VERBOSE_OUTPUT
  printf("Round-1 output for nullary: ");
  PrintWBState(nullaryOutput);
#endif

  // Iterate through all 8 6-bit partial subkeys and their associated SBoxes
  for(int i = 0; i < 8; ++i)
  {
    // Initially, set the list of all key possibilities to all 64 partial subkeys
    std::list<u8> KeyPossibilities;
    for(int j = 0; j < 1<<6; ++j)
      KeyPossibilities.push_back(j);

    // Iterate through all 4 output bits of the SBox
    for(int j = 0; j < 4; ++j)
    {
      // Create two sets, for whether the SBox output bit for that key was 0 or 1
      std::set<u8> KeyBit1, KeyBit0;
      for(int k = 0; k < 1<<6; ++k)
      {
        // For each key, get the SBOX value, and mask off just the desired bit
        // Having erroneously written "i" instead of "7-i" cost me several hours :(
        if(DES::SBOX[7-i][k] & (1 << j))
          KeyBit1.insert(k);
        else
          KeyBit0.insert(k);                
      }

      // Compute the differential for the single left-hand side bit associated with
      // that SBox output bit (differential is computed against the nullary plaintext)
      u8 lBitDifferential[12];
      ComputeRound1Differential(&SBoxBitMappings[i].OutputBits[j], 1, 1, lBitDifferential, nullaryOutput);

#ifdef VERBOSE_DEBUG
      PrintDifferential(i, SBoxBitMappings[i].OutputBits[j], lBitDifferential);
#endif

      // Compute the bitmask for lBitDifferential indicating the two non-zero nibbles
      u8 lBitDifferentialMask[12];
      memset(lBitDifferentialMask, 0, sizeof(lBitDifferentialMask));
      ComputeNibbleBitmask(lBitDifferential, lBitDifferentialMask);

#ifdef VERBOSE_DEBUG
      printf("Differential bitmask: ");
      PrintDifferential(i, j, lBitDifferentialMask);
#endif
      
      // Iterate through all 64 combinations of right-hand input bits (those XORed
      // against the key to produce the SBox index)
      for(int rComb = 1; rComb < 1<<6; ++rComb)
      {
        // Compute the differential between the round-1 output for that 
        // combination of right-hand input bits, against the round-1 output
        // for the nullary plaintext.
        u8 rCombDifferential[12];
        ComputeRound1Differential(SBoxBitMappings[i].InputBits, 6, rComb, rCombDifferential, nullaryOutput);
        
        // Compare the left-hand (odd) bit differential against the right-hand (even) bits
        // differential for this particular combination of input bits.
        WBDesCompResult comp = CompareDifferentialsMasked(lBitDifferential, rCombDifferential, lBitDifferentialMask);
        
#ifdef VERBOSE_DEBUG
        printf("Comparison result = %d ", comp);
        PrintDifferential(i, rComb, rCombDifferential);
#endif

        // If the modified nibbles in the right-hand differential were not either
        // A) identical to those in the left-hand differential, OR
        // B) entirely unmodified, 
        // Then this does not give us information with which to filter the key possibilities.
        if(comp != WBDesComp_Incomparable)
        {
          // If CompareDifferentialsMasked() returns WBDesComp_Identical, that 
          // means that the differential for the right-hand bits specified by 
          // rComb induced the same modification as the differential for the
          // left-hand bit. Thus, the key by itself produces either 0/1, and
          // the differential with rComb produces the opposite bit 1/0. Hence,
          // we have a relation: RELEVANTBIT(SBOX[k]) != RELEVANTBIT(SBOX[k^rComb]).
          // In other words, k and k^rComb should be in different sets (see the
          // declaration and initialization of KeyBit0 and KeyBit1, above).

          // Otherwise, if it returns WBDesComp_Unmodified, then we have the 
          // relation: RELEVANTBIT(SBOX[k]) == RELEVANTBIT(SBOX[k^rComb]).
          // In other words, k and k^rComb should be in the same set (see the
          // declaration and initialization of KeyBit0 and KeyBit1, above).

          // Use the relation just described to filter out possible keys.
          FilterKeyPossibilities(KeyPossibilities, KeyBit0, KeyBit1, rComb, comp == WBDesComp_Identical);
        }
      }
    }
    
    // Once we get here, we have filtered the subkey by all of the definitive
    // relations we generated above.
    printf("Remaining subkey possibilities for group %d:\n", i);

    // Print them.
    for(std::list<u8>::iterator j = KeyPossibilities.begin(); j != KeyPossibilities.end(); ++j)
      printf("\t%d\n", *j);
  }
  exit(0);
  return 0;
}

/* Output: [these subkeys are correct; see for example https://github.com/SideChannelMarvels/Deadpool/wiki/Tutorial-%231:-DCA-against-Wyseur-2007-challenge]
Remaining subkey possibilities for group 0:
	7
Remaining subkey possibilities for group 1:
	15
Remaining subkey possibilities for group 2:
	32
Remaining subkey possibilities for group 3:
	49
Remaining subkey possibilities for group 4:
	44
Remaining subkey possibilities for group 5:
	50
Remaining subkey possibilities for group 6:
	2
Remaining subkey possibilities for group 7:
	20
*/

// DllMain(), which hooks wbDES.exe's .text section, creates the attack thread,
// and initializes the Event objects that main thread hook and attack thread 
// use to communicate with one another.
BOOL APIENTRY DllMain(HMODULE hModule,DWORD ul_reason_for_call,LPVOID lpReserved)
{
  // MessageBoxA(NULL, "ATTACH", "ATTACH", 0);

  // Only hook once
  static bool bInstalled = false;
  if(!bInstalled)
  {
    bInstalled = true;

    // Install the two hooks into our ASM stubs above.
    WriteJump((unsigned long)g_WBInitHookLocation,  (unsigned long)&HookWBInitASM, GetCurrentProcess());
    WriteJump((unsigned long)g_WBRoundHookLocation, (unsigned long)&HookWBRoundASM, GetCurrentProcess());

    // Create the event objects used for communication.
    g_ReadyToComputeEvent       = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_ComputationFinishedEvent  = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_ComputationRequestedEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    
    // Create the attack thread.
    CreateThread(NULL, 0, Attack, NULL, 0, NULL);
  }
  return TRUE;
}
