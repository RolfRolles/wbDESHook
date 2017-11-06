This is my DLL-injection based solution to Brecht Wyseur's wbDES challenge [1], originating from his Ph.D. thesis [0], and described in SysK's Phrack article "Practical Cracking of White-Box Implementations" [2]. To make a long story short, I initially set about implementing the Differential Computation Analysis-based attack [3-4] as a shortcut to reading SysK's solution, but ran into issues with my implementation. (Although both of those authors released their source code, I decided to use their publications as a starting point for developing my own code rather than using the tools they released, for maximum educational purposes.) After spending far too long debugging it, I decided to bite the bullet and read SysK's article (which, ironically, took much less time to implement and debug) in the hopes that I could use that knowledge to fix my differential computation analysis code. That latter piece of work remains to be done.

The source code herein consists of a working implementation for breaking the wbDES challenge. Rather than decompiling and re-implementing the wbDES logic (as did SysK), I decided to go with a real-world attack scenario using DLL injection. To wit, my DLL hooks into the wb_init() and wb_round() functionality in wbDES.exe, and another thread then uses the original functionality as a black box to produce the necessary vectors for differential cryptanalysis. Then, the differential attack described by SysK is implemented from-scratch according to my understanding of SysK's approach. 

The TL;DR version of SysK's approach: from reading the DES specification, you can determine which bits are involved in the round-0 computation of the S-BOX indices, and which input bits are XORed against each S-BOX's output. Then, you can use differential cryptanalysis to determine "the rough location" where those bits are located within the white-box state (that's a simplification), by toggling those individual bits and examining the relationship with the output from where those bits were not toggled. Since the S-BOX lookup is key-dependent, these pieces of information combined gives you a set of constraints that the subkey for that S-BOX must satisfy. E.g. if I toggled the 0th bit in the right-hand S-BOX input and the output did not change in the 2nd bit, then I must have that SBOX[k] & 0x4 == SBOX[k^1] & 0x4, which allows you to discard values of k that do not satisfy this property for the relevant S-BOX. Repeat for all 2^6 right-hand S-BOX input XOR values (where feasible -- not every XOR mask will be feasible due to how the white-box state is encoded), and at the end you will have a unique 6-bit key that satisfied all constraints. Repeat for all 8 SBOXes to recover the complete 48 round subkey one six-bit group at a time, additively, and then the full 56-bit symmetric key can be determined by a 2^8*DES()-complexity brute-force. This takes milliseconds.

As for my implementation, I experienced issues injecting my DLL into wbDES.exe. After eventually tracking down the culprit functionality to the Cygwin CRT code, I decided that on an alternative approach to DLL injection -- namely, adding an IMAGE_IMPORT_DESCRIPTOR to wbDES.exe and forcing it to load my DLL that way. So if you want to tinker with my code, you'll need to do the same thing to wbDES -- a tool called IIDKing [5] will make this easy.

[0] http://www.whiteboxcrypto.com/research.php

[1] http://www.whiteboxcrypto.com/challenges.php

[2] http://phrack.org/issues/68/8.html

[3] https://eprint.iacr.org/2015/753.pdf

[4] https://github.com/SideChannelMarvels/Deadpool/tree/master/wbs_des_wyseur2007

[5] https://tuts4you.com/download.php?view.413

[6] https://en.wikipedia.org/wiki/DES_supplementary_material#Initial_permutation_.28IP.29


Rambling errata:

As usual when implementing cryptography or cryptanalysis, the thing that costs me the most time is indexing issues: some publications start counting at one; some of them start counting bits MSB rather than the LSB; and so on. These issues can multiply atop one another. 

Beyond plaguing my implementation, those issues also played a role in SysK's write-up. Specifically, SysK describes the DES initial permutation IP as moving all of the odd bits into the upper 32-bit quantity, which is then called L (for "left-hand side") within most treatments of DES. And indeed, a cursory examination of the DES IP table would give you the same impression [6].

However, note that the table refers to bits indexed starting at *1* (i.e., 0 does not appear in that table). So if you start indexing your bits at zero -- as SysK does in his publication -- it's actually true that the *even* bits are permuted into L, rather than the odd ones. But wait! That's only true if you start indexing from the LSB. Actually, SysK indexes from 0 starting at the MSB, so all is well with the world again (in that the so-called "odd" bits are the same as the "even" bits when indexing from 0 at the LSB). Stemming from this, I experienced some confusion with an off-by-one issue (versus my own expectations of the nomenclature) in sections 6.2-6.3. Also due to indexing issues, my SBoxBitMappings table is different from his for reasons I only partially understand. Nevertheless, my implementation does produce the correct round-0 subkey, so it works.

If all of that is gibberish to you, consider yourself lucky! I spent about two days confused before I fixed those issues.

