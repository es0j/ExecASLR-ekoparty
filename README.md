# ExecASLR - Abusing Intel branch predictors to bypass ASLR

slide: https://docs.google.com/presentation/d/10t-oo-c26x9ydx1_FYgmhy204rxfmQ92eboPlCnA2y4/edit?usp=sharing


## What is ASLR

Address Space Layout Randomization is a mitigation used to make harder to exploit memory corruption attacks. In a scenario of a buffer overflow vulnerability, for example, an attacker that tries to make a Return Oriented Programing exploit needs to know the addresses of the gadgets in the chain. If the code segment of the exploited binary is randomized, then it's much harder for an attacker to pick the correct address for the exploit, making the exploitation unfeasible.

The following example shows how an address is randomized:

```.c
#include <stdio.h>
void DoNothing();
void (*codePtr)() = DoNothing;

void DoNothing(){}

int main(int argc,char **argv){

    printf("Destination %p\n",codePtr);
    DoNothing();
}


```
Each execution the value is randomized:

```
Destination 0x563714256149
Destination 0x556d8e2f1149
Destination 0x5618c8bdd149
Destination 0x55ee623b0149
```
The last 12 bits `149` are always the same, but the location of the function can be roughly anywhere between 0x550000000000 and 0x570000000000, meaning that 29 bits are randomized, occupying a possible address space of 0x200 0000 0000 or  2.2 TB of size. 

## CPU pipeline
The processing of each instruction is a hard task. Some stages of the processing of a single instruction are:
- Fetching the instruction;
- decoding the instruction;
- Executing operations in the Arithmetic Logic Unity


In order to increase the throughput of instructions in the CPU, each task of the instruction is performed by a specific unity of the processor. With all the unities working in parallel, it allows the CPU to execute at much higher clock speeds, that's the idea of a pipeline.


|Operation \ clock cycle| 1 | 2 | 3 | 4 |5  |
|--------|---|---|---|---|---|
|Fetch | A| B | C |
|Decoding | | A| B | C| 
|Execution| | | A| B | C|


*Execution of instructions A B and C over the cycles 1-5. In cycle 3, for example, the read, decoding and execution unities are simultaneously active*

However, instructions are not completely independent from each other. For example, the following sequence:
```.asm
A. add ax,[bx]
B. jz $+1
C. mov dl,[rsi]  
D. nop
```
In this case, the A instruction in the best case will only finish on the cycle 3 in the execution. However, the fetch unity needs to decide what's the next instruction to be fetched from memory, whether instruction C (`mov dl,[rsi]`) should be skipped.
In this scenario, the CPU has the option to wait for the instruction A to finish, that will only happen in the third clock cycle to then fetch the correct instruction on the memory, if the add operation returns 0, for example:

|Operation \ clock cycle| 1 | 2 | 3 | 4 |5  |6  |
|--------|---|---|---|---|---|---|
|Fetch | A| B |  | D|
|Decoding | | A| B | | D|
|Execution| | | A| B | |D|

That implies in a delay in the pipeline because the CPU must wait for the instruction to get executed. In this example the delay is a single clock cycle, but the instruction `add ax,[bx]` requires a memory operation, which, as seen before, can take up to hundreds of cycles to complete, thus leveraging a significant performance cost on the processor.

A faster option would be trying to "guess" the correct execution path. The CPU can *speculate* if the branch is taken or not. After that point, the execution continues from the speculated path and the values are only committed if the path is proven correct after the finish of the A instruction. If the path is proven wrong, the results are discarded and the state is reverted to before the speculated point.

|Operation \ clock cycle| 1 | 2 | 3 | 4 |5  |6  |
|--------|---|---|---|---|---|---|
|Fetch | A| B |(S) C | |
|Decoding | | A| B |(S) C | |
|Execution| | | A| B |(S) C ||

The only problem in reverting the path taken is that the microarchitectural state of the CPU cannot be reverted. So if the CPU speculates to execute the instruction C (`mov dl,[rsi]`) the data pointed by `rsi` will be moved to the cache. This effect can be measured later using a side channel attack.

![](https://i.imgur.com/FwIv8Ux.png)
*2 Bit conditional predictor. https://en.wikipedia.org/wiki/Branch_predictor*


## Spectre V2 (Branch Target Injection)



Not only conditional instructions must be predicted, but also indirect branches. The CPU must have a mechanism for guessing the destinations of an instruction as `call [rdi]`.

The spectre v2 vulnerability shows that it's possible to exploit the indirect predictor to achieve transient execution in other processes:
![](https://i.imgur.com/yhXvybg.png)
*Extracted from https://spectreattack.com/spectre.pdf*

When placing a call instruction on context A in the same virtual address of another call in context B, the attacker can train the CPU to execute code on a position chose by the attacker on context B, in a code reuse attack, similar as Return Oriented Programing (ROP).

The targeted victim must have a piece of code known as "spectre gadget" that is able to leak a secret using a side channel attack. For a successful spectre attack, the attacker must also know the location of the spectre gadget. Therefore, in user-user attacks, protecting the victim with ASLR used to be a mitigation for this kind of attack. However, there are also techniques for extracting ASLR using microarchitectural attacks such as Jump Over ASLR. However, this technique has some limitations about the amount of bits leaked, since it relies collision on the direct predictor to bypass ASLR.

The internals mechanisms of this predictor are shown below:
![](https://i.imgur.com/SlAOYmV.png)

*Extracted from https://spectreattack.com/spectre.pdf*

Some of these components are:

- The Branch Target Buffer(BTB);
    - The BTB is a cache like component that stores the destinations for the predictions. The BTB Stores the full 64 bit address of the destination and the number of entries available on the BTB depends on the architecture.
- The Branch History Buffer(BHB);
    - The BHB stores a "hash" of the recent flow execution. Each branch instruction writes to the BHB. On skylake CPUs and before, the BHB can store the context of the last 29 branches. On icelake the BHB stores up to ~100 branches. Not that the BHB only uses the 20LSBs from the branches to create the hash, which 12 are not randomized.
- The Indirect predictor;
    - Uses only the 12 LSBs from the indirect branch instruction to determine the full 64 bit destination. Exec ASLR leaks the 64 bit pointer from the BTB to fully recover ASLR addresses.
- The Direct branch predictor
    - Uses the 30 LSBs from the source address to predict to a 32 bit value. The other half of the address is reused from the source. The Jump Over ASLR attack exploits collisions in this predictor to find a source address that collides with another context, therefore it is limited to only leak 30LSBs from the victim context.
 
The classical spectre v2 attack layout looks like this:

![](https://i.imgur.com/3dJEOm6.png)


- The Attacker places an indirect branch in the same position as the victim branch, but the destination matches a spectre gadget on the victim context
- When the victim executes the branch, it misspredicts and the spectre gadget loads a secret and make a conditions access to a shared memory region such as a library. For example, the spectre gadget that executes `getenv + secret[0]*4096` can leak the value of secret at position 0 using the libc as shared memory.
- The attacker then retrieves the secret leaked by detecting what parts of the shared memory were moved to cache using a flush+reload attack

## Exec ASLR

Exec ASLR (aka Reverse Branch Target Buffer Poisoning) is a novel technique to bypass ASLR using spectre-BTI vulnerability. This attack abuses the fact that not only the attacker can polute the BTB in a classic spectre-BTI scenario, but victims can also trigger a branch missprediction in the attacker process, leading the attacker to speculative jump to a address protected by ASLR. Then using a side channel that leaks what address is being executed, an attacker can retrieve the full destination address, bypassing ASLR for the targeted process.

The layout of the Exec ASLR attack looks like this:
![](https://i.imgur.com/lzErW0W.png)

- Victim executes an indirect branch, that writes it´s randomized destination pointer (0x55aabbeef456) into BTB
- Attacker places an indirect branch in a 12LSB alligned address. Since the 12LSBs are not randomized this part is trivial.
- Attacker fills all possible locations of the memory with a "leak gadget" that tells the attacker "Im executing at this address!" using probeArray as side channel.
- When the attacker executes the indirect branch, it misspredicts to one of the many leak gadgets in memory
- The attacker uses a flush+reload attack to recover if ProbeArray was accessed or not when speculating. 

In this kind of attack, there is no need for finding a spectre gadget nor having a shared memory for the side channel, the only requirement is an indirect branch to be exploited, all the required gadgets of a spectre v2 are placed inside the attacker process. The only new requirement for this attack is being able to map the destination address of the victim into your own process, therefore this attack can't work against KASLR for example.
This isn't a bruteforce attack too, with a single try its possible to test multiple addresses at the same time, however there is a limit of how many "leak gadgets" the memory can hold at the same time. This significativly decreaes the time to perform the attack when compared to Jump Over ASLR from ~100 addresses per second to a few hundreds of billions of addresses per second.

### Leak gadget
The leak gadget uses probeArray to inform the attacker where the own gadget is executed. It receives probeArray and the index of RIP to be leaked as argument and performs a kind of branchless programing to decide whether probeArray[0] or probeArray[4096] should be accessed.

```.nasm
lea rax,[rip - 7]      ;load current address
shr rax,cl             ;selects the bit using cl arg
and rax,1
shl rax,12             ;loads probearray
mov dl,[rsi+rax]       ;or probearray+4096
```

### Controling the BHB and target victim code
As seen before, the BHB is used to select a BTB entry. In order to find a BTB collision and exploit this vulnerability, an attacker must know the last N (29 if <skylake) branches taken. In our tests, we used a for loop to set the state of the BHB to a known value before the indirect call. Here is a vulnerable example of victim code:
```.c
#include <stdio.h>

void DoNothing();
void (*codePtr)() = DoNothing;

void DoNothing(){
    return;
}

int main(){
    printf("Destination = %p\n",codePtr);
    while(1){
	for(int i=0;i<200;i++){}
    	codePtr();
    }
}

```

In order to ensure the BHB state is the same in the both contexts, the attacker copies the bytes corresponding to the victim for loop and call in form of a shellcode.The shellcode is copied to all possible 256 positions that can match the 20LSB alignment required for the BHB state to be the same.

```.asm
Victim Code

0x5594c566a152 <+28>:    mov    eax,0xc8
0x5594c566a157 <+33>:    dec    eax
0x5594c566a159 <+35>:    jne    0x1157 <main+33>
0x5594c566a15b <+37>:    nop
0x5594c566a15c <+38>:    nop
0x5594c566a15d <+39>:    nop
0x5594c566a15e <+40>:    lea    rdi,[rip+0x2ecb]
0x5594c566a165 <+47>:    call   QWORD PTR [rdi]

--> Executes to
0x5594c5669135:    ret

```

```.asm
Attacker Code

… //eax=200 rsi=probeArray, cl=0 
0x6a157    dec    eax
0x6a159    jne    0x455555500157
…
0x6a165    jmp    QWORD PTR [rdi]

--> Misspredicts to
0x5594c566a135:    lea rax,[rip - 7]
0x5594c566a13c:    shr rax,cl
0x5594c566a13f:    and rax,1
0x5594c566a133:    shl rax,12
0x5594c566a137:    mov dl,[rsi+rax]
```


### Challenges
There is a problem when trying to place a gadget into all possible positions at the same time. In our tests the ASLR places the destination somewhere between 0x550000000000 and 0x570000000000. Meaning that there is a 2.2TB of possible virtual address to be mapped or 537 million leak gadgets. But the system has only 8GB of RAM.
Besides being possible to map 2TB of ram using COW we haven't had much success with this approach. I suppose it creates too much pressure on the Translation Lookaside Buffer (TLB), making the speculation to a non-translated address way too slow.
In the tests we created a 1GB in memory page and filled with the leaking gadgets. Then we shifted the page across the 2TB range using the remap syscall.
Other problem observer was the fact that the speculated address was probably not present in the TLB, since it never had actually been executed. But intel manual states:
- "The processor may cache translations required for prefetches and for accesses that are a result of speculative execution that would never actually occur in the executed code path" - ISA
 
Therefore, in order to increase the chances of a "speculative induced" pagewalk we tried to make as hard as possible for the correct address to be resolved. This is done using a pointer chain for the destination address. The idea is that the CPU frontend will speculate the destination of the branch and the reorder unit will execute the leak gadget before finishing the pointer chain read.

```.asm
Improved Caller - Frontend fetched instructions
mov rcx,%1       ;mask arg for gadget
lea rsi,[%2]     ;probe array ptr arg
lea rdx,[%0]
mov rdx,[rdx]    ;pointer chain
mov rdx,[rdx]
mov rdx,[rdx]
...
mov rdx,[rdx]
mov rdx,[rdx]
check [rdx]      ;mispredicts to gadget

lea rax,[rip - 7];speculative execution
shr rax,cl
and rax,1
shl rax,12
mov dl,[rsi+rax]

```

```.asm
Improved Caller - Reorder unit scheduled instructions
mov rcx,%1    ;mask arg for gadget
lea rsi,[%2]  ;probe array ptr arg
lea rdx,[%0]
mov rdx,[rdx] ;pointer chain
mov rdx,[rdx]
; <pagewalk occurs some where here>
... ;Out of order + speculation
lea rax,[rip - 7]
shr rax,cl
and rax,1
shl rax,12
mov dl,[rsi+rax]
...
mov rdx,[rdx]
mov rdx,[rdx]
check [rdx] ;the execution path reverted

```
This technique of Out Of Order + Speculative execution showed an improvement in the desired missprediction rates in the attack

### Scheduling and STIBP
In order to perform a spectre V2 attack, the attacker must execute code in the same core as the victim, so they share the same Branch Prediction Unit (BPU). In CPUs <= skylake we observed that it's possible to achieve core coresidency using hyperthread.
Icelake and Cascade lake CPUs implement a mitigation called Single Thread Indirect Branch Predictor, that separates the BPU across threads. Therefore it's needed to execute the victim and the attacker at the same thread and use the usleep to alternate between victim and attacker process what would make the attacker slower on this CPUs if wasn't the fact that the caches (and probably the TLB too) is super good in those generations allowing to cache way more gadgets at the same time. 

### Results
This technique was tested on all intel CPUs available on google cloud, both on N1 and N2 generations:
- Sandy Bridge
- Ivy Bridge
- Haswell
- Broadwell
- Skylake 
- Cascadelake
- Icelake

Besides having some difference in the exploits for Cascade and Ice lake all tests are able to recover the addresses with >99% of precision under 10s.


### Mitigations
The mitigations are the same as Spectre V2 for mitigating user-user attacks. 
Indirect branch prediction barrier (IBPB) allows the flushing of the BPU and can be used on context switches. In linux the IBPB can be used through the `prctl` syscall with the `PR_SET_SPECULATION_CTRL` option. 
I have no idea what is the equivalent mitigation for windows, please tell me.



---
### Paper:

https://cos.ufrj.br/uploadfile/publicacao/3061.pdf

### Ekoparty talk:


{%youtube Qj4z-KvnkxU %}

### References:
### References:
https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html
https://eprint.iacr.org/2013/448.pdf
https://spectreattack.com/spectre.pdf
https://www.cs.ucr.edu/~nael/pubs/micro16.pdf
http://download.vusec.net/papers/bhi-spectre-bhb_sec22.pdf
https://www.kernel.org/doc/html/latest/userspace-api/spec_ctrl.html
Intel® 64 and IA-32 Architectures Software Developer’s Manual Volume
3. Santa Clara, USA: Intel Corporation, 2016, iSBN 325384-060US

