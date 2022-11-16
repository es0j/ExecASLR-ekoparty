#include <stdio.h>

void DoNothing();

void (*codePtr)() = DoNothing;

void DoNothing(){
    return;
}

int main(int argc,char **argv){

    printf("Destination %p\n",codePtr);
    while(1){
        asm __volatile__(
            "mov eax,200    \n"
            "dec eax        \n"
            "jnz $-0x2      \n"
            ".rept 1       \n"
            "nop            \n"
            "nop            \n"
            "nop            \n"
            ".endr          \n"
            "lea rdi,%0     \n"
            "call [rdi]     \n"
            :
            :"m"(codePtr)
            :"rdx"
        );        
        //usleep(1);
    }
}