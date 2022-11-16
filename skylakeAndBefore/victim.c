#include <stdio.h>

void DoNothing();

void (*codePtr)() = DoNothing;

void DoNothing(){
    return;
}

int main(int argc,char **argv){

    printf("Destination %p\n",codePtr);
    while(1){
        for(int i=0;i<30;i++){}

        asm __volatile__(
            "lea rdi,%0     \n"
            "call [rdi]     \n"
            :
            :"m"(codePtr)
            :"rdx"
        );        
    }
}