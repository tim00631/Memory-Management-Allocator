#include "lib/hw_malloc.h"
#include "hw4_mm_test.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#define BLOCK_SIZE 24
#define BUFFERSIZE 100
int main(int argc, char *argv[])
{
    start_address = get_start_sbrk();
    char buffer[BUFFERSIZE];
    while (fgets(buffer, BUFFERSIZE, stdin))
    {
        char *instr = strtok(buffer, " ");
        char *arg = strtok(NULL, " ");
        if(!strcmp(instr,"alloc")){
            size_t bytes = atoi(arg);
            void* addr = hw_malloc(bytes);
            if (addr){
                if ((ull)addr < (ull)sbrk(0) && (ull)addr >= (ull)start_address){
                    printf("0x%012llx\n", (ull)addr-(ull)start_address);
                }
                else{
                    printf("0x%012llx\n", (ull)addr);
                }
            }
            else {
                printf("malloc fail.\n");
            }
        }
        else if(!strcmp(instr,"free")){
            void *data_addr = (void *)strtoull(&arg[2], NULL, 16);//0xffffff0000
            //printf("arg:0x%012llx\n", (ull)data_addr);
            chunk_ptr_t chunk_addr;
            if (arg[2] == '7')
            {
                chunk_addr = (chunk_ptr_t)((ull)data_addr - (ull)24);
            }
            else{
                chunk_addr = (chunk_ptr_t)((ull)data_addr - (ull)24 + (ull)start_address);
            }
            //printf("0x%012llx\n", (ull)chunk_addr - (ull)start_address);
            if(hw_free(chunk_addr)){
                printf("success\n");
            }
            else{
                printf("fail\n");
            }
        }
        else if(!strcmp(instr,"print")){
            if(arg[0]== 'b'){
                int index = -1;
                sscanf(arg, "bin[%d]", &index);
                if(index>= 0 && index < 11){
                    print_bin_i(index);
                }
            }
            else if(arg[0]=='m'){
                print_mmap_i();
            }
            else{
                // chunk_ptr_t test = (chunk_ptr_t)strtoull(&arg[2], NULL, 0);
                // chunk_ptr_t chunk_addr = (chunk_ptr_t)((ull)test - 24 + (ull)start_address);
                // chunk_ptr_t next_addr = (chunk_ptr_t)((ull)chunk_addr + chunk_addr->size_and_flag.curr_chunk_size);
                // printf("alloc_flag:%d\n", chunk_addr->size_and_flag.alloc_flag);
                // printf("curr_chunk_size:%d\n", chunk_addr->size_and_flag.curr_chunk_size);
                // printf("prev_chunk_size:%d\n", chunk_addr->size_and_flag.prev_chunk_size);
                // printf("next_flag:%d\n", next_addr->size_and_flag.alloc_flag);
                // printf("next_chunk_size:%d\n", next_addr->size_and_flag.curr_chunk_size);
                // printf("prev_chunk_size:%d\n", next_addr->size_and_flag.prev_chunk_size);
                
                for (int i = 10; i >= 0; i--)
                {
                    print_bin_i(i);
                }
            }
        }
        else {
            //printf("Not Supported instr\n");
        }
        memset(buffer, 0, sizeof(buffer));
    }
    return 0;
}
