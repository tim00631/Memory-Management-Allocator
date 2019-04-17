#ifndef HW_MALLOC_H
#define HW_MALLOC_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
typedef struct _chunk_info_t
{
    unsigned int prev_chunk_size : 31; //連續記憶體的 bit field
    unsigned int curr_chunk_size : 31;
    unsigned int alloc_flag : 1;
    unsigned int mmap_flag : 1;
} chunk_info_t;

typedef struct _chunk
{
    struct _chunk *prev; //bin 
    struct _chunk *next;
    chunk_info_t size_and_flag;
} chunk;

typedef struct _chunk *chunk_ptr_t;
typedef unsigned long long ull;
chunk_ptr_t bin[11];
chunk_ptr_t mmap_alloc_list;
chunk_ptr_t start_address;
void *hw_malloc(size_t bytes);
int hw_free(void *mem);
void *get_start_sbrk(void);
chunk_ptr_t split(chunk_ptr_t curr_chunk, unsigned int alloc_size);
chunk_ptr_t first_malloc_split(chunk_ptr_t curr_chunk, unsigned int alloc_size);
void add_to_bin(chunk_ptr_t chunk);
void delete_from_bin(chunk_ptr_t chunk);
chunk_ptr_t bin_find_rear(int index);
chunk_ptr_t bin_find_chunk(int index, chunk_ptr_t chunk);
int getlog2(unsigned int chunk_size);
void merge(chunk_ptr_t curr_chunk);
void print_bin_i(int index);
chunk_ptr_t find_bin_space(int index);
void add_to_mmap_list(chunk_ptr_t chunk);
void bin_init();
void mmap_list_init();
void delete_from_mmap(chunk_ptr_t chunk);
void print_mmap_i();
#endif
