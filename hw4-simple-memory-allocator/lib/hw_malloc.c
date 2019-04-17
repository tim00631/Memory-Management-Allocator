#include "hw_malloc.h"
#include <sys/mman.h>
#define BLOCK_SIZE 24
#define mmap_threshold 32 * 1024

void *hw_malloc(size_t bytes)
{
    unsigned int alloc_size = bytes + 24;
    if (alloc_size > mmap_threshold)
    {
        chunk_ptr_t chunk = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (chunk == MAP_FAILED)
        {
            return NULL;
        }
        else
        {
            chunk->size_and_flag.mmap_flag = 1;
            chunk->size_and_flag.curr_chunk_size = alloc_size;
            chunk->size_and_flag.prev_chunk_size = 0;
            chunk->size_and_flag.alloc_flag = 0;
            add_to_mmap_list(chunk);
            //printf("%p\n", chunk);
            //printf("add_to_mmap_list completed\n");
            void *data_addr = (void *)((ull)chunk + 24);
            return data_addr;
        }
    }
    else
    {
        chunk_ptr_t chunk;
        for (size_t space = 32; space <= 32 * 1024; space = space * 2)
        {
            if (space >= alloc_size)
            {
                //printf("malloc size:%ld\n", space);
                int index = getlog2(space) - 5;
                //printf("index:%d\n", index);
                chunk = find_bin_space(index);
                chunk = split(chunk, alloc_size);
                //printf("malloc:%p\n", chunk);
                //printf("chunk addr:0x%012llx\n", (ull)chunk - (ull)start_address);
                void *data_addr = (void *)((ull)chunk + 24);
                return data_addr;
            }
        }
    }
    return NULL;
}

int hw_free(void *mem)
{
    chunk_ptr_t chunk = (chunk_ptr_t)(mem);
    //printf("free:chunk %p\n", chunk);
    if (chunk->size_and_flag.mmap_flag)
    {
        delete_from_mmap(chunk);
        munmap(chunk, chunk->size_and_flag.curr_chunk_size);
        return 1;
    }
    else
    {
        chunk->size_and_flag.alloc_flag = 0;
        merge(chunk);
        return 1;
    }
    return 0;
}

void *get_start_sbrk(void)
{
    chunk_ptr_t heap = (chunk_ptr_t)sbrk(64 * 1024);
    bin_init();
    mmap_list_init();
    //printf("sbrk\n");
    heap->next = NULL;
    heap->prev = NULL;
    heap->size_and_flag.alloc_flag = 0;
    heap->size_and_flag.curr_chunk_size = 64 * 1024;
    heap->size_and_flag.prev_chunk_size = 0;
    heap = first_malloc_split(heap, 32 * 1024);
    //printf("heap_curr_size:%d\n", heap->size_and_flag.curr_chunk_size);
    //printf("=====after first malloc=====\n");
    //print_bin_i(10);
    //print_bin_i(9);
    start_address = heap;
    return start_address;
}

chunk_ptr_t split(chunk_ptr_t curr_chunk, unsigned int alloc_size)
{
    unsigned int curr_size = curr_chunk->size_and_flag.curr_chunk_size; //get current_chunk size
    if (curr_size / 2 >= alloc_size)
    {
        delete_from_bin(curr_chunk);
        chunk_ptr_t third_chunk = (chunk_ptr_t)((ull)curr_chunk + curr_size);
        chunk_ptr_t second_chunk = (chunk_ptr_t)((ull)curr_chunk + (curr_size / 2));
        third_chunk->size_and_flag.prev_chunk_size = (curr_size / 2);
        second_chunk->size_and_flag.curr_chunk_size = (curr_size / 2);
        second_chunk->size_and_flag.prev_chunk_size = (curr_size / 2);
        second_chunk->size_and_flag.alloc_flag = 0;
        second_chunk->size_and_flag.mmap_flag = 0;
        curr_chunk->size_and_flag.curr_chunk_size = (curr_size / 2);
        add_to_bin(second_chunk);
        add_to_bin(curr_chunk);
        return split(curr_chunk, alloc_size);

    }
    else
    {
        curr_chunk->size_and_flag.alloc_flag = 1;
        delete_from_bin(curr_chunk);
        return curr_chunk;
        //best fit curr_chunk
    }
}

chunk_ptr_t first_malloc_split(chunk_ptr_t curr_chunk, unsigned int alloc_size)
{
    unsigned int curr_size = curr_chunk->size_and_flag.curr_chunk_size; //get current_chunk size
    chunk_ptr_t low_chunk = curr_chunk;
    if (curr_size / 2 >= alloc_size)
    {
        //printf("curr_size:%d\n", curr_size);
        chunk_ptr_t high_chunk = (chunk_ptr_t)((ull)curr_chunk + curr_size / 2);
        high_chunk->size_and_flag.alloc_flag = 0;
        high_chunk->size_and_flag.mmap_flag = 0;
        high_chunk->size_and_flag.prev_chunk_size = (curr_size / 2);
        high_chunk->size_and_flag.curr_chunk_size = (curr_size / 2);
        low_chunk->size_and_flag.alloc_flag = 0;
        low_chunk->size_and_flag.mmap_flag = 0;
        low_chunk->size_and_flag.curr_chunk_size = (curr_size / 2);
        low_chunk->size_and_flag.prev_chunk_size = 0;
        //printf("error at first malloc 2\n");
        //printf("after split,size is:%d\n", low_chunk->size_and_flag.curr_chunk_size);
        add_to_bin(high_chunk);
        //printf("add high_chunk:%p\n", high_chunk);
        add_to_bin(low_chunk);
        //printf("add low chunk:%p\n", low_chunk);
        //printf("last:%p\n", bin[10]->prev);
    }
    return low_chunk;
}

void add_to_bin(chunk_ptr_t chunk)
{
    int index = getlog2(chunk->size_and_flag.curr_chunk_size) - 5;
    if (index > 10 || index < 0)
    {
        //printf("bin index overflow :%d\n", index);
        return;
    }
    bin[index]->size_and_flag.curr_chunk_size++;
    chunk_ptr_t last = bin_find_rear(index);
    chunk->next = last->next;
    last->next->prev = chunk;
    last->next = chunk;
    chunk->prev = last;
}
void delete_from_bin(chunk_ptr_t chunk)
{
    int index = getlog2(chunk->size_and_flag.curr_chunk_size) - 5;
    if (index > 10 || index < 0)
    {
        //printf("bin index overflow :%d\n", index);
        return;
    }
    //printf("goto bin[%d] to find chunk\n", index);
    bin[index]->size_and_flag.curr_chunk_size--;
    chunk_ptr_t to_be_remove = bin_find_chunk(index, chunk);
    to_be_remove->prev->next = to_be_remove->next;
    to_be_remove->next->prev = to_be_remove->prev;
}

chunk_ptr_t bin_find_rear(int index)
{
    chunk_ptr_t ptr = bin[index]->prev;
    //printf("HEAD:%p\n", bin[index]);
    //printf("TAIL:%p\n", ptr);
    //printf("rear:0x%012llx\n", (ull)ptr - (ull)start_address);
    return ptr;
}
chunk_ptr_t bin_find_chunk(int index, chunk_ptr_t chunk)
{
    //printf("hi,enter bin_find_chunk\n");
    //printf("target:0x%012llx\n", (ull)chunk-(ull)start_address);
    //printf("index:%d\n", index);
    chunk_ptr_t ptr = bin[index]->next;
    while ((ull)ptr != (ull)chunk)
    {
        if ((ull)ptr->next != (ull)bin[index])
        {
            //printf("ptr = ptr->next\n");
            ptr = ptr->next;
        }
        else
        {
            return NULL;
        }
    }
    //printf("target:0x%012llx\n", (ull)ptr - (ull)start_address);
    return ptr;
}

int getlog2(unsigned int chunk_size)
{
    int i = 0;
    unsigned int temp = chunk_size >> 1;
    while (temp != 0)
    {
        i++;
        temp = temp >> 1;
    }
    return i;
}
void merge(chunk_ptr_t curr_chunk)
{
    //printf("hello, this is merge\n");
    //printf("%d\n", curr_chunk->size_and_flag.curr_chunk_size);
    unsigned int curr_size = curr_chunk->size_and_flag.curr_chunk_size;
    unsigned int prev_size = curr_chunk->size_and_flag.prev_chunk_size;
    chunk_ptr_t prev_chunk = (chunk_ptr_t)((ull)curr_chunk - (ull)prev_size);
    chunk_ptr_t next_chunk = (chunk_ptr_t)((ull)curr_chunk + (ull)curr_size);
    int upper_bound_flag = 0;
    int lower_bound_flag = 0;
    if ((ull)next_chunk >= (ull)sbrk(0))
    {
        //printf("next_chunk addr:0x%012llx\n", (ull)next_chunk - (ull)start_address);
        //printf("limit...for maximum\n");
        upper_bound_flag = 1;
    }
    else if ((ull)prev_chunk < (ull)start_address)
    {
        //printf("prev_chunk addr:0x%012llx\n", (ull)prev_chunk - (ull)start_address);
        //printf("limit...for minimum\n");
        lower_bound_flag = 1;
    }
    else if (curr_size == 32 * 1024)
    {
        //printf("%d\n", curr_size);
        //printf("limit...for size\n");
        curr_chunk->size_and_flag.alloc_flag = 0;
        add_to_bin(curr_chunk);
        return;
    }
    else {
        ;
    }
    unsigned int next_size = next_chunk->size_and_flag.curr_chunk_size;
    if(!lower_bound_flag){
        if (prev_chunk->size_and_flag.alloc_flag == 0 && prev_size == curr_size)
        {
            //printf("with low\n");
            delete_from_bin(prev_chunk);
            curr_chunk->size_and_flag.curr_chunk_size = 0;
            prev_chunk->size_and_flag.curr_chunk_size = prev_size * 2;
            next_chunk->size_and_flag.prev_chunk_size = curr_size * 2;
            curr_chunk = NULL;
            merge(prev_chunk);
        }
    }
    else if(!upper_bound_flag){
        if (next_chunk->size_and_flag.alloc_flag == 0 && next_size == curr_size)
            {
                //printf("with high\n");
                //printf("next size:%d\n", next_size);
                chunk_ptr_t two_higher_chunk = (chunk_ptr_t)((ull)next_chunk + (ull)next_size);
                delete_from_bin(next_chunk);
                curr_chunk->size_and_flag.curr_chunk_size = curr_size * 2;
                two_higher_chunk->size_and_flag.prev_chunk_size = next_size * 2;
                //memset(next_chunk, 0, next_size);
                next_chunk->size_and_flag.curr_chunk_size = 0;
                next_chunk = NULL;
                merge(curr_chunk);
            }
    }
    else
    {
        curr_chunk->size_and_flag.alloc_flag = 0;
        add_to_bin(curr_chunk);
        //printf("nothing can merge\n");
        return;
    }
}

void print_bin_i(int index)
{
    chunk_ptr_t ptr = bin[index]->next;
    while ((ull)(ptr) != (ull)(bin[index]))
    {
        int size = ptr->size_and_flag.curr_chunk_size;
        printf("0x%012llx--------%d\n",(ull)ptr - (ull)start_address, size);
        ptr = ptr->next;
    }
}

chunk_ptr_t find_bin_space(int index)
{
    chunk_ptr_t ptr = bin[index]->next;
    while ((ull)ptr == (ull)bin[index]) //if this bin has nothing
    {
        //printf("bin[%d] is NULL\n", index);
        index++;
        ptr = bin[index]->next;
    }
    chunk_ptr_t low_address = ptr;
    while ((ull)(ptr) != (ull)(bin[index]))
    {
        if ((ull)ptr < (ull)low_address)
        {
            low_address = ptr;
        }
        ptr = ptr->next;
    }
    return low_address;
}
void bin_init()
{
    for (int i = 0; i < 11; i++)
    {
        bin[i] = (chunk_ptr_t)malloc(sizeof(chunk_ptr_t));
        bin[i]->next = bin[i];
        bin[i]->prev = bin[i]; //initial the bin
        bin[i]->size_and_flag.prev_chunk_size = 0;
        bin[i]->size_and_flag.mmap_flag = 0;
        bin[i]->size_and_flag.alloc_flag = -1;
        bin[i]->size_and_flag.curr_chunk_size = 0; //bin's chunk size is equal to the number of node 
    }
}
void mmap_list_init()
{
    mmap_alloc_list = (chunk_ptr_t)malloc(sizeof(chunk_ptr_t));
    mmap_alloc_list->next = mmap_alloc_list;
    mmap_alloc_list->prev = mmap_alloc_list;
    mmap_alloc_list->size_and_flag.curr_chunk_size = 0;
    mmap_alloc_list->size_and_flag.mmap_flag = 0;
    mmap_alloc_list->size_and_flag.alloc_flag = 0;
    mmap_alloc_list->size_and_flag.prev_chunk_size = 0;
}
void add_to_mmap_list(chunk_ptr_t chunk)
{
    //printf("hi, this is add_to_mmap_list\n");
    unsigned int chunk_size = chunk->size_and_flag.curr_chunk_size;
    //printf("chunk_size:%d\n", chunk_size);
    chunk_ptr_t ptr = mmap_alloc_list->next;
    if ((ull)ptr == (ull)mmap_alloc_list)
    {
        //printf("first\n");
        ptr->next = chunk;
        chunk->prev = ptr;
        ptr->prev = chunk;
        chunk->next = ptr;
        return;
    }
    while ((ull)ptr != (ull)mmap_alloc_list)
    {
        if (chunk_size < ptr->size_and_flag.curr_chunk_size)
        {
            //printf("size < curr\n");
            ptr->prev->next = chunk;
            chunk->prev = ptr->prev;
            chunk->next = ptr;
            ptr->prev = chunk;
            break;
        }
        else if (chunk_size == ptr->size_and_flag.curr_chunk_size || (ull)ptr == (ull)mmap_alloc_list->prev)
        {
            //printf("size == curr\n");
            ptr->next->prev = chunk;
            chunk->next = ptr->next;
            ptr->next = chunk;
            chunk->prev = ptr;
            break;
        }
        else
        {
            ptr = ptr->next;
        }
    }
    return;
}
void delete_from_mmap(chunk_ptr_t chunk)
{
    //printf("hi, this is delete from mmap\n");
    //printf("target:%p\n", chunk);
    //printf("index:%d\n", index);
    chunk_ptr_t ptr = mmap_alloc_list->next;
    while ((ull)ptr != (ull)chunk)
    {
        if ((ull)ptr != (ull)mmap_alloc_list)
        { 
            ptr = ptr->next;
        }
        else
        {
            return;
        }
    }
    //printf("target:0x%012llx\n", (ull)ptr - (ull)start_address);
    //printf("%p\n", ptr);
    ptr->prev->next = ptr->next;
    ptr->next->prev = ptr->prev;
}

void print_mmap_i()
{
    chunk_ptr_t ptr = mmap_alloc_list->next;
    while ((ull)(ptr) != (ull)(mmap_alloc_list))
    {
        int size = ptr->size_and_flag.curr_chunk_size;
        printf("0x%012llx--------%d\n", (ull)ptr, size);
        ptr = ptr->next;
    }
}
