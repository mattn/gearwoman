/*
gearmand - Gearman Server
Copyright (C) 2007  Samuel Stauffer <samuel@descolada.com>

See LICENSE and COPYING for license details.
*/

#include <stdlib.h>
#include <glib.h>

#include <assert.h>

#include "memblock.h"

GTrashStack *g_mem_1k    = NULL;
GTrashStack *g_mem_16k    = NULL;
GTrashStack *g_mem_64k   = NULL;
GTrashStack *g_mem_1024k = NULL;

void freePool(GTrashStack **pool, int blocksize)
{
    MemBlock *block;
    for(block = g_trash_stack_pop(pool); block; block = g_trash_stack_pop(pool)) {
        #ifdef DEBUG_MEMORY
        free(block);
        #else
        g_slice_free1(sizeof(MemBlock) + blocksize, block);
        #endif
    }
}

void freePools()
{
    freePool(&g_mem_1k, 1024);
    freePool(&g_mem_16k, 16*1024);
    freePool(&g_mem_64k, 64*1024);
    freePool(&g_mem_1024k, 1024*1024);
}

MemBlock *getBlock(int size)
{
    assert(size <= MAX_MEMBLOCK_SIZE);
    GTrashStack **pool;
    int blocksize;

    if (size <= 1024) {
        pool = &g_mem_1k;
        blocksize = 1024;
    } else if (size <= 16*1024) {
        pool = &g_mem_16k;
        blocksize = 16*1024;
    } else if (size <= 64*1024) {
        pool = &g_mem_64k;
        blocksize = 64*1024;
    } else if (size <= 1024*1024) {
        pool = &g_mem_1024k;
        blocksize = 1024*1024;
    } else {
        g_error("Request block size is too big");
        return NULL;
    }

    MemBlock *block = g_trash_stack_pop(pool);
    if (!block) {
        #ifdef DEBUG_MEMORY
        block = malloc(sizeof(MemBlock) + blocksize);
        g_message("[%.8x] NEW BLOCK (pool = %.8x)", block, pool);
        #else
        block = (MemBlock*)g_slice_alloc(sizeof(MemBlock) + blocksize);
        #endif
    } else {
        #ifdef DEBUG_MEMORY
        g_message("[%.8x] POP BLOCK (pool = %.8x)", block, pool);
        #endif
    }
    block->pool = pool;
    block->refcount = 0;
    block->size = blocksize;
    block->nbytes = 0;
    return block;
}

int incRef(MemBlock *block)
{
    assert(block != NULL);
    // if (!block) return 0;

    block->refcount++;
    #ifdef DEBUG_MEMORY
    g_message("[%.8x] INC REFERENCE (ref = %d, pool = %.8x)", block, block->refcount, block->pool);
    #endif
    return block->refcount;
}

int decRef(MemBlock *block)
{
    if (!block) return 0;

    assert(block->refcount > 0);

    block->refcount--;

    // If reference count reaches zero then return block to pool
    if (block->refcount == 0) {
        #ifdef DEBUG_MEMORY
        g_message("[%.8x] PUSH BLOCK (ref = 0, pool = %.8x)", block, block->pool);
        #endif
        g_trash_stack_push(block->pool, block);
    } else {
        #ifdef DEBUG_MEMORY
        g_message("[%.8x] DEC REFERENCE (ref = %d, pool = %.8x)", block, block->refcount, block->pool);
        #endif
    }

    return block->refcount;
}
