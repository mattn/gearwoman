/*
gearmand - Gearman Server
Copyright (C) 2007  Samuel Stauffer <samuel@descolada.com>

See LICENSE and COPYING for license details.
*/

#ifndef _MEMBLOCK_H_
#define _MEMBLOCK_H_

#define MAX_MEMBLOCK_SIZE 1024*1024

typedef struct _MemBlock {
    GTrashStack **pool;
    int refcount;   // Number of reference to this block
    int size;       // Size of the datablock
    int nbytes;     // Number of bytes actually in buffer
    unsigned char bytes[0];
} MemBlock;

void freePools();
MemBlock *getBlock(int size);
int incRef(MemBlock *block);
int decRef(MemBlock *block);

#endif
