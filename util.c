/*
gearmand - Gearman Server
Copyright (C) 2007  Samuel Stauffer <samuel@descolada.com>

See LICENSE and COPYING for license details.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/socket.h>
#else
#include <winsock2.h>
#endif

#include <assert.h>

#include <glib.h>

#include "common.h"
#include "util.h"

MemBlock *new_response(int type, int data_len, unsigned char *data)
{
    MemBlock *block = getBlock(HEADER_SIZE + data_len);
    block->nbytes = HEADER_SIZE + data_len;
    set_message_magic(block, MAGIC_RESPONSE);
    set_message_type(block, type);
    set_message_size(block, data_len);
    if (data)
        memcpy(block->bytes + HEADER_SIZE, data, data_len);
    return block;
}

MemBlock *new_error_response(char *code, char *msg)
{
    int code_len = strlen(code);
    int msg_len = strlen(msg);
    MemBlock *block = new_response(MSG_ERROR, code_len + msg_len + 1, NULL);
    char *p = (char*)block->bytes + HEADER_SIZE;
    memcpy(p, code, code_len);
    *(p+code_len) = 0;
    memcpy(p+code_len+1, msg, msg_len);
    return block;
}

MemBlock *simple_response(int type) {
    assert(type >= 0 && type <= MAX_MESSAGE_ID);
    static int initialized = 0;
    static MemBlock *cache[MAX_MESSAGE_ID+1];
    if (!initialized) {
        initialized = 1;
        memset(cache, 0, sizeof(cache));
    }
    if (!cache[type]) {
        cache[type] = new_response(type, 0, NULL);
        incRef(cache[type]);
    }
    return cache[type];
}

int parse_args(unsigned char **parsed, int count, unsigned char *arg, int argsize)
{
    if (count == 0)
        return argsize;

    int i;
    unsigned char *end = arg + argsize;
    for(i = 0; i < count; i++) {
        parsed[i] = arg;
        if (i != count-1) {
            while (arg < end && *arg != 0) arg++;
            arg++; /* skip '0' */
            if (arg > end)
                return -1;
        }
    }

    return end - arg;
}

void set_message_magic(MemBlock *block, uint32_t magic)
{
    *(uint32_t*)(block->bytes + HEADER_OFFSET_MAGIC) = htonl(magic);
}

void set_message_type(MemBlock *block, uint32_t type)
{
    *(uint32_t*)(block->bytes + HEADER_OFFSET_TYPE) = htonl(type);
}

void set_message_size(MemBlock *block, uint32_t size)
{
    *(uint32_t*)(block->bytes + HEADER_OFFSET_SIZE) = htonl(size);
}

void g_ptr_array_add_uniq(GPtrArray *array, gpointer value)
{
    int i;
    for(i = 0; i < array->len; i++) {
        if (g_ptr_array_index(array, i) == value)
            return;
    }
    g_ptr_array_add(array, value);
}
