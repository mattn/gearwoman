/*
gearmand - Gearman Server
Copyright (C) 2007  Samuel Stauffer <samuel@descolada.com>

See LICENSE and COPYING for license details.
*/

#ifndef _IDAE_H_
#define _IDAE_H_

#include <stdint.h>

#define MAX_HANDLE_LEN 64
#define MAX_FUNCTION_LEN 255
#define MAX_CLIENT_ID_LEN 255

#define MAGIC_REQUEST  0x524551    /* \x00REQ */
#define MAGIC_RESPONSE 0x524553    /* \x00RES */

#define HEADER_SIZE         12
#define HEADER_OFFSET_MAGIC 0
#define HEADER_OFFSET_TYPE  4
#define HEADER_OFFSET_SIZE  8

#if DEBUG
#define CLEANUP_INTERVAL 10
#else
#define CLEANUP_INTERVAL (60*10)
#endif

#endif
