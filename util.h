/*
gearmand - Gearman Server
Copyright (C) 2007  Samuel Stauffer <samuel@descolada.com>

See LICENSE and COPYING for license details.
*/

#ifndef _UTIL_H_
#define _UTIL_H_

#include <glib.h>
#include <sys/types.h>
#include <event.h>

#include "common.h"
#include "gearmand.h"
#include "memblock.h"

#define MAX_MESSAGE_ID 24

#define MSG_CAN_DO            1   /* func */
#define MSG_CAN_DO_TIMEOUT    23  /* func, timeout */
#define MSG_CANT_DO           2   /* func */
#define MSG_RESET_ABILITIES   3
#define MSG_SET_CLIENT_ID     22  /* client_id */
#define MSG_PRE_SLEEP         4
#define MSG_NOOP              6
#define MSG_SUBMIT_JOB        7   /* func, uniq, arg */
#define MSG_SUBMIT_JOB_HIGH   21  /* func, uniq, arg */
#define MSG_SUBMIT_JOB_BG     18  /* func, uniq, arg */
#define MSG_JOB_CREATED       8   /* handle */
#define MSG_GRAB_JOB          9
#define MSG_NO_JOB            10
#define MSG_JOB_ASSIGN        11  /* handle, func, arg */
#define MSG_WORK_STATUS       12  /* handle, numerator, denominator */
#define MSG_WORK_COMPLETE     13  /* handle, result */
#define MSG_WORK_FAIL         14  /* handle */
#define MSG_GET_STATUS        15  /* handle */
#define MSG_STATUS_RES        20  /* handle, known, running, numerator, denominator */
#define MSG_ECHO_REQ          16  /* text */
#define MSG_ECHO_RES          17  /* text */
#define MSG_ERROR             19  /* code, text */
#define MSG_ALL_YOURS         24

MemBlock *new_response(int type, int data_len, unsigned char *data);
MemBlock *new_error_response(char *code, char *msg);
MemBlock *simple_response(int type);
int parse_args(unsigned char **parsed, int count, unsigned char *arg, int argsize);
void set_message_magic(MemBlock *block, uint32_t magic);
void set_message_type(MemBlock *block, uint32_t type);
void set_message_size(MemBlock *block, uint32_t size);
void g_ptr_array_add_uniq(GPtrArray *array, gpointer value);

#endif
