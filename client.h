/*
gearmand - Gearman Server
Copyright (C) 2007  Samuel Stauffer <samuel@descolada.com>

See LICENSE and COPYING for license details.
*/

#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <glib.h>
#include <sys/types.h>
#include <event.h>

#include "common.h"
#include "gearmand.h"
#include "memblock.h"
#include "job.h"

#define CLIENT_STATE_INITIAL         0
#define CLIENT_STATE_CONNECTED       1

typedef struct _Ability {
    const gchar *func; /* interned */
    int timeout;
} Ability;

typedef struct _Client {
    int fd;
    struct event evt;
    int state;

    unsigned char ip[4];    /* source ip   */
    unsigned short port;    /* source port */

    // client
    GPtrArray *listening;   /* list of jobs this client is listening to */

    // worker
    char id[MAX_CLIENT_ID_LEN+1];
    GPtrArray *abilities;
    int ability_iter;
    gboolean sleeping;
    GPtrArray *working;

    MemBlock *buffer_in;
    GQueue *queue_out;
    int block_out_offset;
    MemBlock *block_out;
} Client;

Client *client_new();
void client_free(Client *cli);
int client_recv(Client *cli, int num);
int client_send(Client *cli, MemBlock *data);
int client_flush(Client *cli);
void client_add_ability(Client *cli, const gchar *func, int timeout);
void client_remove_ability(Client *cli, const gchar *func);
void client_remove_all_abilities(Client *cli);
void client_listen_to(Client *cli, Job *job);
void client_stop_listening_to(Client *cli, Job *job);
void client_clear_listening(Client *cli);
void client_wake_up(Client *cli);
void client_add_working(Client *cli, Job *job);
void client_remove_working(Client *cli, Job *job);
void client_clear_working(Client *cli);

#endif
