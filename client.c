/*
gearmand - Gearman Server
Copyright (C) 2007  Samuel Stauffer <samuel@descolada.com>

See LICENSE and COPYING for license details.
*/


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>

#include <assert.h>

#include <glib.h>

#include "common.h"
#include "memblock.h"
#include "client.h"
#include "util.h"

Client *client_new()
{
    Client *cli = (Client *)malloc(sizeof(Client));
    if (!cli) return NULL;

    cli->state   = CLIENT_STATE_INITIAL;
    cli->fd      = -1;
    cli->port    = 0;
    cli->id[0]   = 0;
    memset(cli->ip, 0, sizeof(cli->ip));

    cli->listening = NULL;

    cli->sleeping = FALSE;
    cli->abilities = g_ptr_array_new();
    cli->ability_iter = 0;
    cli->working = NULL;

    cli->buffer_in = NULL;
    cli->queue_out = g_queue_new();
    cli->block_out = NULL;

    return cli;
}

void client_free(Client *cli)
{
    assert(cli != NULL);
    assert(!cli->listening || cli->listening->len == 0);
    assert(!cli->working || cli->working->len == 0);
    assert(cli->abilities->len == 0);

    if (cli->abilities) g_ptr_array_free(cli->abilities, TRUE);
    if (cli->working) g_ptr_array_free(cli->working, TRUE);
    if (cli->listening) g_ptr_array_free(cli->listening, TRUE);

    assert( (!cli->buffer_in) || (cli->buffer_in->refcount == 1) );
    decRef(cli->buffer_in);
    decRef(cli->block_out);

    GList *node;
    for(node = cli->queue_out->head; node; node = node->next) {
        decRef(node->data);
    }
    g_queue_free(cli->queue_out);

    free(cli);
}

int client_recv(Client *cli, int num)
{
    assert(cli != NULL);
    assert(cli->buffer_in != NULL);

    int n = cli->buffer_in->size - cli->buffer_in->nbytes;
    if (num > 0) {
        num = min(n, num);
    }

    assert( num <= (cli->buffer_in->size - cli->buffer_in->nbytes) );

    int ret = recv(cli->fd, cli->buffer_in->bytes + cli->buffer_in->nbytes,
                   num, 0);

    if (ret < 0) {
        if (errno == EAGAIN)
            ret = 0;
        else
            ret = -1;
    } else if (ret == 0) {
        ret = -1;
    } else {
        cli->buffer_in->nbytes += ret;
    }

    return ret;
}

int client_send(Client *cli, MemBlock *data)
{
    assert( (cli != NULL) && (data != NULL) );

    // #ifdef DEBUG
    // g_debug("[%s] Sending message to client (%d)", cli->id, data->nbytes);
    // #endif

    incRef(data);
    g_queue_push_tail(cli->queue_out, data);

    return client_flush(cli);
}

int client_flush(Client *cli)
{
    assert( cli != NULL );

    if (!cli->block_out) {
        cli->block_out = g_queue_pop_head(cli->queue_out);
        if (!cli->block_out) return 0;
        cli->block_out_offset = 0;
    }

    int ret = send(cli->fd,
                   cli->block_out->bytes + cli->block_out_offset,
                   cli->block_out->nbytes - cli->block_out_offset,
                   MSG_NOSIGNAL);

    if (ret > 0) {
        // #if DEBUG
        // g_debug("[%s] Sent %d (%d left) (block %.8x)", cli->id, ret,
        //     cli->block_out->nbytes - cli->block_out_offset - ret, cli->block_out);
        // #endif
        cli->block_out_offset += ret;
        assert(cli->block_out->nbytes - cli->block_out_offset >= 0);
    } else if (ret < 0 && errno != EAGAIN) {
        return -1;
    }

    if (cli->block_out && (cli->block_out->nbytes - cli->block_out_offset == 0)) {
        // #if DEBUG
        // g_debug("[%s] Block %.8x sent (cleaning out)", cli->id, cli->block_out);
        // #endif
        decRef(cli->block_out);
        cli->block_out = NULL;
    }

    if (cli->block_out || !g_queue_is_empty(cli->queue_out)) {
        // #if DEBUG
        // g_debug("[%s] data left to flush (block=%d) (que=%d) %.8x", cli->id,
        //     ( (cli->block_out != NULL)
        //         ? (cli->block_out->nbytes - cli->block_out_offset)
        //         : 0 ),
        //     cli->queue_out->length, cli->block_out);
        // #endif
        event_del(&cli->evt);
        cli->evt.ev_events = EV_READ|EV_WRITE|EV_PERSIST;
        event_add(&cli->evt, NULL);

        return 1;
    }

    return 0;
}

void client_add_ability(Client *cli, const gchar *func, int timeout)
{
    Ability *ability = malloc(sizeof(Ability));
    ability->func = func;
    ability->timeout = timeout;
    g_ptr_array_add_uniq(cli->abilities, ability);
}

void client_remove_ability(Client *cli, const gchar *func)
{
    g_ptr_array_remove_fast(cli->abilities, (gpointer)func);
}

void _free(gpointer value, gpointer user_data)
{
    free(value);
}

void client_remove_all_abilities(Client *cli)
{
    g_ptr_array_foreach(cli->abilities, _free, NULL);
    g_ptr_array_free(cli->abilities, TRUE);
    cli->abilities = g_ptr_array_new();
}

void client_listen_to(Client *cli, Job *job)
{
    if (!cli->listening)
        cli->listening = g_ptr_array_new();
    g_ptr_array_add(cli->listening, job);
}

void client_stop_listening_to(Client *cli, Job *job)
{
    if (cli->listening) {
        g_ptr_array_remove(cli->listening, job);
    }
}

void client_clear_listening(Client *cli)
{
    if (cli->listening) {
        g_ptr_array_free(cli->listening, TRUE);
        cli->listening = NULL;
    }
}

void client_wake_up(Client *cli)
{
    if (cli->sleeping) {
        client_send(cli, simple_response(MSG_NOOP));
        cli->sleeping = FALSE;
    }
}

void client_add_working(Client *cli, Job *job)
{
    if (!cli->working)
        cli->working = g_ptr_array_new();
    g_ptr_array_add(cli->working, job);
}

void client_remove_working(Client *cli, Job *job)
{
    if (cli->working)
        g_ptr_array_remove(cli->working, job);
}

void client_clear_working(Client *cli)
{
    if (cli->working) {
        g_ptr_array_free(cli->working, TRUE);
        cli->working = NULL;
    }
}
