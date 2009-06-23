/*
gearmand - Gearman Server
Copyright (C) 2007  Samuel Stauffer <samuel@descolada.com>

See LICENSE and COPYING for license details.
*/

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#ifndef _WIN32
#include <netinet/in.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <getopt.h>
#include <signal.h>
#include <ws2tcpip.h>
#define in_addr_t unsigned long
#endif

#include <event.h>
#include <glib.h>

#include <assert.h>

#include "common.h"
#include "gearmand.h"
#include "memblock.h"
#include "client.h"
#include "job.h"
#include "util.h"

/**
    g_jobs owns the reference to a Job
    g_clients owns the reference to a Client
**/
GPtrArray  *g_clients   = NULL;
GHashTable *g_jobqueue  = NULL; /* maps functions -> queue of jobs (GQueue) */
GHashTable *g_jobs      = NULL; /* maps handle -> job */
GHashTable *g_uniq_jobs = NULL; /* maps functions -> uniq -> job */
GHashTable *g_workers   = NULL; /* maps functions -> list of worker clients (GPtrArray) */

int g_foreground = 1;
char *g_logfilename = "gearmand.log";
char *g_bind = "0.0.0.0";
/* int g_port = 4730; */
int g_port = 7003;
char g_handle_base[MAX_HANDLE_LEN];

void work_fail(Job *job);
void remove_job(Job *job);
void schedule_cleanup();

/****************************************************************************
  Create a socket, bind it to the given address and port,
      and set it non-blocking.
  on success, return socket
  on error, return -1
 ****************************************************************************/
int listen_on(in_addr_t addr, int port)
{
    int r;
    struct sockaddr_in sin;
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0) return -1;

    int i = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&i, sizeof(i));
    // setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&i, sizeof(i));
#ifndef _WIN32
    fcntl(sock, F_SETFL, O_NONBLOCK);
#else
    {
        unsigned long flags = 1;
        ioctlsocket(sock, FIONBIO, &flags);
    }
#endif

    sin.sin_addr.s_addr = addr;
    sin.sin_port        = htons(port);
    sin.sin_family      = AF_INET;
    r = bind(sock, (const struct sockaddr *)&sin, sizeof(sin));

    if (r) {
        close(sock);
        sock = -1;
    } else {
        listen(sock, 10);
    }

    return sock;
}

/***/

void register_ability(Client *cli, const gchar *func, int timeout)
{
    GPtrArray *workers;

    client_add_ability(cli, func, timeout);

    workers = g_hash_table_lookup(g_workers, func);
    if (!workers) {
        workers = g_ptr_array_new();
        g_hash_table_insert(g_workers, (gpointer)func, workers);
    }
    g_ptr_array_add_uniq(workers, cli);
}

void unregister_ability(Client *cli, const gchar *func)
{
    GPtrArray *workers = g_hash_table_lookup(g_workers, func);
    if (workers) {
        g_ptr_array_remove_fast(workers, cli);
    }
    client_remove_ability(cli, func);
}

void _unregister_all_abilities(gpointer ability, gpointer cli)
{
    unregister_ability((Client *)cli, ((Ability*)ability)->func);
}

void unregister_all_abilities(Client *cli)
{
    g_ptr_array_foreach(cli->abilities, _unregister_all_abilities, cli);
    client_remove_all_abilities(cli);
}

/***/

void generate_job_handle(char *handle)
{
    static int job_sequence = 0;
    // char *handle = (char *)malloc(128);
    sprintf(handle, "%s%d", g_handle_base, ++job_sequence);
    // return handle;
}

void jobqueue_push(GHashTable *g_jobqueue, Job *job, gboolean high_priority) {
    GQueue *queue = g_hash_table_lookup(g_jobqueue, job->func);
    if (!queue) {
        queue = g_queue_new();
        g_hash_table_insert(g_jobqueue, (const gpointer)job->func, queue);
    }
    if (high_priority) {
        g_queue_push_head(queue, job);
    } else {
        g_queue_push_tail(queue, job);
    }
}

Job *jobqueue_pop(GHashTable *g_jobqueue, const gchar *func)
{
    GQueue *queue = g_hash_table_lookup(g_jobqueue, func);
    if (!queue)
        return NULL;
    Job *job = g_queue_pop_head(queue);
    return job;
}

void remove_job_from_queue(Job *job)
{
    GQueue *queue = g_hash_table_lookup(g_jobqueue, job->func);
    g_queue_remove(queue, job);
    if (g_queue_is_empty(queue)) {
        g_hash_table_remove(g_jobqueue, job->func);
    }
}

/**
    Remove a job from queue, uniq table, and handle table cause it to be deallocated.
    Final step in the life of a job.
**/
void remove_job(Job *job)
{
    if (job->worker) {
        client_remove_working(job->worker, job);
    } else {
        remove_job_from_queue(job);
    }
    g_ptr_array_foreach(job->listeners, (GFunc)client_stop_listening_to, job);
    if (job->is_uniq)
        g_hash_table_remove(g_uniq_jobs, &job->uniq_key);
    if (job->timeout > 0)
        evtimer_del(&job->work_timer);
    g_hash_table_remove(g_jobs, job->handle); /* job is now deallocated */
}

void stop_all_listening(Client *cli)
{
    if (!cli->listening)
        return;

    int i;
    Job *job;
    for(i = 0; i < cli->listening->len; i++) {
        job = g_ptr_array_index(cli->listening, i);
        g_ptr_array_remove_fast(job->listeners, cli);
        if (!job->background && job->listeners->len == 0) {
            #if DEBUG
            g_debug("[%s] removing non-background job with no listeners: %s", cli->id, job->handle);
            #endif
            remove_job(job);
        }
    }
    client_clear_listening(cli);
}

void fail_working_jobs(Client *cli)
{
    if (!cli->working)
        return;

    // work_fail removes the job from cli->working
    while(cli->working->len > 0) {
        Job *job = g_ptr_array_index(cli->working, 0);
        work_fail(job);
    }
}

void _wake_up_client(Client *cli, gpointer user_data)
{ client_wake_up(cli); }

void wake_up_sleepers(const gchar *func)
{
    GPtrArray *workers = g_hash_table_lookup(g_workers, (gpointer)func);
    if (workers)
        g_ptr_array_foreach(workers, (GFunc)_wake_up_client, NULL);
}

void work_fail(Job *job)
{
    MemBlock *block = new_response(MSG_WORK_FAIL, strlen(job->handle), (unsigned char*)job->handle);
    incRef(block); // Make sure the first listener doesn't decRef to 0 causing the block to be returned
    g_ptr_array_foreach(job->listeners, (GFunc)client_send, block);
    decRef(block);
    remove_job(job);
}


/****************************************************************************/
/*                             Message Handlers                             */
/****************************************************************************/


/****************************************************************************
  Message Handler: can_do(func) / cant_do(func)
 ****************************************************************************/
int msg_can_do(Client *cli, unsigned char *arg, int argsize, gboolean cant)
{
    if (argsize > MAX_FUNCTION_LEN) {
        g_warning("[%s] function name too long", cli->id);
        return -1;
    }

    const gchar *func = g_intern_string((char*)arg);
    // printf(">> [%s] = %.8x\n", arg, func);

    #if DEBUG
    if (cant) g_debug("[%s] cant_do %s", cli->id, func);
    else g_debug("[%s] can_do %s", cli->id, func);
    #endif

    if (cant)
        unregister_ability(cli, func);
    else
        register_ability(cli, func, -1);

    return 0;
}

/****************************************************************************
  Message Handler: can_do_timeout(func, timeout)
 ****************************************************************************/
int msg_can_do_timeout(Client *cli, unsigned char *arg, int argsize)
{
    unsigned char *args[2];
    parse_args(args, 2, arg, argsize);

    if (strlen((char*)args[0]) > MAX_FUNCTION_LEN) {
        g_warning("[%s] function name too long", cli->id);
        return -1;
    }

    const gchar *func = g_intern_string((char*)args[0]);
    int timeout = atol((char*)args[1]);
    // printf(">> [%s] = %.8x\n", arg, func);

    #if DEBUG
    g_debug("[%s] can_do_timeout %s %d", cli->id, func, timeout);
    #endif

    register_ability(cli, func, timeout);

    return 0;
}

/****************************************************************************
  Message Handler: reset_abilities()
 ****************************************************************************/
int msg_reset_abilities(Client *cli, unsigned char *arg, int argsize)
{
    #if DEBUG
    g_debug("[%s] reset_abilities", cli->id);
    #endif

    unregister_all_abilities(cli);

    return 0;
}

/****************************************************************************
  Message Handler: set_client_id(client_id)
 ****************************************************************************/
int msg_set_client_id(Client *cli, unsigned char *arg, int argsize)
{
    if (argsize > MAX_CLIENT_ID_LEN) {
        g_warning("[%s] client id too long", cli->id);
    }

    strcpy(cli->id, (char*)arg);

    #if DEBUG
    g_debug("[%s] set_client_id", cli->id);
    #endif

    return 0;
}

/****************************************************************************
  Message Handler: echo_req(text) -> echo_res(text)
 ****************************************************************************/
int msg_echo_req(Client *cli, MemBlock *block)
{
    #if DEBUG
    g_debug("[%s] echo_req", cli->id);
    #endif

    set_message_magic(block, MAGIC_RESPONSE);
    set_message_type(block, MSG_ECHO_RES);
    client_send(cli, block);

    return 0;
}

/****************************************************************************
  Message Handler pre_sleep()
 ****************************************************************************/
int msg_pre_sleep(Client *cli, unsigned char *arg, int argsize)
{
    #if DEBUG
    g_debug("[%s] pre_sleep", cli->id);
    #endif

    /* make sure there isn't any jobs the could be worked on */
    int i;
    for(i = 0; i < cli->abilities->len; i++) {
        Ability *ability = g_ptr_array_index(cli->abilities, i);
        GQueue *queue = g_hash_table_lookup(g_jobqueue, ability->func);
        if (queue && !g_queue_is_empty(queue)) {
            cli->sleeping = FALSE;
            client_send(cli, simple_response(MSG_NOOP));
            return 0;
        }
    }

    cli->sleeping = TRUE;

    return 0;
}

/****************************************************************************
  Message Handler: submit_job_*(func, uniq, arg)
 ****************************************************************************/
int msg_submit_job(Client *cli, unsigned char *arg, int argsize, gboolean background, gboolean high)
{
    unsigned char *args[3];
    int last_arg_len = parse_args(args, 3, arg, argsize);

    int is_uniq = args[1][0] != 0;

    const gchar *func = g_intern_string((char*)args[0]);
    // printf(">> [%s] = %.8x\n", args[0], func);

    /* look for a duplicate job - if one exists, add to listeners */
    if (is_uniq) {
        UniqJobKey uk;
        uk.func = func;
        if (args[1][0] == '-' && args[1][1] == 0) {
            uk.uniq = args[2];
            uk.uniq_len = last_arg_len;
        } else {
            uk.uniq = args[1];
            uk.uniq_len = strlen((char*)args[1]);
        }
        Job *job = g_hash_table_lookup(g_uniq_jobs, &uk);
        if (job) {
            #if DEBUG
            g_debug("[%s] submit_job - merging %s:%s -> %s", cli->id, job->func, job->uniq, job->handle);
            #endif
            if (!job->background) {
                g_ptr_array_add_uniq(job->listeners, cli);
                client_listen_to(cli, job);
            }
            MemBlock *block = new_response(MSG_JOB_CREATED, strlen(job->handle), (unsigned char *)job->handle);
            client_send(cli, block);
            return 0;
        }
    }

    Job *job = job_new();
    generate_job_handle(job->handle);
    job->func = func;
    if (last_arg_len == 0)
        job->arg = (unsigned char *)"";
    else {
        job->arg = malloc(last_arg_len);
        memcpy(job->arg, args[2], last_arg_len);
    }
    job->arg_len = last_arg_len;
    job->background = background;
    if (!background) {
        g_ptr_array_add(job->listeners, cli);
    }
    g_hash_table_insert(g_jobs, job->handle, job);

    #if DEBUG
    g_debug("[%s] submit_job: %s, %s -> %s", cli->id, args[0], args[1], job->handle);
    #endif

    jobqueue_push(g_jobqueue, job, high);
    if (!background) {
        client_listen_to(cli, job);
    }

    job->is_uniq = is_uniq;
    if (is_uniq) {
        job->uniq = strdup((char*)args[1]);
        job->uniq_key.func = func;
        if (job->uniq[0] == '-' && job->uniq[1] == 0) {
            job->uniq_key.uniq = job->arg;
            job->uniq_key.uniq_len = job->arg_len;
        } else {
            job->uniq_key.uniq = (unsigned char *)job->uniq;
            job->uniq_key.uniq_len = strlen(job->uniq);
        }
        g_hash_table_insert(g_uniq_jobs, &job->uniq_key, job);
        #if DEBUG
        g_debug("[%s] \tadded uniq job %s", cli->id, job->handle);
        #endif
    }

    MemBlock *block = new_response(MSG_JOB_CREATED, strlen(job->handle), (unsigned char *)job->handle);
    client_send(cli, block);
    wake_up_sleepers(job->func);

    return 0;
}

void _work_timeout(int fd, short events, Job *job)
{
    // if (cli->working->worker != cli) {
    //     /* should this even be possible? */
    //     MemBlock *block = new_error_response("not_worker", "");
    //     client_send(cli, block, TRUE);
    // } else {
    g_warning("[%s] job %s (func=%s) timed out", ((Client*)job->worker)->id, job->handle, job->func);

    work_fail(job);
}

/****************************************************************************
  Message Handler: grab_job() -> no_job(), job_assign(handle, func, arg)
 ****************************************************************************/
int msg_grab_job(Client *cli, unsigned char *arg, int argsize)
{
    Job *job = NULL;
    Ability *ability = NULL;
    int nabilities = cli->abilities->len;
    int i;
    for(i = 0; i < nabilities && !job; i++) {
        cli->ability_iter = (cli->ability_iter + 1) % nabilities;
        ability = g_ptr_array_index(cli->abilities, cli->ability_iter);
        job = jobqueue_pop(g_jobqueue, ability->func);
    }

    if (!job) {
        #if DEBUG
        g_debug("[%s] grab_job - no job", cli->id);
        #endif
        MemBlock *block = simple_response(MSG_NO_JOB);
        client_send(cli, block);
    } else {
        #if DEBUG
        g_debug("[%s] grab_job - assigned %s %s", cli->id, ability->func, job->handle);
        #endif

        job->worker = cli;
        client_add_working(cli, job);

        int data_len = strlen(job->handle) + strlen(job->func) + job->arg_len + 2;
        MemBlock *block = new_response(MSG_JOB_ASSIGN, data_len, NULL);
        unsigned char *p = block->bytes + HEADER_SIZE;
        p += sprintf((char*)p, job->handle) + 1;
        p += sprintf((char*)p, job->func) + 1;
        memcpy(p, job->arg, job->arg_len);
        client_send(cli, block);

        if (ability->timeout > 0) {
            struct timeval tv = {ability->timeout, 0};
            job->timeout = ability->timeout;
            evtimer_set(&job->work_timer, (void*)_work_timeout, job);
            evtimer_add(&job->work_timer, &tv);
        }
    }

    return 0;
}

/****************************************************************************
  Message Handler: work_status(handle, numerator, denominator)
 ****************************************************************************/
int msg_work_status(Client *cli, MemBlock *block)
{
    unsigned char *args[3];
    parse_args(args, 3, block->bytes + HEADER_SIZE, block->nbytes - HEADER_SIZE);

    Job *job = g_hash_table_lookup(g_jobs, args[0]);
    if (!job || job->worker != cli) {
        #if DEBUG
        g_debug("[%s] work_status (%s) - not_worker", cli->id, args[0]);
        #endif
        client_send(cli, new_error_response("not_worker", ""));
        return 0;
    }

    job->status[0] = atoi((char*)args[1]);
    job->status[1] = atoi((char*)args[2]);
    #if DEBUG
    g_debug("[%s] work_status (%s) : %d / %d", cli->id, args[0], job->status[0], job->status[1]);
    #endif

    set_message_magic(block, MAGIC_RESPONSE);
    g_ptr_array_foreach(job->listeners, (GFunc)client_send, block);

    return 0;
}


/* TODO: maybe merge work_complete and work_fail */

/****************************************************************************
  Message Handler: work_complete(handle, result)
 ****************************************************************************/
int msg_work_complete(Client *cli, MemBlock *block)
{
    char *handle = (char*)block->bytes + HEADER_SIZE;
    Job *job = g_hash_table_lookup(g_jobs, handle);
    if (!job || job->worker != cli) {
        #if DEBUG
        g_debug("[%s] work_complete (%s) - not_worker", cli->id, handle);
        #endif
        client_send(cli, new_error_response("not_worker", job?"You don't own this job":"Unknown job"));
        return 0;
    }

    #if DEBUG
    g_debug("[%s] work_complete (%s) : %d bytes", cli->id, handle, block->nbytes - HEADER_SIZE - strlen(handle) - 1);
    #endif
    set_message_magic(block, MAGIC_RESPONSE);
    g_ptr_array_foreach(job->listeners, (GFunc)client_send, block);
    remove_job(job);

    return 0;

}

/****************************************************************************
  Message Handler: work_fail(handle)
 ****************************************************************************/
int msg_work_fail(Client *cli, MemBlock *block)
{
    Job *job = g_hash_table_lookup(g_jobs, block->bytes + HEADER_SIZE);
    if (!job || job->worker != cli) {
        #if DEBUG
        g_debug("[%s] work_fail (%s) - not_worker", cli->id, block->bytes + HEADER_SIZE);
        #endif
        client_send(cli, new_error_response("not_worker", ""));
        return 0;
    }

    #if DEBUG
    g_debug("[%s] work_fail (%s)", cli->id, block->bytes + HEADER_SIZE);
    #endif
    set_message_magic(block, MAGIC_RESPONSE);
    g_ptr_array_foreach(job->listeners, (GFunc)client_send, block);
    remove_job(job);

    return 0;
}

/****************************************************************************
  Message Handler: get_status(handle) -> status_res(handle, known, running, numerator, denominator)
 ****************************************************************************/
int msg_get_status(Client *cli, unsigned char *arg, int arg_len)
{
    char *handle = (char*)arg;
    if (arg_len > MAX_HANDLE_LEN) {
        g_warning("[%s] Invalid handle length received: %d", cli->id, arg_len);
        return -1;
    }

    #if DEBUG
    g_debug("[%s] get_status(%s)", cli->id, handle);
    #endif

    char *known = "0";
    char *running = "0";
    int numerator = -1;
    int denominator = -1;

    Job *job = g_hash_table_lookup(g_jobs, handle);
    if (job) {
        known = "1";
        if (job->worker)
            running = "1";
        numerator = job->status[0];
        denominator = job->status[1];
    }

    MemBlock *block = new_response(MSG_STATUS_RES, 256, NULL);
    char *p = (char*)block->bytes + HEADER_SIZE;
    p += sprintf(p, handle) + 1;
    p += sprintf(p, known) + 1;
    p += sprintf(p, running) + 1;
    if (numerator >= 0) {
        p += sprintf(p, "%d", numerator) + 1;
        p += sprintf(p, "%d", denominator);
    } else {
        *(p++) = 0;
    }
    block->nbytes = (unsigned char*)p - block->bytes;
    set_message_size(block, block->nbytes - HEADER_SIZE);
    client_send(cli, block);

    return 0;
}

/****************************************************************************
 *
 ****************************************************************************/
int process_client(Client *cli)
{
    assert( cli != NULL );

    if ( (cli->buffer_in == NULL) || (cli->buffer_in->nbytes < HEADER_SIZE) )
        return 0;

    uint32_t size = ntohl(*(uint32_t*)(cli->buffer_in->bytes + HEADER_OFFSET_SIZE));

    /* Check if there's a full packet's worth of data */
    if (cli->buffer_in->nbytes < size+HEADER_SIZE) {
        // #ifdef DEBUG
        // g_debug("[%s] Waiting for more data: %d / %d",
        //     cli->id, cli->buffer_in->nbytes, size+HEADER_SIZE);
        // #endif
        return 0;
    }

    int ret = 0;

    int type = ntohl(*(uint32_t*)(cli->buffer_in->bytes + HEADER_OFFSET_TYPE));

    unsigned char *arg = cli->buffer_in->bytes + HEADER_SIZE;
    int argsize = cli->buffer_in->nbytes - HEADER_SIZE;
    arg[argsize] = 0;
    switch(type) {
        case MSG_CAN_DO: ret = msg_can_do(cli, arg, argsize, FALSE); break;
        case MSG_CANT_DO: ret = msg_can_do(cli, arg, argsize, TRUE); break;
        case MSG_CAN_DO_TIMEOUT: ret = msg_can_do_timeout(cli, arg, argsize); break;
        case MSG_RESET_ABILITIES: ret = msg_reset_abilities(cli, arg, argsize); break;
        case MSG_SET_CLIENT_ID: ret = msg_set_client_id(cli, arg, argsize); break;
        case MSG_PRE_SLEEP: ret = msg_pre_sleep(cli, arg, argsize); break;

        case MSG_SUBMIT_JOB: ret = msg_submit_job(cli, arg, argsize, FALSE, FALSE); break;
        case MSG_SUBMIT_JOB_HIGH: ret = msg_submit_job(cli, arg, argsize, FALSE, TRUE); break;
        case MSG_SUBMIT_JOB_BG: ret = msg_submit_job(cli, arg, argsize, TRUE, FALSE); break;

        case MSG_GRAB_JOB: ret = msg_grab_job(cli, arg, argsize); break;
        case MSG_WORK_STATUS: ret = msg_work_status(cli, cli->buffer_in); break;
        case MSG_WORK_COMPLETE: ret = msg_work_complete(cli, cli->buffer_in); break;
        case MSG_WORK_FAIL: ret = msg_work_fail(cli, cli->buffer_in); break;

        case MSG_GET_STATUS: ret = msg_get_status(cli, arg, argsize); break;
        case MSG_ECHO_REQ: ret = msg_echo_req(cli, cli->buffer_in); break;
    default:
        g_warning("[%s] Unknown message received of type %.4x", cli->id, type);
        ret = -1;
    }

	/* We are now done with the input buffer */
    decRef(cli->buffer_in);
    cli->buffer_in = NULL;

    return ret;
}

// void _print_queue(char *func, GQueue *queue, gpointer unused)
// {
//     printf("%s> %.8x %d\n", func, queue, g_queue_get_length(queue));
// }

/******************************************************************
 * This function is called when an event occurs on a client socket
 ******************************************************************/
void client_cb(int fd, short events, void *arg)
{
    assert(arg != NULL);

    Client *cli = arg;
    int free = 0;

    // g_hash_table_foreach(g_jobqueue, _print_queue, NULL);

    if ((events & EV_WRITE) != 0) {
        event_del(&cli->evt);
        cli->evt.ev_events = EV_READ|EV_PERSIST;
        event_add(&cli->evt, NULL);
        if (client_flush(cli) < 0) {
            free = 1;
        }
    }
    if ((events & EV_READ) != 0) {
        int ret = 0;
        if (!cli->buffer_in) {
            cli->buffer_in = getBlock(HEADER_SIZE);
            incRef(cli->buffer_in);
            ret = client_recv(cli, HEADER_SIZE);
        }
        if (ret >= 0) {
            /* Make sure we don't over-read into the next packet */
            int psize = HEADER_SIZE;
            if (cli->buffer_in->nbytes >= HEADER_SIZE) {
                if (ntohl(*(uint32_t*)(cli->buffer_in->bytes + HEADER_OFFSET_MAGIC)) != MAGIC_REQUEST) {
                    free = 1;
                    g_warning("[%s] Invalid MAGIC", cli->id);
                    goto free_client;
                }
                psize = HEADER_SIZE + ntohl(*(uint32_t*)(cli->buffer_in->bytes + HEADER_OFFSET_SIZE));
                /* If the input block isn't large enough to receive the
                   entire packet then switch to one that is */
                if (psize > cli->buffer_in->size) {
                    #if DEBUG
                    g_debug("Switching to bigger block (pktsize=%d)", psize);
                    #endif

                    /* Create new (bigger) block */
                    MemBlock *block = getBlock(psize + 1); /* +1 for terminating NULL to make args easier to work with */
					if (!block) {
                        g_error("Failed to get block of size %d", psize);
						free = 1;
						goto free_client;
					}
                    incRef(block);

                    /* Copy bytes into new block */
                    block->nbytes = cli->buffer_in->nbytes;
                    memmove(block->bytes, cli->buffer_in->bytes, cli->buffer_in->nbytes);

                    /* Swap blocks */
                    decRef(cli->buffer_in);
                    cli->buffer_in = block;
                }
            }
            int num = psize - cli->buffer_in->nbytes;
            if (num > 0)
                ret = client_recv(cli, num);
        }
        if (ret < 0) {
            #if DEBUG
            g_debug("[%s] Connection on closed", cli->id);
            #endif
            free = 1;
        } else if (ret >= 0) {
            if (process_client(cli) != 0) {
                g_warning("[%s] Processing of client failed", cli->id);
                free = 1;
            }
        }
    }
    /*if ((events & (EV_READ|EV_WRITE)) == 0) {
        g_warning("[%s] unhandled event %d", __func__, events);
    }*/

free_client:
    if (free != 0) {
        #if DEBUG
        g_message("[%s] Client disconnected", cli->id);
        #endif

        /*printf("[%s] Removing client %d\n", __func__, cli->fd);*/
        close(cli->fd);
        cli->fd = -1;

        fail_working_jobs(cli);
        stop_all_listening(cli);
        unregister_all_abilities(cli);

        event_del(&cli->evt);
        g_ptr_array_remove_fast(g_clients, cli);

        client_free(cli);
    }
}

/****************************************************************************
 * This function gets called when a connection is made to a listening socket
 ****************************************************************************/
void listener_cb(int fd, short events, void *arg)
{
    struct sockaddr_in sin;
    socklen_t addrlen = sizeof(sin);

    int s = accept(fd, (struct sockaddr *)&sin, &addrlen);
    
#ifndef _WIN32
    fcntl(s, F_SETFL, O_NONBLOCK);
#else
    {
        unsigned long flags = 1;
        ioctlsocket(s, FIONBIO, &flags);
    }
#endif

    Client *cli = client_new();
    cli->state = CLIENT_STATE_CONNECTED;
    cli->fd    = s;
    cli->port  = ntohs(sin.sin_port);
    *(uint32_t*)cli->ip = sin.sin_addr.s_addr;
    sprintf(cli->id, "%d.%d.%d.%d:%d",
        cli->ip[0], cli->ip[1], cli->ip[2], cli->ip[3], cli->port);

    g_ptr_array_add(g_clients, cli);

    event_set(&cli->evt, s, EV_READ|EV_PERSIST, client_cb, cli);
    event_add(&cli->evt, NULL);
}

/****************************************************************************/

gboolean _clean_up_empty_queue(gpointer func, gpointer queue, gpointer user_data)
{ return g_queue_is_empty(queue); }

gboolean _clean_up_empty_ptr_array(gpointer func, gpointer queue, gpointer user_data)
{ return ((GPtrArray*)queue)->len == 0; }

void cleanup_cb(int fd, short events, void *arg)
{
    #if DEBUG
    g_debug("CLEANUP");
    #endif
    g_hash_table_foreach_remove(g_jobqueue, _clean_up_empty_queue, NULL);
    g_hash_table_foreach_remove(g_workers, _clean_up_empty_ptr_array, NULL);
    schedule_cleanup();
}

void schedule_cleanup()
{
    static struct event cleanup_timer;
    struct timeval tv = {CLEANUP_INTERVAL, 0};
    evtimer_set(&cleanup_timer, cleanup_cb, NULL);
    evtimer_add(&cleanup_timer, &tv);
}

/****************************************************************************
 ****************************************************************************/
FILE *g_logfile;
void logger(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer user_data)
{
    struct tm dt;
    time_t tme = time(NULL);
    char str[64], *lvl = "OTHER";
#ifndef _WIN32
    localtime_r(&tme, &dt);
#else
    memcpy(&dt, localtime(&tme), sizeof(dt));
#endif

    strftime(str, 64, "%F %T", &dt);
    switch(level) {
    case G_LOG_LEVEL_DEBUG:
        lvl = "DEBUG";
        break;
    case G_LOG_LEVEL_MESSAGE:
        lvl = "MESSAGE";
        break;
    case G_LOG_LEVEL_WARNING:
        lvl = "WARNING";
        break;
    case 6:
    case G_LOG_LEVEL_ERROR:
        lvl = "ERROR";
        break;
    case 10:
    case G_LOG_LEVEL_CRITICAL:
        lvl = "CRITICAL";
        break;
    default:
        ;
    }
    fprintf(g_logfile, "%s gearmand[0] %s: %s\n", str, lvl, message);
    fflush(g_logfile);
}

/****************************************************************************
 ****************************************************************************/
void parseargs(int argc, char *argv[])
{
    int c;    
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"config",      1, 0, 'c'},
            {"daemon",      0, 0, 'd'},
            {"foreground",  0, 0, 'f'},
            {"log",         1, 0, 'l'},
            {"port",        1, 0, 'p'},
            {"host",        1, 0, 'h'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "c:dfl:p:h:",
                long_options, &option_index);
        if (c == -1)
            break;

        switch(c) {
        case 'l':
            g_logfilename = strdup(optarg);
            break;
        case 'd':
            g_foreground = 0;
            break;
        case 'f':
            g_foreground = 1;
            break;
        case 'h':
            g_bind = strdup(optarg);
            break;
        case 'p':
            g_port = atoi(optarg);
            break;
        }
    }
}

void signal_cb(int fd, short event, void *arg)
{
    /*struct event *signal = arg;

    printf("%s: got signal %d\n", __func__, EVENT_SIGNAL(signal));*/

    struct timeval tv = {0,0};
    event_loopexit(&tv);
}

void detach()
{
#ifndef _WIN32
    if (fork() != 0)
        exit(0);

    setsid();

    if (fork() != 0)
        exit(0);

    umask(0);

    /* TODO: set core size limit */

    int fd;
    for(fd = 0; fd < 1024; fd++)
        close(fd);

    // open("/dev/null", O_RDONLY, 0); /* 0 stdin */
    // open("/dev/null", O_WRONLY, 0); /* 1 stdout */
    // open("/dev/null", O_WRONLY, 0); /* 2 stderr */

    open("/dev/null", O_RDWR, 0);   /* 0 stdin */
    dup2(0, 1);  /* 1 stdout */
    dup2(0, 2);  /* 2 stderr */
#else
    perror("daemon mode is disabled on win32 ...");
    exit(0);
#endif
}

/****************************************************************************
 ****************************************************************************/
int main(int argc, char *argv[])
{
    int nsockets = 0;
    struct event listeners[10];

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 0), &wsaData);
#endif

    parseargs(argc, argv);

    if (g_foreground == 0) {
        detach();
        g_logfile = fopen(g_logfilename, "a");
        g_log_set_default_handler(logger, NULL);
    }

    g_handle_base[0] = 'H';
    g_handle_base[1] = ':';
    if (gethostname(g_handle_base+2, 128-28) != 0) {
        sprintf(g_handle_base+2, "hostname"); /* TODO: figure out some other unique identifier */
    }
    char *p = strchr(g_handle_base, '.');
    if (!p) p = g_handle_base + strlen(g_handle_base);
    *(p++) = ':';
    *p = 0;

    g_thread_init(NULL);

    event_init();
    //printf("%s %s\n", event_get_version(), event_get_method());

#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

#ifndef _WIN32
    struct event sig_int, sig_hup, sig_term;/*, sig_pipe;*/
    if (g_foreground) {
        event_set(&sig_int, SIGINT, EV_SIGNAL|EV_PERSIST, signal_cb, &sig_int);
        event_add(&sig_int, NULL);
        event_set(&sig_hup, SIGHUP, EV_SIGNAL|EV_PERSIST, signal_cb, &sig_hup);
        event_add(&sig_hup, NULL);
    } else {
        signal(SIGINT, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
    }
    event_set(&sig_term, SIGTERM, EV_SIGNAL|EV_PERSIST, signal_cb, &sig_term);
    event_add(&sig_term, NULL);
    /*event_set(&sig_pipe, SIGPIPE, EV_SIGNAL|EV_PERSIST, signal_cb, &sig_pipe);
    event_add(&sig_pipe, NULL);*/
#else
    struct event sig_int, sig_term;/*, sig_pipe;*/
    if (g_foreground) {
        event_set(&sig_int, SIGINT, EV_SIGNAL|EV_PERSIST, signal_cb, &sig_int);
        event_add(&sig_int, NULL);
    } else {
        signal(SIGINT, SIG_IGN);
    }
    event_set(&sig_term, SIGTERM, EV_SIGNAL|EV_PERSIST, signal_cb, &sig_term);
    event_add(&sig_term, NULL);
#endif

    int s = listen_on(inet_addr(g_bind), g_port);
    if (s == -1) {
        perror("failed to listen on port ...");
        return -1;
    }
    event_set(&listeners[nsockets], s, EV_READ|EV_PERSIST,
              listener_cb, &listeners[nsockets]);
    event_add(&listeners[nsockets], NULL);
    nsockets++;

    g_message("listening on port %d", g_port);

    g_clients   = g_ptr_array_new();
    g_jobs = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)job_free);
    g_jobqueue = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, (GDestroyNotify)g_queue_free);
    g_uniq_jobs = g_hash_table_new_full(uniq_job_hash, uniq_job_equal, NULL, NULL);
    g_workers = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, (GDestroyNotify)g_ptr_array_free);

    schedule_cleanup();

    g_message("gearmand running");
    event_dispatch();
    g_message("gearmand stopped");

    g_hash_table_destroy(g_workers);
    g_hash_table_destroy(g_uniq_jobs);
    g_hash_table_destroy(g_jobqueue);
    g_hash_table_destroy(g_jobs);
    g_ptr_array_free(g_clients, TRUE);

    freePools();

    if (g_foreground == 0)
        fclose(g_logfile);

    return 0;
}
