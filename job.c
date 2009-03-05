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
#include "job.h"

guint hash(gconstpointer v, guint len)
{
  /* 31 bit hash function */
  const signed char *p = v;
  guint32 h = *p;
  int i;

  for(i = 1, p += 1; i < len; i++, p++)
    h = (h << 5) - h + *p;

  return h;
}

guint uniq_job_hash(gconstpointer key)
{
    const UniqJobKey *uniq_key = key;
    // assert(uniq_key->func != NULL);
    assert(uniq_key->uniq != NULL);
    // return g_str_hash(uniq_key->func) + hash(uniq_key->uniq, uniq_key->uniq_len);
    /* TODO: an interned string's pointer isn't exactly a hash but good enough for now */
    return (guint32)uniq_key->func + hash(uniq_key->uniq, uniq_key->uniq_len);
}

gboolean uniq_job_equal(gconstpointer a, gconstpointer b)
{
    const UniqJobKey *x = a;
    const UniqJobKey *y = b;
    assert(x->func != NULL && x->uniq != NULL);
    assert(y->func != NULL && y->uniq != NULL);
    // return g_str_equal(x->func, y->func) &&
    //     (x->uniq_len == y->uniq_len) &&
    //     (memcmp(x->uniq, y->uniq, x->uniq_len) == 0);
    return (x->func == y->func) &&
        (x->uniq_len == y->uniq_len) &&
        (memcmp(x->uniq, y->uniq, x->uniq_len) == 0);
}

Job *job_new()
{
    Job *job = (Job *)malloc(sizeof(Job));
    if (!job) return NULL;

    job->handle[MAX_HANDLE_LEN] = 0;
    job->func    = NULL;
    job->uniq    = NULL;
    job->arg     = NULL;
    job->arg_len = 0;
    job->background = FALSE;
    job->status[0] = -1;
    job->status[1] = -1;
    job->is_uniq = 0;
    job->timeout = 0;
    // job->finished = FALSE;

    job->worker = NULL;
    job->listeners = g_ptr_array_new();

    return job;
}

void job_free(Job *job)
{
    assert(job != NULL);
    // assert(job->listeners->len == 0);

    if (job->uniq) free(job->uniq);
    if (job->arg) free(job->arg);
    g_ptr_array_free(job->listeners, TRUE);

    free(job);
}
