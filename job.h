/*
gearmand - Gearman Server
Copyright (C) 2007  Samuel Stauffer <samuel@descolada.com>

See LICENSE and COPYING for license details.
*/

#ifndef _JOB_H_
#define _JOB_H_

#include <glib.h>
#include <sys/types.h>
#include <event.h>

#include "common.h"
#include "gearmand.h"

typedef struct _UniqJobKey {
    const gchar *func; /* interned */
    unsigned char *uniq;
    int uniq_len;
} UniqJobKey;

guint uniq_job_hash(gconstpointer key);
gboolean uniq_job_equal(gconstpointer a, gconstpointer b);

typedef struct _Job {
    char handle[MAX_HANDLE_LEN+1];
    const gchar *func; /* interned */
    char *uniq;
    unsigned char *arg;
    int arg_len;
    gboolean background;
    int status[2];

    int is_uniq;
    UniqJobKey uniq_key;

    // gboolean finished;

    void *worker;
    int timeout;
    struct event work_timer;
    GPtrArray *listeners;
} Job;

Job *job_new();
void job_free(Job *job);

#endif
