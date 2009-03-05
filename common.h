/*
gearmand - Gearman Server
Copyright (C) 2007  Samuel Stauffer <samuel@descolada.com>

See LICENSE and COPYING for license details.
*/

#ifndef _COMMON_H_
#define _COMMON_H_

#if defined(__APPLE__)
#define MSG_NOSIGNAL 0
#endif

#if defined(_WIN32)
#define MSG_NOSIGNAL 0
#endif

#ifndef max
#define max(a,b) (a<b?a:b)
#define min(a,b) (a<b?a:b)
#endif

#endif
