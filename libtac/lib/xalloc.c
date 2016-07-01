/* xalloc.c - Failsafe memory allocation functions.
 *            Taken from excellent glibc.info ;)
 * 
 * Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 * Jeroen Nijhof <jeroen@jeroennijhof.nl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 *
 * See `CHANGES' file for revision history.
 */

#include "xalloc.h"

void *tac_xcalloc(size_t nmemb, size_t size) {
    void *val = calloc(nmemb, size);
    if(val == 0) {
        TACSYSLOG((LOG_ERR, "%s: calloc(%u,%u) failed", __func__,\
            (unsigned) nmemb, (unsigned) size))
        exit(1);
    }
    return val;
}

void *tac_xrealloc(void *ptr, size_t size) {
    void *val = realloc(ptr, size);
    if(val == 0) {
        TACSYSLOG((LOG_ERR, "%s: realloc(%u) failed", __func__, (unsigned) size))
        exit(1);
    }
    return val;
}

char *tac_xstrdup(const char *s) {
    char *p;
    if (s == NULL) return NULL;

    if ( (p = strdup(s)) == NULL ) {
        TACSYSLOG((LOG_ERR, "%s: strdup(%s) failed: %m", __func__, s))
        exit(1);
    }
    return p;
}


/*
    safe string copy that aborts when destination buffer is too small
*/
char *tac_xstrcpy(char *dst, const char *src, size_t dst_size) {
    if (dst == NULL) {
        TACSYSLOG((LOG_ERR, "tac_xstrcpy(): dst == NULL"));
        abort();
    }
    if (src == NULL) {
        TACSYSLOG((LOG_ERR, "tac_xstrcpy(): src == NULL"));
        abort();
    }
    if (!dst_size)
        return NULL;

    if (strlen(src) >= dst_size) {
        TACSYSLOG((LOG_ERR, "tac_xstrcpy(): argument too long, aborting"));
        abort();
    }

    return strcpy(dst, src);
}

