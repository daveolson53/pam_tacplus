/* crypt.c - TACACS+ encryption related functions
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

#include "libtac.h"
#include "xalloc.h"

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif

#if defined(HAVE_OPENSSL_MD5_H) && defined(HAVE_LIBCRYPTO)
# include <openssl/md5.h>
#else
# include "md5.h"
# ifndef MD5_LBLOCK /*  should be always, since it's in openssl */
#  define MD5_LBLOCK MD5_LEN
# endif 
#endif

/* Produce MD5 pseudo-random pad for TACACS+ encryption.
   Use data from packet header and secret, which
   should be a global variable */
u_char *_tac_md5_pad(int len, HDR *hdr)  {
    int n, i, bufsize;
    int bp = 0; /* buffer pointer */
    int pp = 0; /* pad pointer */
    u_char *pad;
    u_char *buf;
    MD5_CTX mdcontext;

    /* make pseudo pad */
    n = (int)(len/16)+1;  /* number of MD5 runs */
    bufsize = sizeof(hdr->session_id) + strlen(tac_secret) + sizeof(hdr->version)
        + sizeof(hdr->seq_no) + MD5_LBLOCK + 10;
    buf = (u_char *) tac_xcalloc(1, bufsize);
    pad = (u_char *) tac_xcalloc(n, MD5_LBLOCK);

    for (i=0; i<n; i++) {
        /* MD5_1 = MD5{session_id, secret, version, seq_no}
           MD5_2 = MD5{session_id, secret, version, seq_no, MD5_1} */

        /* place session_id, key, version and seq_no in buffer */
        bp = 0;
        bcopy(&hdr->session_id, buf, sizeof(session_id));
        bp += sizeof(session_id);
        bcopy(tac_secret, buf+bp, strlen(tac_secret));
        bp += strlen(tac_secret);
        bcopy(&hdr->version, buf+bp, sizeof(hdr->version));
        bp += sizeof(hdr->version);
        bcopy(&hdr->seq_no, buf+bp, sizeof(hdr->seq_no));
        bp += sizeof(hdr->seq_no);

        /* append previous pad if this is not the first run */
        if (i) {
            bcopy(pad+((i-1)*MD5_LBLOCK), buf+bp, MD5_LBLOCK);
            bp+=MD5_LBLOCK;
        }
  
#if defined(HAVE_OPENSSL_MD5_H) && defined(HAVE_LIBCRYPTO)
        MD5_Init(&mdcontext);
        MD5_Update(&mdcontext, buf, bp);
        MD5_Final(pad+pp, &mdcontext);
#else
        MD5Init(&mdcontext);
        MD5Update(&mdcontext, buf, bp);
        MD5Final(pad+pp, &mdcontext);
#endif
   
        pp += MD5_LBLOCK;
    }

    free(buf);
    return pad;
 
}    /* _tac_md5_pad */

/* Perform encryption/decryption on buffer. This means simply XORing
   each byte from buffer with according byte from pseudo-random
   pad. */
void _tac_crypt(u_char *buf, HDR *th, int length) {
    int i;
    u_char *pad;
 
    /* null operation if no encryption requested */
    if((tac_secret != NULL) && (th->encryption == TAC_PLUS_ENCRYPTED_FLAG)) {
        pad = _tac_md5_pad(length, th);
 
        for (i=0; i<length; i++) {
            *(buf+i) ^= pad[i];
        }
  
        free(pad);
    } else {
        TACSYSLOG((LOG_WARNING, "%s: using no TACACS+ encryption", __func__))
    }
}    /* _tac_crypt */
