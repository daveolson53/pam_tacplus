/* acct_r.c - Read accounting reply from server.
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
#include "libtac.h"
#include "messages.h"

/*
 * return value:
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *             LIBTAC_STATUS_READ_TIMEOUT
 *             LIBTAC_STATUS_SHORT_HDR
 *             LIBTAC_STATUS_SHORT_BODY
 *             LIBTAC_STATUS_PROTOCOL_ERR
 *   >= 0 : server response, see TAC_PLUS_AUTHEN_STATUS_...
 */
int tac_acct_read(int fd, struct areply *re) {
    HDR th;
    struct acct_reply *tb = NULL;
    unsigned int len_from_header, len_from_body;
    int r;
    ssize_t packet_read;
    char *msg = NULL;
    int timeleft;
    re->attr = NULL; /* unused */
    re->msg = NULL;

    if (tac_readtimeout_enable &&
        tac_read_wait(fd,tac_timeout*1000, TAC_PLUS_HDR_SIZE,&timeleft) < 0 ) {
        TACSYSLOG((LOG_ERR,\
            "%s: reply timeout after %d secs", __func__, tac_timeout))
        re->msg = tac_xstrdup(acct_syserr_msg);
        re->status = LIBTAC_STATUS_READ_TIMEOUT;
        free(tb);
        return re->status;
    }

    packet_read = read(fd, &th, TAC_PLUS_HDR_SIZE);
    if(packet_read  < TAC_PLUS_HDR_SIZE) {
        TACSYSLOG((LOG_ERR,\
            "%s: short reply header, read %ld of %d: %m", __func__,\
            packet_read, TAC_PLUS_HDR_SIZE))
        re->msg = tac_xstrdup(acct_syserr_msg);
        re->status = LIBTAC_STATUS_SHORT_HDR;
        free(tb);
        return re->status;
    }

    /* check the reply fields in header */
    msg = _tac_check_header(&th, TAC_PLUS_ACCT);
    if(msg != NULL) {
        re->msg = tac_xstrdup(msg);
        re->status = LIBTAC_STATUS_PROTOCOL_ERR;
        free(tb);
        TACDEBUG((LOG_DEBUG, "%s: exit status=%d, status message \"%s\"",\
            __func__, re->status, re->msg != NULL ? re->msg : ""))
        return re->status;
    }

    len_from_header=ntohl(th.datalength);
    if (len_from_header > TAC_PLUS_MAX_PACKET_SIZE) {
        TACSYSLOG((LOG_ERR,\
            "%s: length declared in the packet %d exceeds max packet size %d",\
            __func__,\
            len_from_header, TAC_PLUS_MAX_PACKET_SIZE))
        re->status=LIBTAC_STATUS_SHORT_HDR;
        free(tb);
        return re->status;
    }
    tb=(struct acct_reply *) tac_xcalloc(1, len_from_header);

    /* read reply packet body */
    if (tac_readtimeout_enable &&
        tac_read_wait(fd,timeleft,len_from_header,NULL) < 0 ) {
        TACSYSLOG((LOG_ERR,\
            "%s: reply timeout after %d secs", __func__, tac_timeout))
        re->msg = tac_xstrdup(acct_syserr_msg);
        re->status = LIBTAC_STATUS_READ_TIMEOUT;
        free(tb);
        return re->status;
    }

    r=read(fd, tb, len_from_header);
    if(r < len_from_header) {
        TACSYSLOG((LOG_ERR,\
            "%s: short reply body, read %d of %d: %m",\
            __func__,\
            r, len_from_header))
        re->msg = tac_xstrdup(acct_syserr_msg);
        re->status = LIBTAC_STATUS_SHORT_BODY;
        free(tb);
        return re->status;
    }

    /* decrypt the body */
    _tac_crypt((u_char *) tb, &th, len_from_header);

    /* Convert network byte order to host byte order */
    tb->msg_len  = ntohs(tb->msg_len);
    tb->data_len = ntohs(tb->data_len);

    /* check the length fields */
    len_from_body=sizeof(tb->msg_len) + sizeof(tb->data_len) +
        sizeof(tb->status) + tb->msg_len + tb->data_len;

    if(len_from_header != len_from_body) {
        TACSYSLOG((LOG_ERR,\
            "%s: inconsistent reply body, incorrect key?",\
            __func__))
        re->msg = tac_xstrdup(acct_syserr_msg);
        re->status = LIBTAC_STATUS_PROTOCOL_ERR;
        free(tb);
        return re->status;
    }

    /* save status and clean up */
    r=tb->status;
    if(tb->msg_len) {
        msg=(char *) tac_xcalloc(1, tb->msg_len+1);
        bcopy((u_char *) tb+TAC_ACCT_REPLY_FIXED_FIELDS_SIZE, msg, tb->msg_len); 
        msg[(int)tb->msg_len] = '\0';
        re->msg = msg;      /* Freed by caller */
    }

    /* server logged our request successfully */
    if (tb->status == TAC_PLUS_ACCT_STATUS_SUCCESS) {
        TACDEBUG((LOG_DEBUG, "%s: accounted ok", __func__))
        if (!re->msg) re->msg = tac_xstrdup(acct_ok_msg);
        re->status = tb->status;
        free(tb);
        return re->status;
    }

    TACDEBUG((LOG_DEBUG, "%s: accounting failed, server reply status=%d",\
        __func__, tb->status))
    switch(tb->status) {
        case TAC_PLUS_ACCT_STATUS_FOLLOW:
            re->status = tb->status;
            if (!re->msg) re->msg=tac_xstrdup(acct_fail_msg);
            break;

        case TAC_PLUS_ACCT_STATUS_ERROR:
        default:
            re->status = tb->status;
            if (!re->msg) re->msg=tac_xstrdup(acct_err_msg);
            break;
    }

    free(tb);
    return re->status;
}
