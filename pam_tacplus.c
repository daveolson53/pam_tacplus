/* pam_tacplus.c - PAM interface for TACACS+ protocol.
 *
 * Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 * Jeroen Nijhof <jeroen@jeroennijhof.nl>
 *
 * Copyright 2015, 2016 Cumulus Networks, Inc.  All rights reserved.
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

#include "pam_tacplus.h"
#include "support.h"

#include <stdlib.h>     /* malloc */
#include <stdio.h>
#include <syslog.h>
#include <netdb.h>      /* gethostbyname */
#include <sys/socket.h> /* in_addr */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>     /* va_ */
#include <signal.h>
#include <string.h>     /* strdup */
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>

#include <tacplus/map_tacplus_user.h>

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif

#if defined(HAVE_OPENSSL_RAND_H) && defined(HAVE_LIBCRYPTO)
# include <openssl/rand.h>
#else
# include "libtac/lib/magic.h"
#endif

/* address of server discovered by pam_sm_authenticate */
tacplus_server_t active_server;

extern char *__vrfname;

/* privilege level, used for mapping from tacacs userid to local
 * tacacs{0...15} user
 */
static unsigned priv_level;

/* accounting task identifier */
static short unsigned int task_id = 0;


/* Helper functions */
int _pam_send_account(int tac_fd, int type, const char *user, char *tty,
    char *r_addr, char *cmd) {
    char buf[64];
    struct tac_attrib *attr = NULL;
    int retval = -1;
    struct areply re;

    re.msg = NULL;
    snprintf(buf, sizeof buf, "%lu", (unsigned long)time(NULL));

    if (type == TAC_PLUS_ACCT_FLAG_START) {
        tac_add_attrib(&attr, "start_time", buf);
    } else if (type == TAC_PLUS_ACCT_FLAG_STOP) {
        tac_add_attrib(&attr, "stop_time", buf);
    }
    snprintf(buf, sizeof buf, "%hu", task_id);
    tac_add_attrib(&attr, "task_id", buf);
    tac_add_attrib(&attr, "service", tac_service);
    if(tac_protocol[0] != '\0')
      tac_add_attrib(&attr, "protocol", tac_protocol);
    if (cmd != NULL) {
        tac_add_attrib(&attr, "cmd", cmd);
    }

    retval = tac_acct_send(tac_fd, type, user, tty, r_addr, attr);

    /* attribute is no longer needed */
    tac_free_attrib(&attr);

    if(retval < 0) {
        _pam_log (LOG_WARNING, "%s: send %s accounting failed (task %hu)",
            __func__, tac_acct_flag2str(type), task_id);
    }
    else if( tac_acct_read(tac_fd, &re) != TAC_PLUS_ACCT_STATUS_SUCCESS ) {
        _pam_log (LOG_WARNING, "%s: accounting %s failed (task %hu)",
            __func__, tac_acct_flag2str(type), task_id);
        retval = -1;
    }
    else
        retval = 0;

    if(re.msg != NULL)
        free(re.msg);

    active_server.addr = NULL;
    close(tac_fd);
    tac_fd = -1;
    return retval;
}

/*
 * Send an accounting record to the TACACS+ server.
 * We send the start/stop accounting records even if the user is not known
 * to the TACACS+ server.   This seems non-intuitive, but it's the way
 * this code is written to work.
 */
int _pam_account(pam_handle_t *pamh, int argc, const char **argv,
    int type, char *cmd) {

    int retval;
    int ctrl;
    char *user = NULL;
    char *tty = NULL;
    char *r_addr = NULL;
    char *typemsg;
    int status = PAM_SESSION_ERR;
    int srv_i, tac_fd;

    typemsg = tac_acct_flag2str(type);
    ctrl = _pam_parse (argc, argv);

    if (ctrl & PAM_TAC_DEBUG)
        syslog (LOG_DEBUG, "%s: [%s] called (pam_tacplus v%u.%u.%u)",
            __func__, typemsg, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

    _pam_get_user(pamh, &user);
    if (user == NULL)
        return PAM_USER_UNKNOWN;

    if (ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: username [%s] obtained", __func__, user);

    if (!task_id)
#if defined(HAVE_OPENSSL_RAND_H) && defined(HAVE_LIBCRYPTO)
        RAND_pseudo_bytes((unsigned char *) &task_id, sizeof(task_id));
#else
        task_id = (short unsigned int) tac_magic();
#endif

    _pam_get_terminal(pamh, &tty);
    if(!strncmp(tty, "/dev/", 5))
        tty += 5;
    if (ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: tty [%s] obtained", __func__, tty);

    _pam_get_rhost(pamh, &r_addr);
    if (ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: rhost [%s] obtained", __func__, r_addr);

    /* checks for specific data required by TACACS+, which should
       be supplied in command line  */
    if(tac_protocol[0] == '\0') {
        _pam_log (LOG_ERR, "ACC: TACACS+ protocol type not configured");
        return PAM_AUTH_ERR;
    }

    /* when this module is called from within pppd or other
       application dealing with serial lines, it is likely
       that we will get hit with signal caused by modem hangup;
       this is important only for STOP packets, it's relatively
       rare that modem hangs up on accounting start */
    if(type == TAC_PLUS_ACCT_FLAG_STOP) {
        signal(SIGALRM, SIG_IGN);
        signal(SIGCHLD, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
    }

    /*
     * If PAM_SESSION_ERR is used, then the pam config can't
     * ignore server failures, so use PAM_AUTHINFO_UNAVAIL.
     *
     * We have to make a new connection each time, because libtac is single
     * threaded (doesn't support multiple connects at the same time due to
     * use of globals)), and doesn't have support for persistent connections.
     * That's fixable, but not worth the effort at this point.
     *
     * TODO: this should be converted to use do_tac_connect eventually.
     */
    status = PAM_AUTHINFO_UNAVAIL;
    for(srv_i = 0; srv_i < tac_srv_no; srv_i++) {
        tac_fd = tac_connect_single(tac_srv[srv_i].addr, tac_srv[srv_i].key,
            NULL, __vrfname);
        if (tac_fd < 0) {
            _pam_log(LOG_WARNING, "%s: error sending %s (fd)", __func__,
                typemsg);
            continue;
        }
        if (ctrl & PAM_TAC_DEBUG)
            syslog(LOG_DEBUG, "%s: connected with fd=%d to srv[%d] %s", __func__,
                tac_fd, srv_i, tac_srv[srv_i].addr ?
                tac_ntop(tac_srv[srv_i].addr->ai_addr) : "not set");

        retval = _pam_send_account(tac_fd, type, user, tty, r_addr, cmd);
        if (retval < 0) {
            _pam_log(LOG_WARNING, "%s: error sending %s (acct)",
                __func__, typemsg);
        } else {
            status = PAM_SUCCESS;
            if (ctrl & PAM_TAC_DEBUG)
                syslog(LOG_DEBUG, "%s: [%s] for [%s] sent", __func__, typemsg, user);
        }

        if ((status == PAM_SUCCESS) && !(ctrl & PAM_TAC_ACCT)) {
            /* do not send acct start/stop packets to _all_ servers */
            break;
        }
    }

    if (type == TAC_PLUS_ACCT_FLAG_STOP) {
        signal(SIGALRM, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
    }
    return status;
}


/*
 * Talk to the server for authentication
 */
static int tac_auth_converse(int ctrl, int fd, int *sptr,
    char *pass, pam_handle_t * pamh) {
    int msg, status, flags;
    int ret = 1;
    struct areply re = { .attr = NULL, .msg = NULL, .status = 0, .flags = 0 };
    struct pam_message conv_msg = { .msg_style = 0, .msg = NULL };
    struct pam_response *resp = NULL;

    msg = tac_authen_read(fd, &re);

    if (NULL != re.msg) {
        conv_msg.msg = re.msg;
    }

    /* talk the protocol */
    switch (msg) {
        case TAC_PLUS_AUTHEN_STATUS_PASS:
            /* success */
            if (ctrl & PAM_TAC_DEBUG)
                syslog(LOG_DEBUG, "tacacs status: TAC_PLUS_AUTHEN_STATUS_PASS");
            if (NULL != conv_msg.msg) {
                int retval = -1;

                conv_msg.msg_style = PAM_TEXT_INFO;
                retval = converse(pamh, 1, &conv_msg, &resp);
                if (PAM_SUCCESS == retval) {
                    if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
                        syslog(LOG_DEBUG, "send msg=\"%s\"", conv_msg.msg);
                }
                else {
                    _pam_log(LOG_WARNING, "%s: error sending msg=\"%s\", retval=%d",
                             __func__, conv_msg.msg, retval);
                }
            }
            *sptr = PAM_SUCCESS;
            ret = 0;
            break;

        case TAC_PLUS_AUTHEN_STATUS_FAIL:
            /*
             * This can be a user unknown case, so we don't want to stop
             * trying other servers when we hit this case during authentication
             */
            if (ctrl & PAM_TAC_DEBUG)
                syslog(LOG_DEBUG, "tacacs status: TAC_PLUS_AUTHEN_STATUS_FAIL");
            if (NULL != conv_msg.msg) {
                int retval = -1;

                conv_msg.msg_style = PAM_ERROR_MSG;
                retval = converse(pamh, 1, &conv_msg, &resp);
                if (PAM_SUCCESS == retval) {
                    if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
                        syslog(LOG_DEBUG, "send msg=\"%s\"", conv_msg.msg);
                }
                else {
                    _pam_log(LOG_WARNING, "%s: error sending msg=\"%s\", retval=%d",
                             __func__, conv_msg.msg, retval);
                }
            }

            *sptr = PAM_AUTH_ERR;
            ret = 0;
            _pam_log(LOG_NOTICE, "auth failed %d", msg);
            break;

        case TAC_PLUS_AUTHEN_STATUS_GETDATA:
            /* not implemented */
            if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
                syslog(LOG_DEBUG, "tacacs status: TAC_PLUS_AUTHEN_STATUS_GETDATA");

            if (NULL != conv_msg.msg) {
                int retval = -1;
                int echo_off = (0x1 == (re.flags & 0x1));

                conv_msg.msg_style = echo_off ? PAM_PROMPT_ECHO_OFF : PAM_PROMPT_ECHO_ON;
                retval = converse(pamh, 1, &conv_msg, &resp);
                if (PAM_SUCCESS == retval) {
                    if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
                        syslog(LOG_DEBUG, "sent msg=\"%s\", resp=\"%s\"",
                               conv_msg.msg, resp->resp);

                    if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
                        syslog(LOG_DEBUG, "%s: calling tac_cont_send", __func__);

                    if (0 > tac_cont_send_seq(fd, resp->resp, re.seq_no + 1)) {
                        _pam_log(LOG_ERR, "error sending continue req to TACACS+ server");
                        status = PAM_AUTH_ERR;
                    }
                }
                else {
                    _pam_log(LOG_WARNING, "%s: error sending msg=\"%s\", retval=%d (%s)",
                             __func__, conv_msg.msg, retval, pam_strerror(pamh, retval));
                    status = PAM_AUTH_ERR;
                }
            }
            else {
                syslog(LOG_ERR, "GETDATA response with no message, returning PAM_AUTH_ERR");

                status = PAM_AUTH_ERR;
            }

            ret = 0;
            break;

        case TAC_PLUS_AUTHEN_STATUS_GETUSER:
            /* not implemented */
            if (ctrl & PAM_TAC_DEBUG)
                syslog(LOG_DEBUG, "tacacs status: TAC_PLUS_AUTHEN_STATUS_GETUSER");

            ret = 0;
            break;

        case TAC_PLUS_AUTHEN_STATUS_GETPASS:
            if (ctrl & PAM_TAC_DEBUG)
                syslog(LOG_DEBUG, "tacacs status: TAC_PLUS_AUTHEN_STATUS_GETPASS");

            if (ctrl & PAM_TAC_DEBUG)
                syslog(LOG_DEBUG, "%s: tac_cont_send called", __func__);

            if (tac_cont_send(fd, pass) < 0) {
                _pam_log (LOG_ERR, "error sending continue req to TACACS+ server");
                ret = 0;
                break;
            }
            /* continue the while loop; go read tac response */
            break;

        case TAC_PLUS_AUTHEN_STATUS_RESTART:
            /* try it again */
            if (ctrl & PAM_TAC_DEBUG)
                syslog(LOG_DEBUG, "tacacs status: TAC_PLUS_AUTHEN_STATUS_RESTART (not impl)");

            /*
             * not implemented
             * WdJ: I *think* you can just do tac_authen_send(user, pass) again
             *      but I'm not sure
             */
            ret = 0;
            break;

        case TAC_PLUS_AUTHEN_STATUS_ERROR:
            /* server has problems */
            if (ctrl & PAM_TAC_DEBUG)
                syslog(LOG_DEBUG, "tacacs status: TAC_PLUS_AUTHEN_STATUS_ERROR");

            ret = 0;
            break;

        case TAC_PLUS_AUTHEN_STATUS_FOLLOW:
            /* server tells to try a different server address */
            /* not implemented */
            if (ctrl & PAM_TAC_DEBUG)
                syslog(LOG_DEBUG, "tacacs status: TAC_PLUS_AUTHEN_STATUS_FOLLOW");

            ret = 0;
            break;

        default:
            if (msg < 0) {
                /* connection error */
                ret = 0;
                if (ctrl & PAM_TAC_DEBUG)
                    syslog(LOG_DEBUG, "error communicating with tacacs server");
                break;
            }

            /* unknown response code */
            ret = 0;
            if (ctrl & PAM_TAC_DEBUG)
                syslog(LOG_DEBUG, "tacacs status: unknown response 0x%02x", msg);
    }

    if (NULL != resp) {
       free(resp->resp);
       free(resp);
    }

    if (NULL != re.msg);
        free(re.msg);

    return ret;
}

/*
 * Only acct and auth now; should handle all the cases here
 * Talk to the tacacs server for each type of transaction conversation
 */
static void talk_tac_server(int ctrl, int fd, char *user, char *pass,
                            char *tty, char *r_addr, struct tac_attrib **attr,
                            int *sptr, struct areply *reply,
                            pam_handle_t * pamh) {
    if(!pass && attr) {  /* acct, much simpler */
        int retval;
        struct areply arep;
        if(*tac_protocol) {
            tac_add_attrib(attr, "protocol", tac_protocol);
        }
        else
            _pam_log (LOG_ERR, "SM: TACACS+ protocol type not configured "
                "(IGNORED)");
        tac_add_attrib(attr, "cmd", "");
        retval = tac_author_send(fd, user, tty, r_addr, *attr);
        if(retval < 0) {
            _pam_log (LOG_ERR, "error getting authorization");

            *sptr =  PAM_AUTH_ERR;
            return;
        }

        if (ctrl & PAM_TAC_DEBUG)
            syslog(LOG_DEBUG, "%s: sent authorization request for [%s]",
                __func__, user);

        arep.msg = NULL;
        tac_author_read(fd, &arep);
        if (reply)
            *reply = arep;

        if(arep.status != AUTHOR_STATUS_PASS_ADD &&
            arep.status != AUTHOR_STATUS_PASS_REPL) {
            /*
             * this is debug because we can get called for any user for
             * commands like sudo, not just tacacs users
             */
            *sptr = PAM_PERM_DENIED;
            _pam_log (LOG_ERR, "TACACS+ authorization failed for [%s] (status=%d)",
                user, arep.status);
            if(arep.msg != NULL)
                free (arep.msg);
        }
        else  {
            *sptr = PAM_SUCCESS;
        }
    }
    else if (pass)  { /* auth */
        if (tac_authen_send(fd, user, pass, tty, r_addr, TAC_PLUS_AUTHEN_LOGIN) < 0) {
            _pam_log(LOG_ERR, "error sending auth req to TACACS+ server");
        }
        else {
            while ( tac_auth_converse(ctrl, fd, sptr, pass, pamh))
                    ;
        }
    }
}


/*
 * find a responding tacacs server, and converse with it.
 * See comments at do_tac_connect() below
 */
static void find_tac_server(int ctrl, int *tacfd, char *user, char *pass,
                           char *tty, char *r_addr, struct tac_attrib **attr,
                           int *sptr, struct areply *reply, pam_handle_t * pamh) {
    int fd = -1, srv_i;

    for (srv_i = 0; srv_i < tac_srv_no; srv_i++) {
        if (ctrl & PAM_TAC_DEBUG)
            syslog(LOG_DEBUG, "%s: trying srv[%d] %s", __func__, srv_i,
                tac_srv[srv_i].addr ?
                tac_ntop(tac_srv[srv_i].addr->ai_addr) : "not set");

        fd = tac_connect_single(tac_srv[srv_i].addr, tac_srv[srv_i].key, NULL,
            __vrfname);
        if (fd < 0) {
            _pam_log(LOG_ERR, "connection to srv[%d] %s failed: %m", srv_i,
                tac_srv[srv_i].addr ?
                tac_ntop(tac_srv[srv_i].addr->ai_addr) : "not set");
            active_server.addr = NULL; /*  in case last in list */
            continue;
        }

        talk_tac_server(ctrl, fd, user, pass, tty, r_addr, attr, sptr,
            reply, pamh);

        if (*sptr == PAM_SUCCESS || *sptr == PAM_AUTH_ERR ||
            *sptr == PAM_PERM_DENIED) {
            if (ctrl & PAM_TAC_DEBUG)
                syslog(LOG_DEBUG, "%s: srv[%d] %s, pam_status=%d", __func__,
                   srv_i, tac_ntop(tac_srv[srv_i].addr->ai_addr), *sptr);
            if (*sptr == PAM_SUCCESS) {
                if (active_server.addr == NULL) {
                    active_server.addr = tac_srv[srv_i].addr;
                    active_server.key = tac_srv[srv_i].key;
                }
                break;
            }
            /*  else try other servers, if any. On errs, won't need fd */
        }
        else /*  in case end of list */
            active_server.addr = NULL;

        close(fd);
        fd = -1;
    }
    *tacfd = fd;
}

/*
 * We have to make a new connection each time, because libtac is single
 * threaded (doesn't support multiple connects at the same time due to
 * use of globals), and doesn't have support for persistent connections.
 * That's fixable, but not worth the effort at this point.
 *
 * Trying to make this common code is ugly, but worth it to simplify
 * maintenance and debugging.
 *
 * The problem is that the definition allows for multiple tacacs
 * servers to be consulted, but a lot of the code was written such
 * that once a server is found that responds, it keeps using it.
 * That means when we are finding a server we need to do the full sequence.
 * The related issue is that the lower level code can't communicate
 * with multiple servers at the same time, and can't keep a connection
 * open.
 *
 * TODO: Really should have a structure to pass user, pass, tty, and r_addr
 * around everywhere.
 */
static int do_tac_connect(int ctrl, int *tacfd, char *user, char *pass,
                          char *tty, char *r_addr, struct tac_attrib **attr,
                          struct areply *reply, pam_handle_t * pamh) {
    int status = PAM_AUTHINFO_UNAVAIL, fd;

    if (active_server.addr == NULL) { /* find a server with the info we want */
        find_tac_server(ctrl, &fd, user, pass, tty, r_addr, attr, &status,
            reply, pamh);
    }
    else { /* connect to the already chosen server, so we get
            * consistent results.  */
        if (ctrl & PAM_TAC_DEBUG)
            syslog(LOG_DEBUG, "%s: use previous server %s", __func__,
               tac_ntop(active_server.addr->ai_addr));

        fd = tac_connect_single(active_server.addr, active_server.key, NULL,
            __vrfname);
        if (fd < 0)
            _pam_log(LOG_ERR, "reconnect failed: %m");
        else
            talk_tac_server(ctrl, fd, user, pass, tty, r_addr, attr, &status,
                reply, pamh);
    }

    /*
     * this is debug because we can get called for any user for
     * commands like sudo, not just tacacs users, so it's not an
     * error to fail here.  The caller can handle the logging.
     */
    if ((ctrl & PAM_TAC_DEBUG) && status != PAM_SUCCESS &&
        status != PAM_AUTH_ERR)
        _pam_log(LOG_ERR, "no more servers to connect");
    if (tacfd)
        *tacfd = fd; /* auth caller needs fd */
    else if (fd != -1)
        close(fd); /* acct caller doesn't need connection */
    return status;
}

/* Main PAM functions */

/* authenticates user on remote TACACS+ server
 * returns PAM_SUCCESS if the supplied username and password
 * pair is valid
 */
PAM_EXTERN
int pam_sm_authenticate (pam_handle_t * pamh, int flags,
    int argc, const char **argv) {
    int ctrl, retval;
    char *user, *puser;
    char *pass;
    char *tty;
    char *r_addr;
    int status;

    priv_level = 0;
    user = pass = tty = r_addr = NULL;

    ctrl = _pam_parse(argc, argv);

    if (ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: called (pam_tacplus v%u.%u.%u)",
            __func__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

    /* reset static state in case we are re-entered */
    _reset_saved_user(ctrl & PAM_TAC_DEBUG);

    /*
     * If a mapped user entry already exists, we are probably being
     * used for su or sudo, so we need to get the original user password,
     * rather than the mapped user.
     * Decided based on auid != uid and then do the lookup, similar to
     * find_pw_user() in nss_tacplusc
     */
    _pam_get_user(pamh, &puser);
    user = get_user_to_auth(puser);

    if (user == NULL)
        return PAM_USER_UNKNOWN;

    if (ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: user [%s] obtained", __func__, user);

    retval = tacacs_get_password (pamh, flags, ctrl, &pass);
    if (retval != PAM_SUCCESS || pass == NULL || *pass == '\0') {
        _pam_log(LOG_ERR, "unable to obtain password");
        status = PAM_CRED_INSUFFICIENT;
        goto err;
    }

    retval = pam_set_item (pamh, PAM_AUTHTOK, pass);
    if (retval != PAM_SUCCESS) {
        _pam_log(LOG_ERR, "unable to set password");
        status = PAM_CRED_INSUFFICIENT;
        goto err;
    }

    if (ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: password obtained", __func__);

    _pam_get_terminal(pamh, &tty);
    if (!strncmp(tty, "/dev/", 5))
        tty += 5;
    if (ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: tty [%s] obtained", __func__, tty);

    _pam_get_rhost(pamh, &r_addr);
    if (ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: rhost [%s] obtained", __func__, r_addr);

    status = do_tac_connect(ctrl, NULL, user, pass, tty, r_addr, NULL, NULL, pamh);

    if (ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: exit with pam status: %d", __func__, status);

err:
    if (user && user != puser)
        free(user); /* it was stdrup'ed */
    if (NULL != pass) {
        bzero(pass, strlen (pass));
        free(pass);
    }

    return status;
}    /* pam_sm_authenticate */


/* no-op function to satisfy PAM authentication module */
PAM_EXTERN
int pam_sm_setcred (pam_handle_t * pamh, int flags,
    int argc, const char **argv) {

    int ctrl = _pam_parse (argc, argv);

    if (ctrl & PAM_TAC_DEBUG)
        syslog (LOG_DEBUG, "%s: called (pam_tacplus v%u.%u.%u)",
            __func__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

    return PAM_SUCCESS;
}    /* pam_sm_setcred */


/* authorizes user on remote TACACS+ server, i.e. checks
 * his permission to access requested service
 * returns PAM_SUCCESS if the service is allowed
 */
PAM_EXTERN
int pam_sm_acct_mgmt (pam_handle_t * pamh, int flags,
    int argc, const char **argv) {

    int ctrl, status=PAM_AUTH_ERR;
    char *user;
    char *tty;
    char *r_addr;
    struct areply arep;
    struct tac_attrib *attr_s = NULL, *attr;
    int tac_fd = -1;

    user = tty = r_addr = NULL;
    memset(&arep, 0, sizeof(arep));

    /* this also obtains service name for authorization
       this should be normally performed by pam_get_item(PAM_SERVICE)
       but since PAM service names are incompatible TACACS+
       we have to pass it via command line argument until a better
       solution is found ;) */
    ctrl = _pam_parse (argc, argv);

    if (ctrl & PAM_TAC_DEBUG)
        syslog (LOG_DEBUG, "%s: called (pam_tacplus v%u.%u.%u)",
            __func__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

    _pam_get_user(pamh, &user);
    if (user == NULL)
        return PAM_USER_UNKNOWN;


    _pam_get_terminal(pamh, &tty);
    if(!strncmp(tty, "/dev/", 5))
        tty += 5;

    _pam_get_rhost(pamh, &r_addr);

    /* checks for specific data required by TACACS+, which should
       be supplied in pam module command line  */
    if(!*tac_service) {
        _pam_log (LOG_ERR, "SM: TACACS+ service type not configured");
        return PAM_AUTH_ERR;
    }

    tac_add_attrib(&attr_s, "service", tac_service);
    if(tac_protocol != NULL && tac_protocol[0] != '\0')
          tac_add_attrib(&attr_s, "protocol", tac_protocol);
    tac_add_attrib(&attr_s, "cmd", "");

    memset(&arep, 0, sizeof arep);

    /*
     * Check if user is authorized, independently of authentication.
     * Authentication may have happened via ssh public key, rather than
     * via TACACS+.  PAM should not normally get to this entry point if
     * user is not yet authenticated.
     * We only write the mapping entry (if needed) when authorization
     * is succesful.
    */
    status = do_tac_connect(ctrl, &tac_fd, user, NULL, tty, r_addr, &attr_s,
        &arep, pamh);
    tac_free_attrib(&attr_s);
    if(active_server.addr == NULL || tac_fd < 0) {
        /* we need to return PAM_AUTHINFO_UNAVAIL here, rather than
         * PAM_AUTH_ERR, or we can't use "ignore" in the pam configuration
         */
        status = PAM_AUTHINFO_UNAVAIL;
        goto cleanup;
    }

    if(status) {
        if (ctrl & PAM_TAC_DEBUG)
            _pam_log(LOG_NOTICE, "No TACACS mapping for %s after auth failure",
                user);
        goto cleanup;
    }

    if (ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: user [%s] successfully authorized", __func__,
            user);

    attr = arep.attr;
    while (attr != NULL)  {
        char attribute[attr->attr_len];
        char value[attr->attr_len];
        char attrenv[attr->attr_len];
        char *sep;

        sep = index(attr->attr, '=');
        if(sep == NULL)
            sep = index(attr->attr, '*');
        if(sep != NULL) {
            bcopy(attr->attr, attribute, attr->attr_len-strlen(sep));
            attribute[attr->attr_len-strlen(sep)] = '\0';
            bcopy(sep, value, strlen(sep));
            value[strlen(sep)] = '\0';

            size_t i;
            for (i = 0; attribute[i] != '\0'; i++) {
                attribute[i] = toupper(attribute[i]);
                if (attribute[i] == '-')
                    attribute[i] = '_';
            }

            if (ctrl & PAM_TAC_DEBUG)
                syslog(LOG_DEBUG, "%s: returned attribute `%s(%s)' from server",
                    __func__, attribute, value);

            if(strncmp(attribute, "PRIV", 4) == 0) {
                char *ok;

                /* because of the separation above, value will start with
                 * the separator, which we don't want.  */
                priv_level = (unsigned)strtoul(value+1, &ok, 0);
                /* if this fails, we leave priv_level at 0, which is
                 * least privileged, so that's OK, but at least report it
                 */
                if (ok == value)
                    _pam_log (LOG_WARNING,
                        "%s: non-numeric privilege for %s, got (%s)",
                        __func__, attribute, value+1);
            }

            /*
             * make returned attributes available for other PAM modules via PAM
             * environment. Since separator can be = or *, ensure it's = for
             * the env.
             */
            snprintf(attrenv, sizeof attribute, "%s=%s", attribute, value+1);
            if (pam_putenv(pamh, attrenv) != PAM_SUCCESS)
                _pam_log(LOG_WARNING, "%s: unable to set PAM environment (%s)",
                    __func__, attribute);

        } else {
            syslog(LOG_WARNING, "%s: invalid attribute `%s', no separator",
                __func__, attr->attr);
        }
        attr = attr->next;
    }

    update_mapped(pamh, user, priv_level, r_addr);


cleanup:
    /* free returned attributes */
    if(arep.attr != NULL)
        tac_free_attrib(&arep.attr);

    if(arep.msg != NULL)
        free (arep.msg);

    if(tac_fd >= 0) {
        active_server.addr = NULL;
        close(tac_fd);
        tac_fd = -1;
    }

    return status;
}    /* pam_sm_acct_mgmt */

/*
 * accounting packets may be directed to any TACACS+ server,
 * independent from those used for authentication and authorization;
 * they may be also directed to all specified servers
 */

static short unsigned int session_taskid;

/*
 * send START accounting request to the remote TACACS+ server
 * returns PAM error only if the request was refused or there
 * were problems connection to the server
 * sets sess_taskid so it can be used in close_session, so that
 * accounting start and stop records have the same task_id, as
 * the specification requires.
 */
PAM_EXTERN
int pam_sm_open_session (pam_handle_t * pamh, int flags,
    int argc, const char **argv) {

    if (!task_id)
#if defined(HAVE_OPENSSL_RAND_H) && defined(HAVE_LIBCRYPTO)
        RAND_pseudo_bytes((unsigned char *) &task_id, sizeof(task_id));
#else
        task_id=(short int) tac_magic();
#endif
    session_taskid = task_id;
    return _pam_account(pamh, argc, argv, TAC_PLUS_ACCT_FLAG_START, NULL);
}    /* pam_sm_open_session */

/* sends STOP accounting request to the remote TACACS+ server
 * returns PAM error only if the request was refused or there
 * were problems connection to the server
 */
PAM_EXTERN
int pam_sm_close_session (pam_handle_t * pamh, int flags,
    int argc, const char **argv) {
    int rc;
    char *user;

    _pam_get_user(pamh, &user);

    task_id = session_taskid; /* task_id must match start */
    rc = _pam_account(pamh, argc, argv, TAC_PLUS_ACCT_FLAG_STOP, NULL);
    __update_loguid(user); /* now dead, cleanup mapping */
    return rc;
}    /* pam_sm_close_session */


#ifdef PAM_SM_PASSWORD
/* Tested for servers that require password change during challenge/response */
PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t * pamh, int flags,
    int argc, const char **argv) {

    int ctrl;
    char *user;
    char *pass;
    char *tty;
    char *r_addr;
    const void *pam_pass = NULL;
    int srv_i;
    int status;

    user = pass = tty = r_addr = NULL;

    ctrl = _pam_parse(argc, argv);

    if (ctrl & PAM_TAC_DEBUG)
        syslog (LOG_DEBUG, "%s: called (pam_tacplus v%u.%u.%u) (flags=%d, argc=%d)",
            __func__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT, flags, argc);

    if (   (pam_get_item(pamh, PAM_OLDAUTHTOK, &pam_pass) == PAM_SUCCESS)
        && (pam_pass != NULL) ) {
         if ((pass = strdup(pam_pass)) == NULL)
              return PAM_BUF_ERR;
    } else {
        pass = strdup("");
    }

    _pam_get_user(pamh, &user);
    if (user == NULL) {
        if(pass) {
                free(pass);
        }
        return PAM_USER_UNKNOWN;
    }

    if (ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: user [%s] obtained", __func__, user);

    _pam_get_terminal(pamh, &tty);
    if (tty && !strncmp(tty, "/dev/", 5))
        tty += 5;
    if (ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: tty [%s] obtained", __func__, tty?tty:"UNKNOWN");

    _pam_get_rhost(pamh, &r_addr);
    if (ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: rhost [%s] obtained", __func__, r_addr?r_addr:"UNKNOWN");

    if (PAM_SILENT != (flags & PAM_SILENT))
        status = do_tac_connect(ctrl, NULL, user, pass, tty, r_addr, NULL, NULL, pamh);
    else
        status = PAM_AUTHTOK_ERR;

    if (status != PAM_SUCCESS && status != PAM_AUTHTOK_ERR)
        _pam_log(LOG_ERR, "no more servers to connect");

    if (ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: exit with pam status: %d", __func__, status);

    if (NULL != pass) {
        bzero(pass, strlen(pass));
        free(pass);
        pass = NULL;
    }

    return status;

}    /* pam_sm_chauthtok */
#endif


#ifdef PAM_STATIC
struct pam_module _pam_tacplus_modstruct {
    "pam_tacplus",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
#ifdef PAM_SM_PASSWORD
    pam_sm_chauthtok
#else
    NULL
#endif
};
#endif
