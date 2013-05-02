/* 
   BlueZ - Bluetooth protocol stack for Linux
   Copyright (C) 2000-2001 Qualcomm Incorporated

   Written 2000,2001 by Maxim Krasnyansky <maxk@qualcomm.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation;

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
   IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
   CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

   ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
   COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
   SOFTWARE IS DISCLAIMED.
*/

#include <asm/types.h>
#include <asm/byteorder.h>
#include <linux/list.h>
#include <linux/poll.h>
#include <net/sock.h>

/* Connection and socket states */
enum {
	AD_CONNECTED = 1, /* Equal to TCP_ESTABLISHED to make net code happy */
	AD_OPEN,
	AD_BOUND,
	AD_LISTEN,
	AD_CONNECT,
	AD_CONNECT2,
	AD_CONFIG,
	AD_DISCONN,
	AD_CLOSED
};

/* Common socket structures and functions */

#define ad_sk(__sk) ((struct ad_sock *) __sk)

struct ad_sock {
	struct sock sk;
	struct socket* sock2;
	struct socket* sock3;
	struct socket* sock4;
	struct socket* currentSock;
	struct totaldaddr_t*  addressAll;
	struct list_head accept_q;
	struct sock *parent;
	u32 defer_setup;
};

struct ad_sock_list {
	struct hlist_head head;
	rwlock_t          lock;
};

int  ad_sock_register(int proto, struct net_proto_family *ops);
int  ad_sock_unregister(int proto);

extern struct class *bt_class;

