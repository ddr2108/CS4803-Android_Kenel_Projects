/*
   ad implementation for Linux Bluetooth stack (BlueZ).
   Copyright (C) 2002 Maxim Krasnyansky <maxk@qualcomm.com>
   Copyright (C) 2002 Marcel Holtmann <marcel@holtmann.org>

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

/*
 * ad sockets.
 */

#include <linux/module.h>

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/device.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <net/inet_common.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>
#include <net/bluetooth/l2cap.h>
#include <net/bluetooth/rfcomm.h>
#include <net/bluetooth/rfcommP.h>
#include <net/nfcP.h>
#include <net/nfc.h>

#include "ad.h"
static const struct proto_ops ad_sock_ops;
static void ad_sock_close(struct sock *sk);
static void ad_sock_kill(struct sock *sk);

#define AD_MAX_PROTO	1
static struct net_proto_family *ad_protoArray[AD_MAX_PROTO];
static DEFINE_RWLOCK(ad_proto_lock);

int ad_sock_register(int proto, struct net_proto_family *ops)
{
	int err = 0;

	if (proto < 0 || proto >= AD_MAX_PROTO)
		return -EINVAL;
	sock_register(ops);

	write_lock(&ad_proto_lock);

	if (ad_protoArray[proto])
		err = -EEXIST;
	else
		ad_protoArray[proto] = ops;

	write_unlock(&ad_proto_lock);

	return err;
}
EXPORT_SYMBOL(ad_sock_register);

int ad_sock_unregister(int proto)
{
	int err = 0;

	if (proto < 0 || proto >= AD_MAX_PROTO)
		return -EINVAL;

	write_lock(&ad_proto_lock);

	if (!ad_protoArray[proto])
		err = -ENOENT;
	else
		ad_protoArray[proto] = NULL;

	write_unlock(&ad_proto_lock);

	return err;
}
EXPORT_SYMBOL(ad_sock_unregister);


/* ---- Socket functions ---- */
static struct sock *__ad_get_sock_by_addr(u8 channel, bdaddr_t *src)
{
	struct sock *sk = NULL;
	struct hlist_node *node;

	/*sk_for_each(sk, node, &ad_sk_list.head) {
		if (ad_pi(sk)->channel == channel &&
				!bacmp(&ad_sk(sk)->src, src))
			break;
	}*/

	return node ? sk : NULL;
}

static void ad_sock_destruct(struct sock *sk)
{
	skb_queue_purge(&sk->sk_receive_queue);
	skb_queue_purge(&sk->sk_write_queue);
}

static void ad_sock_cleanup_listen(struct sock *parent)
{
	parent->sk_state  = AD_CLOSED;
	sock_set_flag(parent, SOCK_ZAPPED);
}

/* Kill socket (only if zapped and orphan)
 * Must be called on unlocked socket.
 */
static void ad_sock_kill(struct sock *sk)
{
	if (!sock_flag(sk, SOCK_ZAPPED) || sk->sk_socket)
		return;

	/* Kill poor orphan */
	sock_set_flag(sk, SOCK_DEAD);
	sock_put(sk);
}

static void __ad_sock_close(struct sock *sk)
{
	switch (sk->sk_state) {
	case 1:
		ad_sock_cleanup_listen(sk);
		break;
	case 2:
	case 3:
	case 4:
	case 5:
	default:
		sock_set_flag(sk, SOCK_ZAPPED);
		break;
	}
}

/* Close socket.
 * Must be called on unlocked socket.
 */
static void ad_sock_close(struct sock *sk)
{
	lock_sock(sk);
	__ad_sock_close(sk);
	release_sock(sk);
}

static void ad_sock_init(struct sock *sk, struct sock *parent)
{

}

static struct proto ad_proto = {
	.name		= "AD",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct ad_sock)
};

static struct sock *ad_sock_alloc(struct net *net, struct socket *sock, struct socket *sock2, struct socket *sock3, struct socket *sock4,int proto, gfp_t prio)
{

	struct sock *sk;

	sk = sk_alloc(net, PF_AD, prio, &ad_proto);
	if (!sk)
		return NULL;

	sock_init_data(sock, sk);
	ad_sk(sk)->sock2=sock2;
	ad_sk(sk)->sock3=sock3;
	ad_sk(sk)->sock4=sock4;



	//ad_sk(sk)->currentSock=sock2;		//Fix when add multiple

	sock_reset_flag(sk, SOCK_ZAPPED);

	sk->sk_protocol = proto;
	sk->sk_state    = AD_OPEN;

	return sk;
}

//Edited
static int ad_sock_create(struct net *net, struct socket *sockAll, int protocol)
{
	struct socket **sockAllArray = (struct socket**) sockAll;
	struct socket *sock =  sockAllArray[0];
	struct socket *sock2 = sockAllArray[1];
	struct socket *sock3 = sockAllArray[2];
	struct socket *sock4 = sockAllArray[3];
	struct sock *sk;

	sock->state = SS_UNCONNECTED;
	sock->ops = &ad_sock_ops;
	sk = ad_sock_alloc(net, sock, sock2, sock3, sock4, protocol, GFP_ATOMIC);
	if (!sk)
		return -ENOMEM;
	ad_sock_init(sk, NULL);
	return 0;
}

//TODO: Call corresponding fx
static int ad_sock_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock2){
		inet_bind(ad_sk(sock->sk)->currentSock, addr, addr_len);
	}else if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock3){
		rfcomm_sock_bind(ad_sk(sock->sk)->currentSock, addr, addr_len);
	}else if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock4){
		//inet_bind(ad_sk(sock->sk)->currentSock, addr, addr_len);
	}

	return 0;
}
//TODO: Call corresponding fx
static int ad_sock_connect(struct socket *sock, struct sockaddr *addr, int alen, int flags)
{
	int err = 0;
	int chosen = 0;

	ad_sk(sock->sk)->addressAll=((struct sockaddr_ad *)addr)->ad_bdaddr;
	
	chosen = ((struct sockaddr_ad *)addr)->pad[0];
	printk("chosen:%d", chosen);
	if (chosen==0){
		ad_sk(sock->sk)->currentSock=ad_sk(sock->sk)->sock3;		//Fix when add multiple
	}else if (chosen==1){
		ad_sk(sock->sk)->currentSock=ad_sk(sock->sk)->sock4;		//Fix when add multiple
	}else if (chosen==2){
		ad_sk(sock->sk)->currentSock=ad_sk(sock->sk)->sock2;		//Fix when add multiple
	}

	if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock2){
		inet_stream_connect(ad_sk(sock->sk)->currentSock, ad_sk(sock->sk)->addressAll->inet, alen, flags);
	}else if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock3){
		rfcomm_sock_connect(ad_sk(sock->sk)->currentSock, ad_sk(sock->sk)->addressAll->bt, alen, flags);
	}else if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock4){
		rawsock_connect(ad_sk(sock->sk)->currentSock, ad_sk(sock->sk)->addressAll->nfc, alen, flags);
	}

	return err;
}
//TODO: Call corresponding fx
static int ad_sock_listen(struct socket *sock, int backlog)
{
	if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock2){
		inet_listen(ad_sk(sock->sk)->currentSock, backlog);
	}else if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock3){
		rfcomm_sock_listen(ad_sk(sock->sk)->currentSock, backlog);
	}else if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock4){
		//rfcomm_sock_listen(ad_sk(sock->sk)->currentSock, backlog);
	}

	return 0;
}
//TODO: Call corresponding fx
static int ad_sock_accept(struct socket *sock, struct socket *newsock, int flags)
{
	if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock2){
		inet_accept(ad_sk(sock->sk)->currentSock, newsock, flags);
	}else if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock3){
		rfcomm_sock_accept(ad_sk(sock->sk)->currentSock, newsock, flags);
	}else if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock4){
		//inet_accept(ad_sk(sock->sk)->currentSock, newsock, flags);
	}
	return 0;
}

//TODO: Call corresponding fx
static int ad_sock_getname(struct socket *sock, struct sockaddr *addr, int *len, int peer)
{
	if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock2){
		inet_getname(ad_sk(sock->sk)->currentSock, addr, len, peer);
	}else if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock3){
		rfcomm_sock_getname(ad_sk(sock->sk)->currentSock, addr, len, peer);
	}else if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock4){
		//inet_getname(ad_sk(sock->sk)->currentSock, addr, len, peer);
	}
	return 0;
}
//TODO: Call corresponding fx
static int ad_sock_sendmsg(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t len)
{
	struct sock_iocb *si = kiocb_to_siocb(iocb);
	si->sock = ad_sk(sock->sk)->currentSock;

	if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock2){
		printk("Hello from inet sendmsg\n");
		inet_sendmsg(iocb, ad_sk(sock->sk)->currentSock, msg, len);
	}else if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock3){
		rfcomm_sock_sendmsg(iocb, ad_sk(sock->sk)->currentSock, msg, len);
	}else if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock4){
		rawsock_sendmsg(iocb, ad_sk(sock->sk)->currentSock, msg, len);
	}
	
	return 1;
}
//TODO: Call corresponding fx
static long ad_sock_data_wait(struct sock *sk, long timeo)
{
	return 1;
}
//TODO: Call corresponding fx
static int ad_sock_recvmsg(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t size, int flags)
{
	struct sock_iocb *si = kiocb_to_siocb(iocb);
	si->sock = ad_sk(sock->sk)->currentSock;

	security_socket_recvmsg(ad_sk(sock->sk)->currentSock, msg, size, flags);
	if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock2){
		printk("Hello from inet recvmsg\n");
		inet_recvmsg(iocb, ad_sk(sock->sk)->currentSock, msg, size, flags);
	}else if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock3){
		rfcomm_sock_recvmsg(iocb, ad_sk(sock->sk)->currentSock, msg, size, flags);
	}else if (ad_sk(sock->sk)->currentSock == ad_sk(sock->sk)->sock4){
		rawsock_recvmsg(iocb, ad_sk(sock->sk)->currentSock, msg, size, flags);
	}
	return 1;
}

//Looks good
static int ad_sock_setsockopt_old(struct socket *sock, int optname, char __user *optval, int optlen)
{
	struct sock *sk = sock->sk;
	int err = 0;

	//release_sock(&ad_sk(sk)->sock2);
	//release_sock(&ad_sk(sk)->sock3);
	//release_sock(&ad_sk(sk)->sock4);
	release_sock(sk);
	return err;
}

//Looks good
static int ad_sock_setsockopt(struct socket *sock, int level, int optname, char __user *optval, int optlen)
{
	struct sock *sk = sock->sk;
	//struct ad_security sec;
	int err = 0;

	//release_sock(&ad_sk(sk)->sock2);
	//release_sock(&ad_sk(sk)->sock3);
	//release_sock(&ad_sk(sk)->sock4);
	release_sock(sk);
	return err;
}

//looks good
static int ad_sock_getsockopt_old(struct socket *sock, int optname, char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	//struct sock *l2cap_sk;
	//struct ad_conninfo cinfo;
	int err = 0;

	//release_sock(&ad_sk(sk)->sock2);
	///release_sock(&ad_sk(sk)->sock3);
	//release_sock(&ad_sk(sk)->sock4);
	release_sock(sk);
	return err;
}

//Looks good
static int ad_sock_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	int err=0;
	//release_sock(&ad_sk(sk)->sock2);
	///release_sock(&ad_sk(sk)->sock3);
	//release_sock(&ad_sk(sk)->sock4);
	release_sock(sk);
	return err;
}

//Looks good
static int ad_sock_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk __maybe_unused = sock->sk;
	int err = 0;


	return err;
}

//Looks good
static int ad_sock_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	int err = 0;

	//release_sock(&ad_sk(sk)->sock2);
	///release_sock(&ad_sk(sk)->sock3);
	///release_sock(&ad_sk(sk)->sock4);
	release_sock(sk);
	return err;
}

//Looks good
static int ad_sock_release(struct socket *sock)
{
	int err=0;

	return err;
}


//static CLASS_ATTR(ad, S_IRUGO, ad_sock_sysfs_show, NULL);

static const struct proto_ops ad_sock_ops = {
	.family		= PF_AD,
	.owner		= THIS_MODULE,
	.release	= ad_sock_release,
	.bind		= ad_sock_bind,
	.connect	= ad_sock_connect,
	.listen		= ad_sock_listen,
	.accept		= ad_sock_accept,
	.getname	= ad_sock_getname,
	.sendmsg	= ad_sock_sendmsg,
	.recvmsg	= ad_sock_recvmsg,
	.shutdown	= ad_sock_shutdown,
	.setsockopt	= ad_sock_setsockopt,
	.getsockopt	= ad_sock_getsockopt,
	.ioctl		= ad_sock_ioctl,
	.socketpair	= sock_no_socketpair,
	.mmap		= sock_no_mmap
};

static struct net_proto_family ad_sock_family_ops = {
	.family		= PF_AD,
	.owner		= THIS_MODULE,
	.create		= ad_sock_create
};

int __init ad_init_sockets(void)
{
	int err;

	err = proto_register(&ad_proto, 1);

	if (err < 0)
		return err;

	err = ad_sock_register(0, &ad_sock_family_ops);
	if (err < 0)
		goto error;

	return 0;

error:
	proto_unregister(&ad_proto);
	return err;
}

void __exit ad_cleanup_sockets(void)
{
	//class_remove_file(bt_class, &class_attr_ad);

	bt_sock_unregister(0);

	proto_unregister(&ad_proto);
}
fs_initcall(ad_init_sockets);
MODULE_ALIAS_NETPROTO(PF_AD);
