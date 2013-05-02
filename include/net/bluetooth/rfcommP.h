int rfcomm_sock_release(struct socket *sock);
int rfcomm_sock_bind(struct socket *sock, struct sockaddr *addr, int addr_len);
int rfcomm_sock_listen(struct socket *sock, int backlog);
int rfcomm_sock_accept(struct socket *sock, struct socket *newsock, int flags);
int rfcomm_sock_getname(struct socket *sock, struct sockaddr *addr, int *len, int peer);
int rfcomm_sock_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len);
int rfcomm_sock_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t size, int flags);
int rfcomm_sock_connect(struct socket *sock, struct sockaddr *addr, int alen, int flags);
