int rawsock_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len);
int rawsock_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags);
int rawsock_release(struct socket *sock);
int rawsock_connect(struct socket *sock, struct sockaddr *_addr, int len, int flags);
