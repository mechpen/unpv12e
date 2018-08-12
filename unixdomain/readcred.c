#include	"unp.h"
#include	<sys/param.h>

ssize_t
read_cred(int fd, void *ptr, size_t nbytes, struct ucred *ucredptr)
{
	struct msghdr	msg;
	struct iovec	iov[1];
	ssize_t			n;

	union {
	  struct cmsghdr	cm;
	  char				control[CMSG_SPACE(sizeof(struct ucred))];
	} control_un;
	struct cmsghdr	*cmptr;

	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof(control_un.control);

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov[0].iov_base = ptr;
	iov[0].iov_len = nbytes;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	if ( (n = recvmsg(fd, &msg, 0)) < 0)
		return(n);

/* *INDENT-OFF* */
	if (ucredptr) {
		if (msg.msg_controllen > sizeof(struct cmsghdr)) {
			cmptr = CMSG_FIRSTHDR(&msg);

			if (cmptr->cmsg_len != CMSG_LEN(sizeof(struct ucred)))
				err_quit("control length = %d", cmptr->cmsg_len);
			if (cmptr->cmsg_level != SOL_SOCKET)
				err_quit("control level != SOL_SOCKET");
			if (cmptr->cmsg_type != SCM_CREDENTIALS)
				err_quit("control type != SCM_CREDENTIALS");
			memcpy(ucredptr, CMSG_DATA(cmptr), sizeof(struct ucred));
		} else
			bzero(ucredptr, sizeof(struct ucred)); /* none returned */
	}
/* *INDENT-ON* */

	return(n);
}
