#include	"unp.h"
#include	<sys/param.h>

ssize_t	 read_cred(int, void *, size_t, struct ucred *);

void
str_echo(int sockfd)
{
	ssize_t			n;
	const int		on = 1;
	char			line[MAXLINE];
	struct ucred		cred;

	Setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));

	if ( (n = read_cred(sockfd, NULL, 0, &cred)) < 0)
		err_sys("read_cred error");
	else {
		printf("pid = %d\n", cred.pid);
		printf("uid = %d\n", cred.uid);
		printf("gid = %d\n", cred.gid);
	}

	for ( ; ; ) {
		if ( (n = Readline(sockfd, line, MAXLINE)) == 0)
			return;		/* connection closed by other end */

		Writen(sockfd, line, n);
	}
}
