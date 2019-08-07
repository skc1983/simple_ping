#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <errno.h>

#define PACKET_SIZE 4096
#define MAX_NO_PACKETS 1

char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];
int sockfd, datalen = 56;
int nsend = 0, nreceived = 0;

pid_t pid;

struct sockaddr_in dest_addr;
struct sockaddr_in from;

void statistics()
{
	printf("\n--------------------PING statistics-------------------\n");
	printf("%d packets transmitted, %d received , %%%d lost\n", nsend, nreceived, (nsend - nreceived) / nsend * 100);
}

unsigned short cal_chksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return answer;
}

int pack(int pack_no)
{
	int i, packsize;
	struct icmp *icmp;
	
	icmp = (struct icmp *)sendpacket;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_seq = pack_no;
	icmp->icmp_id = pid;
	packsize = 8 + datalen;
	icmp->icmp_cksum = cal_chksum((unsigned short *)icmp, packsize);

	return packsize;
}

void send_packet()
{
	int packetsize;

	packetsize = pack(nsend);
	if (sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
	{
	perror("sendto error\n");
	exit(1);
	}
}


int unpack(char *buf, int len)
{
	int i, iphdrlen;
	struct ip *ip;
	struct icmp *icmp;

	ip = (struct ip *)buf;
	iphdrlen = ip->ip_hl << 2;
	icmp = (struct icmp *)(buf + iphdrlen);
	len -= iphdrlen;

	printf("%d byte from %s: icmp_seq=%u ttl=%d\n", len, inet_ntoa(from.sin_addr), icmp->icmp_seq, ip->ip_ttl);
	return 0;
}

void recv_packet()
{
	int n, fromlen;
	extern int errno;
	fromlen = sizeof(from);

	if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, (socklen_t *)&fromlen)) < 0)
	{
		perror("failed to receive\n");
		exit(1);
	}
	if (unpack(recvpacket, n) == -1)
		exit(1);
}

int main(int argc, char *argv[])
{
	struct hostent *host;
	struct protoent *protocol;

	unsigned long inaddr;
	int size = 50 * 1024;

	if (argc < 2)
	{
		perror("usage:%s hostname/IP address\n", argv[0]);
		exit(1);
	}
	if ((protocol = getprotobyname("icmp")) == NULL)
	{
		perror("getprotobyname\n");
		exit(1);
	}

	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
	{
		perror("socket error\n");
		exit(1);
  	}

	bzero(&dest_addr, sizeof(dest_addr));
	if(argv[1]==NULL)
	{
		perror("gethostbyname error\n");
		exit(1);
	}
	dest_addr.sin_addr.s_addr = inet_addr(argv[1]);
	pid = getpid();
	printf("\nPING %s(%s): %d bytes data in ICMP packets.\n", argv[1], inet_ntoa(dest_addr.sin_addr), datalen);
	send_packet();
	++nsend;
	recv_packet();
	++nreceived;
	statistics();
	close(sockfd);

	return 0;
}
