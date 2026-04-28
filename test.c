
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include "ipheader.h"
#include "tcpheader.h"

char *target_domain = NULL;
	
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
    unsigned char *packet_data;
	unsigned char *domain_start;
	uint32_t id = ntohl(nfq_get_msg_packet_hdr(nfa)->packet_id);
    int len = nfq_get_payload(nfa, &packet_data);

    if (len >= 0) {

        ipheader *iph = (ipheader *)packet_data;
        int ip_header_len = (iph->version_ihl & 0x0F) * 4;
		printf("IP Header Length: %d bytes\n", ip_header_len);

		tcpheader *tcph = (tcpheader*)(packet_data + ip_header_len);
		int tcp_header_len = ((tcph->offset_reserved & 0xF0) >> 4) * 4;
		printf("TCP Header Length: %d bytes\n", tcp_header_len);

		unsigned char *http_payload = packet_data + ip_header_len + tcp_header_len;
		unsigned int http_len = len - (ip_header_len + tcp_header_len);
		
		if(http_len > 0){
			
			http_payload[http_len] = '\0';
			char *host_ptr = strstr((char*)http_payload, "Host: ");
			if(host_ptr != NULL){
				
				domain_start = (unsigned char*)(host_ptr + 6);
				unsigned int target_len = strlen(target_domain);
				if (strncmp((char *)domain_start, target_domain, target_len) == 0) {
					
					printf("차단 대상 발견: %s\n", target_domain);
					return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
				}
			}
		}


    }

    // 일단은 모든 패킷을 허용(ACCEPT)으로 둡니다.
    
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h; //커널과의 통신을 위해 딱 한번 필요
	struct nfq_q_handle *qh; //우리가 실제로 감시할 특정 번호의 큐에 대한 핸들
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

	if (argc != 2) {
        fprintf(stderr, "Usage: netfilter-test <target_domain>\n");
        exit(EXIT_FAILURE);
    }

	target_domain = argv[1];

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) { //rv에는 실제로 읽어온 데이터의 바이트수 저장됨.
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
