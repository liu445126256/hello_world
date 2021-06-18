#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <memory.h>
#include <sys/ioctl.h>	
#include <stdlib.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h> 
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <errno.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <string.h>
#include <inttypes.h>
#include <sys/time.h>

static int nb_pkts = 1000;
static const char* fpga_if_name = "ens6";


static unsigned long long rdtsc(void)
{
    unsigned int low, high;
    asm volatile ("rdtsc" : "=a"(low), "=d"(high) : );
    return ((unsigned long long)high<<32) + (unsigned long long)low;
}

unsigned long long getCpuCyclesMhz()
{
    FILE *fp;
    char cycleStr[128];
    memset(cycleStr, 0, 128);
    fp = popen("cat /proc/cpuinfo | grep MHz | uniq |sed -e 's/.*:[^0-9]//'","r");
    if (fp<0) {
        printf("Can't read CPU cycle info !!!\n");
        exit(1);
    }
    fgets(cycleStr, 127, fp);
    fclose(fp);
    unsigned long long cycle = (unsigned long long)atof(cycleStr);
    printf("CPU cycle : %llu MHz\n", cycle);
    return cycle;
}



/* Per-port statistics struct */
struct pingpong_port_statistics
{
    uint64_t tx;
    uint64_t rx;
    uint64_t *rtt;
    uint64_t dropped;
} __rte_cache_aligned;

struct pingpong_port_statistics port_statistics;

static inline void
initlize_port_statistics(void)
{
    port_statistics.tx = 0;
    port_statistics.rx = 0;
    port_statistics.rtt = malloc(sizeof(uint64_t) * nb_pkts);
    port_statistics.dropped = 0;
}

static inline void
destroy_port_statistics(void)
{
    free(port_statistics.rtt);
}

static inline void
print_port_statistics(void)
{
    uint64_t i, min_rtt, max_rtt, sum_rtt, avg_rtt;
    printf("============ statistics ==========\n");
    printf("tx %" PRIu64 " ping packets\n", port_statistics.tx);
    printf("rx %" PRIu64 " pong packets\n", port_statistics.rx);
    printf("dopped %" PRIu64 " packets\n", port_statistics.dropped);

    min_rtt = 999999999;
    max_rtt = 0;
    sum_rtt = 0;
    avg_rtt = 0;
    for (i = 0; i < nb_pkts; i++)
    {
        sum_rtt += port_statistics.rtt[i];
        if (port_statistics.rtt[i] < min_rtt)
            min_rtt = port_statistics.rtt[i];
        if (port_statistics.rtt[i] > max_rtt)
            max_rtt = port_statistics.rtt[i];
    }
    avg_rtt = sum_rtt / nb_pkts;
    printf( "min rtt: %" PRIu64 " us\n", min_rtt);
    printf( "max rtt: %" PRIu64 " us\n", max_rtt);
    printf( "average rtt: %" PRIu64 " us\n", avg_rtt);
    printf( "=================================\n");
}





int main(int argc, char **argv) {
	//1.创建通信用的原始套接字
	int n;
	char buffer[1024];
	int sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	uint8_t sendbuffer[1024]; 	

	uint64_t ping_tsc, pong_tsc, diff_tsc, rtt_us;
	uint64_t sys_hz = getCpuCyclesMhz()*1000000;

	//2.根据各种协议首部格式构建发送数据报
	unsigned char send_msg[1024] = {
		//--------------组MAC--------14------
		0x00, 0x0c, 0x29, 0x56, 0xd5, 0xc7, //dst_mac: E8-6A-64-17-CB-5C目的地址
		0x00, 0x0c, 0x29, 0x0d, 0xe8, 0x83, //src_mac: 8c:ec:4b:73:79:b5源mac地址
		0x08, 0x00,                         //类型：0x0800 IP协议
	/*	//--------------组IP---------20------
		0x45, 0x00, 0x00, 0x00,             //版本号：4, 首部长度：20字节, TOS:0, --总长度--：
		0x00, 0x00, 0x00, 0x00,				//16位标识、3位标志、13位片偏移都设置0
		0x80, 17,   0x00, 0x00,				//TTL：128、协议：UDP（17）、16位首部校验和
		10,  221,   20,  11,				//src_ip: 10.221.20.11
		10,  221,   20,  10,				//dst_ip: 10.221.20.10
		//--------------组UDP--------8+78=86------
		0x1f, 0x90, 0x1f, 0x90,             //src_port:0x1f90(8080), dst_port:0x1f90(8080)
		0x00, 0x00, 0x00, 0x00,               //#--16位UDP长度--30个字节、#16位校验和*/
	};	

	int len = sprintf(send_msg+14, "%s", "FPGALatencyTest");
	struct sockaddr_ll sll;					//原始套接字地址结构
	struct ifreq req;					//网络接口地址	
	strncpy(req.ifr_name, fpga_if_name, IFNAMSIZ);			//指定网卡名称
	if(-1 == ioctl(sock_raw_fd, SIOCGIFINDEX, &req))	//获取网络接口
	{
		perror("ioctl");
		close(sock_raw_fd);
		exit(-1);
	}	
	/*将网络接口赋值给原始套接字地址结构*/
	bzero(&sll, sizeof(sll));
	sll.sll_ifindex = req.ifr_ifindex;

	for (int i = 0; i < nb_pkts; i++) {

		ping_tsc = rdtsc();
		port_statistics.tx += 1;

		len = sendto(sock_raw_fd, send_msg, 14+len, 0 , (struct sockaddr *)&sll, sizeof(sll));
		if(len == -1)
		{
			perror("sendto");
		}	
		
                socklen_t addr_length = sizeof(struct sockaddr_ll);
		n = recvfrom(sock_raw_fd, buffer,1024,0, (struct sockaddr *)&sll, &addr_length);

		pong_tsc = rdtsc();
		diff_tsc = pong_tsc - ping_tsc;
        rtt_us = diff_tsc * 1000000 / sys_hz;
        port_statistics.rtt[port_statistics.rx] = rtt_us;
        port_statistics.rx += 1;

		if (n < 14) {
			perror("Recv data length error\n");
		}
		/*
		int num = n-14;
		memcpy(sendbuffer, buffer, n);
		char data[1024];
		data[24]='\0';
        memcpy(data,sendbuffer+14,num);
		printf("%s\n",data);
		*/
	}
	print_port_statistics();

	return 0;

}





/*FPGA version*/
static const char* fpga_if_name = "ens6";
static void
send_and_recv_loop(void)
{
    unsigned lcore_id;
    uint64_t ping_tsc, pong_tsc, diff_tsc, rtt_us;
    unsigned i, nb_rx=0, nb_tx=0;
    const uint64_t tsc_hz = rte_get_tsc_hz();
    uint64_t pkt_idx = 0;
    bool received_pong = false;
    lcore_id = rte_lcore_id();


    // init FPGA 
    //1.创建通信用的原始套接字
    int n;
    char buffer[1024];
    int sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw_fd < 0)
    {
            perror("socket");
            exit(1);
    }
    uint8_t sendbuffer[1024];   

    //2.根据各种协议首部格式构建发送数据报
    unsigned char send_msg[1024] = {
        //--------------组MAC--------14------
        0x00, 0x0c, 0x29, 0x56, 0xd5, 0xc7, //dst_mac: E8-6A-64-17-CB-5C目的地址
        0x00, 0x0c, 0x29, 0x0d, 0xe8, 0x83, //src_mac: 8c:ec:4b:73:79:b5源mac地址
        0x08, 0x00,                         //类型：0x0800 IP协议
    /*  //--------------组IP---------20------
        0x45, 0x00, 0x00, 0x00,             //版本号：4, 首部长度：20字节, TOS:0, --总长度--：
        0x00, 0x00, 0x00, 0x00,             //16位标识、3位标志、13位片偏移都设置0
        0x80, 17,   0x00, 0x00,             //TTL：128、协议：UDP（17）、16位首部校验和
        10,  221,   20,  11,                //src_ip: 10.221.20.11
        10,  221,   20,  10,                //dst_ip: 10.221.20.10
        //--------------组UDP--------8+78=86------
        0x1f, 0x90, 0x1f, 0x90,             //src_port:0x1f90(8080), dst_port:0x1f90(8080)
        0x00, 0x00, 0x00, 0x00,               //#--16位UDP长度--30个字节、#16位校验和*/
    };  

    int len = sprintf(send_msg+14, "%s", "FPGALatencyTest");
    struct sockaddr_ll sll;                 //原始套接字地址结构
    struct ifreq req;                   //网络接口地址    
    strncpy(req.ifr_name, fpga_if_name, IFNAMSIZ);          //指定网卡名称
    if(-1 == ioctl(sock_raw_fd, SIOCGIFINDEX, &req))    //获取网络接口
    {
        perror("ioctl");
        close(sock_raw_fd);
        exit(-1);
    }   
    /*将网络接口赋值给原始套接字地址结构*/
    bzero(&sll, sizeof(sll));
    sll.sll_ifindex = req.ifr_ifindex;



    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_PINGPONG, "FPGA: entering send/recv loop on lcore %u\n", lcore_id);
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_PINGPONG, "FPGA: start to ping\n");
    for (pkt_idx = 0; pkt_idx < nb_pkts && !force_quit; pkt_idx++)
    {
        /* start timing */
        ping_tsc = rte_rdtsc();
        

        port_statistics.tx += 1;

        len = sendto(sock_raw_fd, send_msg, 14+len, 0 , (struct sockaddr *)&sll, sizeof(sll));
        if(len == -1)
        {
            perror("sendto");
        }   
        
        socklen_t addr_length = sizeof(struct sockaddr_ll);
        n = recvfrom(sock_raw_fd, buffer,1024,0, (struct sockaddr *)&sll, &addr_length);

        pong_tsc = rte_rdtsc();
        diff_tsc = pong_tsc - ping_tsc;
        rtt_us = diff_tsc * US_PER_S / tsc_hz;
        port_statistics.rtt[port_statistics.rx] = rtt_us;
        port_statistics.rx += 1;

        if (n < 14) {
            perror("Recv data length error\n");
        }
        /*
        int num = n-14;
        memcpy(sendbuffer, buffer, n);
        char data[1024];
        data[24]='\0';
        memcpy(data,sendbuffer+14,num);
        printf("%s\n",data);
        */
        received_pong = true;

    }
    /* print port statistics when ping main loop finishes */
    print_port_statistics();
}