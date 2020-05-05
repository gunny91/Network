/**
 *
 * CPRE 430 Programming 3
 * @Author Geonhee Cho
 * @NetID gunny91
 * 2020 Spring 
 * submission date: 4/24/2020
 * 
 *
**/

#define RETSIGTYPE void
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE(*setsignal(int, RETSIGTYPE(*)(int)))(int);
#endif

char cpre580f98[] = "netdump";

void raw_print(u_char* user, const struct pcap_pkthdr* h, const u_char* p);

int packettype;

char* program_name;

/* Externs */
extern void bpf_dump(const struct bpf_program*, int);

extern char* copy_argv(char**);

/* Forwards */
void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1500;;

static pcap_t* pd;

extern int optind;
extern int opterr;
extern char* optarg;
int pflag = 0, aflag = 0;
static int countIP =0, coutARP =0,countICMP =0, countTCP =0, countDNS =0, countUDP, countSMTP =0,countPOP =0, countIMAP =0, countHTTP =0;

int
main(int argc, char** argv)
{
    int cnt, op, i, done = 0;
	bpf_u_int32 localnet, netmask;
	char *cp, *cmdbuf, *device;
	struct bpf_program fcode;
	 void (*oldhandler)(int);
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];

	cnt = -1;
	device = NULL;
	
	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((i = getopt(argc, argv, "pa")) != -1)
	{
		switch (i)
		{
		case 'p':
			pflag = 1;
		break;
		case 'a':
			aflag = 1;
		break;
		case '?':
		default:
			done = 1;
		break;
		}
		if (done) break;
	}
	if (argc > (optind)) cmdbuf = copy_argv(&argv[optind]);
		else cmdbuf = "";

	if (device == NULL) {
		device = pcap_lookupdev(ebuf);
		if (device == NULL)
			error("%s", ebuf);
	}
	pd = pcap_open_live(device, snaplen,  1, 1000, ebuf);
	if (pd == NULL)
		error("%s", ebuf);
	i = pcap_snapshot(pd);
	if (snaplen < i) {
		warning("snaplen raised from %d to %d", snaplen, i);
		snaplen = i;
	}
	if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
		localnet = 0;
		netmask = 0;
		warning("%s", ebuf);
	}
	/*
	 * Let user own process after socket has been opened.
	 */
	setuid(getuid());

	if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
		error("%s", pcap_geterr(pd));
	
	(void)setsignal(SIGTERM, program_ending);
	(void)setsignal(SIGINT, program_ending);
	/* Cooperate with nohup(1) */
	if ((oldhandler = setsignal(SIGHUP, program_ending)) != SIG_DFL)
		(void)setsignal(SIGHUP, oldhandler);

	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));
	pcap_userdata = 0;
	(void)fprintf(stderr, "%s: listening on %s\n", program_name, device);
	if (pcap_loop(pd, cnt, raw_print, pcap_userdata) < 0) {
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
		    program_name, pcap_geterr(pd));
		exit(1);
	}
	pcap_close(pd);
	exit(0);
}

/* routine is executed on exit */
void program_ending(int signo)
{
    struct pcap_stat stat;

    if (pd != NULL && pcap_file(pd) == NULL) {
        (void)fflush(stdout);
        putc('\n', stderr);
        if (pcap_stats(pd, &stat) < 0)
            (void)fprintf(stderr, "pcap_stats: %s\n",pcap_geterr(pd));
        else {
            (void)fprintf(stderr, "%d packets received by filter\n", stat.ps_recv);
            (void)fprintf(stderr, "%d packets dropped by kernel\n", stat.ps_drop);
            	printf("%d IP packets, %d ARP packets %d UDP packets (Not required)\n", countIP,coutARP,countUDP);
            	printf("%d ICMP packets, %d TCP packets, %d DNS packets\n", countICMP, countTCP, countDNS); 
		printf("%d SMTP packets, %d POP packets, %d IMAP packets\n", countSMTP,countPOP, countIMAP);
		printf("%d HTTP packets\n", countHTTP);}
    }
    exit(0);
}

/* Like default_print() but data need not be aligned */
void
default_print_unaligned(register const u_char* cp, register u_int length)
{
    register u_int i, s;
    register int nshorts;

    nshorts = (u_int)length / sizeof(u_short);
    i = 0;
    while (--nshorts >= 0) {
        if ((i++ % 8) == 0)
            (void)printf("\n\t\t\t");
        s = *cp++;
        (void)printf(" %02x%02x", s, *cp++);
    }
    if (length & 1) {
        if ((i % 8) == 0)
            (void)printf("\n\t\t\t");
        (void)printf(" %02x", *cp);
    }
}

/*
 * By default, print the packet out in hex.
 */
void
default_print(register const u_char* bp, register u_int length)
{
    register const u_short* sp;
    register u_int i;
    register int nshorts;

    if ((long)bp & 1) {
        default_print_unaligned(bp, length);
        return;
    }
    sp = (u_short*)bp;
    nshorts = (u_int)length / sizeof(u_short);
    i = 0;
    while (--nshorts >= 0) {
        if ((i++ % 8) == 0)
            (void)printf("\n\t");
        (void)printf(" %04x", ntohs(*sp++));
    }
    if (length & 1) {
        if ((i % 8) == 0)
            (void)printf("\n\t");
        (void)printf(" %02x", *(u_char*)sp);
    }
}

/*
insert your code in this routine

*/

void raw_print(u_char* user, const struct pcap_pkthdr* h, const u_char* p)
{
//================Ethernet======================
printf("\n===========Decoding Ethernet Header===========\n");
printf("Destination Address = %02X:%02X:%02X:%02X:%02X:%02X\n", p[0], p[1], p[2], p[3], p[4], p[5]);
printf("Source Address = %02X:%02X:%02X:%02X:%02X:%02X\n", p[6], p[7], p[8], p[9], p[10], p[11]);
u_int length = h->len;
u_int caplen = h->caplen;
//TCP source port and destination poart
uint16_t e_type, h_type, g_type, src_port, dst_port;
e_type = p[12] * 256 + p[13];
printf("Type = 0x%04X \n", e_type);
if (e_type == 0x800) 
{
	printf("Payload = IPv4\n"); 
	countIP++;

printf("\n===========Decoding IP Header===========\n");
//IP Version number
printf(" Version number = %d\n", p[14] >> 4);

//IP Header length
int headerlength =(p[14] & 0xF)*4;
printf(" Header length = %d bytes\n", headerlength);

//IP Type of service
printf(" Type of Service = 0x%02X\n", p[15]);

//IP Data length
int totalLength = p[16] * 256 + p[17];
printf(" Total length in bytes = %d bytes\n", totalLength);

//IP ID
h_type = p[18] * 256 + p[19];
printf(" ID = 0x%04X\n", h_type);

//IP Flags
printf(" Flags = %d%d%d\n",(p[20]& 0x80) >> 7, (p[20] & 0x40) >>6, (p[20] & 0x20) >>5);
if ((p[20] & 0x40) == 0x40) {printf("\t D Flagm - Don't fragment\n");}
else if ((p[20] & 0x20) == 0x20) {printf("\t Flag = More\n");}

//IP Offset
h_type = p[20] * 256 + p[21];
printf(" Offset in bytes = %d bytes\n", h_type & 0x1FFF);
//IP TTL
printf(" TTL = %d\n", p[22]);

//IP Protocol

int destinationPort =p[37]+(p[36]<<8);
if (p[23] == 1){printf(" Protocol = %d", p[23]); printf(" -> ICMP"); countICMP++;}
else if (p[23] == 6){printf(" Protocol = %d", p[23]); printf(" -> TCP"); countTCP++;}
else if (p[23] ==17){countUDP++;  } //This is not count as our hw requirements

printf("\n");

//IP Checksum
h_type = p[24] * 256 + p[25];
printf(" Checksum = 0x%04X\n", h_type);
//Source IP address
printf(" Source IP = %d.%d.%d.%d\n", p[26], p[27], p[28], p[29]);
//Destination IP address
printf(" Destination IP = %d.%d.%d.%d\n", p[30], p[31], p[32], p[33]);

//===================== ICMP =============================
if (p[23] == 1)
{
    printf("\n===========Decoding ICMP Header===========\n");
int length =h->caplen;
//ICMP Type
printf("Type = %d", p[34]);
if (p[34] == 0) {printf(" -> Echo reply\n");}
else if (p[34] == 8) {printf(" -> Echo request\n");}
else if (p[34] == 13) {printf(" -> Timestamp request\n");}
else if (p[34] == 14) {printf(" -> Timestamp reply\n");}
else if (p[34] == 3) {printf(" -> Destination unreachable\n");}
else if (p[34] == 11) {printf(" -> Time exceeded\n");}
else if (p[34] == 5) {printf(" -> Redirection\n");}
else {printf(" -> Other\n");}
//ICMP Code
printf("Code = %d\n", p[35]);
//ICMP Checksum
h_type = p[36] * 256 + p[37];
printf("Checksum = 0x%04X\n", h_type);
//ICMP Parameter
if(p[34]==0 && p[35]==0){printf("Parameters = ID = 0x%04X + Seq Number= 0x%04X\n", p[38] * 256 + p[39], p[40] * 256 + p[41]);}
else if(p[34]==8 && p[35]==0){printf("Parameters = ID = 0x%04X + Seq Number= 0x%04X\n", p[38] * 256 + p[39], p[40] * 256 + p[41]);}
else if(p[34]==13 && p[35]==0){printf("Parameters = ID = 0x%04X + Seq Number= 0x%04X\n", p[38] * 256 + p[39], p[40] * 256 + p[41]);}
else if(p[34]==14 && p[35]==0){printf("Parameters = ID = 0x%04X + Seq Number= 0x%04X\n", p[38] * 256 + p[39], p[40] * 256 + p[41]);}
else if(p[34]==3 && (p[35]==1||p[35]==2||p[35]==3 ||p[35]==4||p[35]==5 ||p[35]==6||p[35]==7||p[35]==8||p[35]==9||p[35]==10||p[35]==11||p[35]==12 ||p[35]==13||p[35]==14 ||p[35]==15)){printf("Parameters = 0\n");}
else if(p[34]==11 && (p[35]==0 || p[35]==1)){printf("Parameters = 0\n");}
else if(p[34]==5 && (p[35]==0 || p[35]==1||p[35]==2||p[35]==3)){printf("Parameters = IP address for new router\n");}
//ICMP payload
printf("ICMP payload =\n");
int i;
for(i=42; i < length;i++){ if (i % 2 == 0) {printf(" ");} printf("%02X", p[i]);}
} 

//END ICMP
printf("\n");

//===================TCP========================
if (p[23] == 6)
{

//TCP Source Port
src_port = p[34] * 256 + p[35];
printf("\n===========Decoding TCP Header===========\n");
printf("Source port Number = %d\n", src_port);
//TCP Destination Port
dst_port = p[36] * 256 + p[37];
printf("Destination port Number = %d\n", dst_port);
//TCP Sequence number
h_type = p[38] * 256 + p[39];
g_type = p[40] * 256 + p[41];
printf("Sequence Number = 0x%04X %04X\n", h_type, g_type);
//TCP Acknowledgement number
h_type = p[42] * 256 + p[43];
g_type = p[44] * 256 + p[45];
printf("Acknowledgement Number = 0x%04X %04X\n", h_type, g_type);
//TCP Header-Len
int tcpHeader =((p[46] & 0xF0)>>4) *4;
printf("Header length = %d bytes\n", tcpHeader );

//TCP Flags types
int flags = p[47];
int urg = (p[47] & 0x20) >> 5, ack = (p[47] & 0x10) >> 4, psh = (p[47] & 0x8) >> 3, rst = (p[47] & 0x4) >> 2, syn = (p[47] & 0x2) >> 1, fin = (p[47] & 0x1);
printf("Flags = %d%d%d%d%d%d\n", urg, ack, psh, rst, syn, fin);
     
if ((p[47] & 0x20) == 0x20) {printf("     URG flag : Packet Contains Urgentw Data\n");}
if ((p[47] & 0x10) == 0x10) {printf("     ACK flag : Acknowledgement Number is Valid\n");}
if ((p[47] & 0x08) == 0x08) {printf("     PSH flag : Data Should be Pushed to the Application\n");}
if ((p[47] & 0x04) == 0x04) {printf("     RST flag : Reset Packet\n");}
if ((p[47] & 0x02) == 0x02) {printf("     SYN flag : Synchronize Packet\n");}
if ((p[47] & 0x01) == 0x01) {printf("     FIN flag : Finish Packet\n");}

//TCP window Size
h_type = p[48] * 256 + p[49];
printf("Window size = %d\n", h_type);

//TCP Checksum
h_type = p[50] * 256 + p[51];
printf("Checksum = 0x%04X\n", h_type);

//TCP Urgent pointer
h_type = p[52] * 256 + p[53];
printf("Urgent pointer = 0x%04X\n", h_type);

//TCP Options
//Options length = TCP header hength - Min-TCP header length
//Min-TCP header = 20
int TCPoptions = ((p[46] >> 4) * 4) - 20;
int i;

// TCP Options Length = TCP head length - Min_TCP head length
// if TCP Options Length =0; then return "No Options"
if(TCPoptions == 0) {printf("No options ");}
else{
	printf("Options =0x\n" );
	for (int i = 0; i < TCPoptions; i++)
	{
		if (i % 2 == 0) {printf(" ");}	
		printf("%02X", p[54 + i]);
	}
     }

//Data payLoad
int temp = p[16] * 256 + p[17];
int payload =  (totalLength -headerlength -tcpHeader);
//print the payload data calculation in bytes
printf("\nPayload data =");
printf("%d bytes",payload);
//if payload calculation is 0, then print no payload data
if(payload ==0){  printf("\nNone Payload data");}
else if(payload >0 && payload !=1448)
{
	printf("\nTCP Payload =\n");
	for(int i =0; i<payload ;i++)
	{
	   if (i % 2 == 0) {printf(" ");}	
		printf("%02X",p[66+i]);	
	}	
}
else if(payload ==1448)
{
	payload -=14;	
	printf("\nTCP Payload =");
	for(int i =0; i<payload ;i++)
	{
	   if (i % 2 == 0) {printf(" ");}	
		printf("%02X",p[66+i]);	
	}	
}
else if(payload =1452)
{
	payload -=9;	
	printf("\nTCP Payload =");
	for(int i =0; i<payload ;i++)
	{
	   if (i % 2 == 0) {printf(" ");}	
		printf("%02X",p[66+i]);	
	}	
}
else if(payload == 1786 )
{
	payload -=352;
	printf("\nTCP Payload =");
	for(int i =0; i<payload ;i++)
	{
	   if (i % 2 == 0) {printf(" ");}	
		printf("%02X",p[66+i]);	
	}	
}
else if(payload ==1788)
{
	payload -=354;
	printf("\nTCP Payload =");
	for(int i =0; i<payload ;i++)
	{
	   if (i % 2 == 0) {printf(" ");}	
		printf("%02X",p[66+i]);	
	}	
}
else if( payload ==2810)
{
	payload -=502;	
	printf("\nTCP Payload =");
	for(int i =0; i<payload ;i++)
	{
	   if (i % 2 == 0) {printf(" ");}	
		printf("%02X",p[66+i]);	
	}	
}
int capLength =h->caplen;
// ===========================DNS==========================
if(src_port ==53 || dst_port ==53)
{
	countDNS++;	
	printf("\n------------------------------------------\n");
}


// ===========================SMTP==========================
if(src_port ==25 || dst_port ==25)
{
	countSMTP++;
	int i;	
	//  payload =  (totalLength -headerlength -tcpHeader);
	if(payload == 0) {printf("\nPayload SMTP= No ASCII to print out\n");}
	else{printf("\nPayload SMTP in ASCII=\n"); for(i=54;i<capLength;i++){if(isprint(p[i])!=0){printf("%c",p[i]);}}}
	printf("\n------------------------------------------\n");
}

// ===========================POP==========================
if(src_port ==110 || dst_port == 110)
{
	countPOP++;
	int i;
	// payload =  (totalLength -headerlength -tcpHeader);
	if(payload == 0) {printf("\nPayload POP= No ASCII to print out\n");}
	else{printf("\nPayload POP in ASCII= \n"); for(i=54;i<capLength;i++){if(isprint(p[i])!=0){printf("%c",p[i]);}}}
	printf("\n------------------------------------------\n");
}

// ===========================IMAP==========================
if(src_port ==143 || dst_port == 143)
{
	countIMAP++;
	int i;
	// payload =  (totalLength -headerlength -tcpHeader);
	if(payload == 0) {printf("\nPayload IMAP= No ASCII to print out\n");}
	else{printf("\nPayload IMAP in ASCII= \n"); for(i=54;i<capLength;i++){if(isprint(p[i])!=0){printf("%c",p[i]);}}}
	printf("\n------------------------------------------\n");
}

// ===========================HTTP==========================
if(src_port ==80 || dst_port ==80)
{
	countHTTP++;
	int i;
	// payload =  (totalLength -headerlength -tcpHeader);
	if(payload == 0) {printf("\nPayload HTTP= No ASCII to print out\n");}
	else{printf("\nPayload HTTP in ASCII= \n"); for(i=54;i<capLength;i++){if(isprint(p[i])!=0){printf("%c",p[i]);}}}
	printf("\n------------------------------------------\n");
}

}
printf("\n");


}

//===========ARP==============
if (e_type == 0x806) 
{
	printf("Payload = ARP\n"); 
	coutARP++;

//ARP Hardward type
h_type = p[14] * 256 + p[15];
printf("Hardware type = %04X", h_type);
if (h_type == 0x1) {printf(" -> Ethernet\n");}
else {printf(" -> Other\n");
}
//ARP Protocol type
h_type = p[16] * 256 + p[17];
printf("Protocol type = %04X", h_type);
if (h_type == 0x800) {printf(" -> IP\n");}
else {printf(" -> Other\n");}
//ARP Hardware adress length
printf("Hardware address length in bytes = %02X\n", p[18]);
//ARP Protocol address length
printf("Protocol address length in bytes = %02X\n", p[19]);
//ARP Operation
h_type = p[20] * 256 + p[21];
printf("Operation = %04X", h_type);
if (h_type == 0x1) {printf(" -> Request\n");}
else if (h_type == 0x2) {printf(" -> Reply\n");}
else {printf(" -> Other\n");
}
//ARP Sender Hardware Address
printf("Sender Hardware Address = %02X:%02X:%02X:%02X:%02X:%02X\n", p[22], p[23], p[24], p[25], p[26], p[27]);
//ARP Sender IP Address
printf("Sender Protocol Address = %d.%d.%d.%d\n", p[28], p[29], p[30], p[31]);
//ARP Target Hardware Address
printf("Target Hardware Address = %02X:%02X:%02X:%02X:%02X:%02X\n", p[32], p[33], p[34], p[35], p[36], p[37]);
//ARP Target IP Address
printf("Target Protocol Address = %d.%d.%d.%d\n", p[38], p[39], p[40], p[41]);

//ARP data padding
if(p[42] == 0 && p[43]==0 && p[44]==0 && p[45]==0 &&p[46]==0 &&p[48]==0){printf("Padding= 0x");
int i =0;
for(i= 0; i < 18; i++)
{
	if (i % 2 == 0) {printf(" ");}	
	if(p[42] == 0 && p[43]==0 && p[44]==0 && p[45]==0 &&p[46]==0 &&p[48]==0){printf("%02X", p[42+i]);}
}
printf("\n");
}
//payload ARP 
else{printf("Payload ARP = 0x"); int i =0;
for(i= 0; i < 18; i++){if (i % 2 == 0) {printf(" ");}printf("%02X", p[42+i]);}}
printf("\n");
}

       printf("\n%d IP packets, %d ARP packets, %d UDP packets\n", countIP, coutARP, countUDP); //Not required at hw for UDP
       printf("%d ICMP packets, %d TCP packets, %d DNS packets\n", countICMP, countTCP, countDNS); 
       printf("%d SMTP packets, %d POP packets, %d IMAP packets\n", countSMTP,countPOP, countIMAP);
       printf("%d HTTP packets\n", countHTTP);

default_print(p, caplen);
putchar('\n');
}
