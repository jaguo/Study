#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h> 

//#define EXCHANGE_BYTE(value) (((uint16_t)(value) & 0xff00)>>8 + ((uint16_t)(value) & 0xff)<<8)
//#define BigtoLittle16(A) (((A) >> 8) + ((A) << 8))

#pragma pack(1)


void show(const u_char * packet);
void showMacAddr(const char * mac_Addr);
void showIPAddr(uint32_t ipAddr);
void showProtocol(uint8_t Protocol);
void show_RARP_PacketMes(const u_char * packet);		//struct
void show_ARP_PacketMes(const u_char * packet);			//struct
void show_IP_PacketMes(const u_char * packet);			//struct
void show_TCP_PacketMes(const u_char * packet);			//pointer
void show_UDP_PacketMes(const u_char * packet);			//pointer
void show_ICMP_PacketMes(const u_char * packet);		//pointer (only show code and type)
uint16_t exchange_byte(uint16_t num);
void show_DNS_Mes(const u_char * packet);
void showQueriesAndAns(const u_char * packet, uint16_t question, uint16_t ans);
int print_name(const u_char *packet, char *p, int *i);

//Header

typedef struct frameheader
{
	char DesMAC[6];
	char SrcMAC[6];
	uint16_t FrameType;
} frameheader;

//IP Packet Header

typedef struct IPHeader
{
	uint8_t Ver_Hlen;			//IP Version and Header Length
	uint8_t TOS;				//Type of Service
	uint16_t TotalLen;			//Packet of length
	uint16_t id;				//Identification(...)
	uint16_t Flag_Segment;		//Fragment offset
	uint8_t ttl;				//Time to Live
	uint8_t Protocol;			//Protocol
	uint16_t Checksum;			//Check Sum
	uint32_t SrcIP;				//Src IP
	uint32_t DstIP;				//Dst IP
} IPHeader;

//ARP and RARP Packet Header

typedef struct ARP_RARP_Header
{
	uint16_t HardWareType;			//Hardware type
	uint16_t ProtocolType;			//Protocol type
	uint8_t HardWareSize;			//Hardware Size
	uint8_t ProtocolSize;			//Protocol size
	uint16_t Opcode;				//Opcode (request or reply)
	char SenderMAC[6];				//Sender MAC address
	uint32_t SenderIP;				//Sender IP address
	char TargetMAC[6];				//Target MAC address
	uint32_t TargetIP;				//Target IP address
} ARPHeader, RARPHeader;


typedef struct IPFrameData
{
	frameheader Frhdr;
	IPHeader Iphdr;
} IPFrameData;

typedef struct ARPFrameData
{
	frameheader Frhdr;
	ARPHeader Arphdr;
} ARPFrameData;

typedef struct RARPFrameData
{
	frameheader Frhdr;
	RARPHeader Rarphdr;
} RARPFrameData;



void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)  
{
	int *id = (int *)arg;

	printf("=======================================\n");
	printf("id : %d\n", ++(*id));
	printf("Packet Length: %d\n", pkthdr->len);
	printf("Number of Bytes: %d\n", pkthdr->caplen);
	printf("Recieved time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));

	show(packet);

	// int i, j;

	// putchar(10);
	// for (i = 0; i<pkthdr->len; i += 0x10)
	// {
	// 	printf("0x%04x\t", i);
	// 	for(j = 0; j < 0x10; j++)
	// 	{
	// 		printf(" %02x", packet[i + j]);
	// 	}
	// 	printf("\t\t");
	// 	for(j = 0; j < 0x10; j++)
	// 	{
	// 		if(isprint(packet[i + j]))
	// 			printf("%c", packet[i + j]);
	// 		else
	// 			printf(".");
	// 	}
	// 	printf("\n");
	// }
	printf("\n");

}


int main(int argc, char const *argv[])
{
	char filter_out[20] = "";
	int i;
	if(argc > 0)
	{
		for(i = 1; i < argc; i++)
		{
			strcat(filter_out,argv[i]);
			strcat(filter_out," ");
		}
	}

	char errBuf[PCAP_ERRBUF_SIZE], * device;

	//get a device

	device = pcap_lookupdev(errBuf);

	// char local_net[] = "lo";
	// device = local_net;

	if(device){
		printf("Success: device: %s\n", device);
	}else{
		printf("error: %s\n", errBuf);
		exit(1);
	}

	//open a device, wait until a packet arrives

	pcap_t *handle = pcap_open_live(device, 65535, 1, 0, errBuf);

	if(!handle)
	{
		printf("error: pcap_open_live(): %s\n", errBuf);
		exit(1);
	}

	//construct a filter
	struct bpf_program filter;
	pcap_compile(handle, &filter, filter_out, 1, 0);
	pcap_setfilter(handle, &filter);

	//wait loop forever
	int id = 0;
	pcap_loop(handle, -1, getPacket, (u_char *)&id);
	pcap_close(handle);

	return 0;
}

void show(const u_char * packet)
{
	frameheader * header = (frameheader *)(packet);
	printf("DstMacAdd: ");
	showMacAddr(header->DesMAC);
	printf("SrcMACAdd: ");
	showMacAddr(header->SrcMAC);
	//uint16_t type = header-> FrameType;
	//type = (type << 8) + (type >> 8);
	printf("=======================================\n");
	switch(exchange_byte(header-> FrameType))
	{
		case 0x0800:
			printf("Type: IP\n");
			show_IP_PacketMes(packet);
			break;
		case 0x0806:
			printf("Type: ARP\n");
			show_ARP_PacketMes(packet);
			break;
		case 0x8035:
			printf("Type: RARP\n");
			show_RARP_PacketMes(packet);
			break;
		case 0x86dd:
			printf("Type: IPv6\n");
			break;
		default:
			printf("FrameType Unknown\n");
	}
	printf("=======================================\n");
	printf("\n\n");
}

void show_IP_PacketMes(const u_char * packet)
{
	IPFrameData * ip_packet = (IPFrameData *)(packet);

	// printf("DstMacAdd: ");
	// showMacAddr(ip_packet->Frhdr.DesMAC);
	// printf("SrcMACADD: ");
	// showMacAddr(ip_packet->Frhdr.SrcMAC);
	// printf("Type: IP\n");
	uint8_t ver_hlen = ip_packet->Iphdr.Ver_Hlen;
	uint8_t version = (ver_hlen & 0xf0);
	if(version == 0x40)
		printf("Version: IP4\n");
	else
		printf("Version: IP6\n");
	printf("Packet HL: %d\n", (ver_hlen & 0xf) * 4);
	printf("Packet TL: %d\n", exchange_byte(ip_packet->Iphdr.TotalLen));
	printf("Identification: 0x%04x(%d)\n",exchange_byte(ip_packet->Iphdr.id),exchange_byte(ip_packet->Iphdr.id));
	printf("Time to Live: %d\n", ip_packet->Iphdr.ttl);
	showProtocol(ip_packet->Iphdr.Protocol);
	printf("CheckSum: 0x%04x\n", exchange_byte(ip_packet->Iphdr.Checksum));
	printf("SrcIPAdd: ");
	showIPAddr(ip_packet->Iphdr.SrcIP);
	printf("DstIPAdd: ");
	showIPAddr(ip_packet->Iphdr.DstIP);
	switch(ip_packet->Iphdr.Protocol)
	{
		case 0x01:show_ICMP_PacketMes(packet + 0x22);break;
		case 0x02:printf("IGMP\n");break;
		case 0x06:show_TCP_PacketMes(packet + 0x22);break;
		case 0x11:show_UDP_PacketMes(packet + 0x22);break;
		default:printf("Unknown\n");
	}
}

void show_Port(uint16_t port)
{
	switch(port)
	{
		case 21:printf(" ftp ");break;
		case 22:printf(" ssh ");break;
		case 23:printf(" Telnet ");break;
		case 25:printf(" SMTP ");break;
		case 53:printf(" DNS ");break;
		case 69:printf(" TFTP ");break;
		case 79:printf(" finger ");break;
		case 80:printf(" HTTP ");break;
		case 137:printf(" netbios-ns ");break;
		case 138:printf(" netbios-dgm ");break;
		case 139:printf(" netbios-ssn ");break;
		case 443:printf(" HTTPS");break;
		default:printf("%d",(uint16_t)port);
	}
}

void show_TCP_PacketMes(const u_char * packet)
{
	printf("\nTransmission Control Protocol (TCP):\n");
	int i,j;
	char set[] = "Set";
	char not[] = "Not set";
	uint16_t sp = exchange_byte(*(uint16_t *)packet);
	printf("Sourse port:");
	show_Port(sp);
	printf("(%d)\n", (uint16_t)sp);
	uint16_t dp = exchange_byte(*(uint16_t *)(packet + 2));
	printf("Destination port:");
	show_Port(dp);
	printf("(%d)\n", (uint16_t)dp);
	printf("Sequence number:");
	for(i = 0; i < 4; i++){
		printf(" %02x",*(packet + 4 + i));
	}
	printf("\nAcknowledgment number:");
	for(i = 0; i< 4; i++){
		printf(" %02x", *(packet + 8 + i));
	}
	int len = (uint8_t)(*(packet + 12) & 0xf0) >> 4;
	printf("\nHeader length: %d bytes\n", len * 4);
	uint16_t flag = (uint8_t)(*(packet + 13)) + ((uint8_t)(*(packet + 12) & 0x3) << 8);
	printf("\tFlag: 0x%03x\n", flag);
	printf("\t000. .... .... = Reserved: Not set\n");
	printf("\t...%d .... .... = Nonce: %s\n", (flag & 0x100) != 0, (flag & 0x100) ? set : not);
	printf("\t.... %d... .... = Congestion Window Reduced (CWR): %s\n", (flag & 0x80) != 0, (flag & 0x80) ? set : not);
	printf("\t.... .%d.. .... = ECN-Echo: %s\n", (flag & 0x40) != 0, (flag & 0x40) ? set : not);
	printf("\t.... ..%d. .... = Urgent: %s\n", (flag & 0x20) != 0, (flag & 0x20) ? set : not);
	printf("\t.... ...%d .... = Acknowledgment: %s\n", (flag & 0x10) != 0, (flag & 0x10) ? set : not);
	printf("\t.... .... %d... = Push: %s\n", (flag & 0x8) != 0, (flag & 0x8) ? set : not);
	printf("\t.... .... .%d.. = Reset: %s\n", (flag & 0x4) != 0, (flag & 0x4) ? set : not);
	printf("\t.... .... ..%d. = Syn: %s\n", (flag & 0x2) != 0, (flag & 0x2) ? set : not);
	printf("\t.... .... ...%d = Fin: %s\n", (flag & 0x1) != 0, (flag & 0x1) ? set : not);
	uint16_t winsize = (*(uint16_t *)(packet + 14));
	printf("Window size value: %d\n", exchange_byte(winsize));
	uint16_t checksum = (*(uint16_t *)(packet + 16));
	printf("Checksum: 0x%04x(%d)\n", exchange_byte(checksum),exchange_byte(checksum));
}

void show_UDP_PacketMes(const u_char * packet)
{
	printf("\nUser Datagram Protocol(UDP):\n");
	uint16_t sp = exchange_byte(*(uint16_t *)packet);
	printf("Sourse port:");
	show_Port(sp);
	printf("(%d)\n", (uint16_t)sp);
	uint16_t dp = exchange_byte(*(uint16_t *)(packet + 2));
	printf("Destination port:");
	show_Port(dp);
	printf("(%d)\n", (uint16_t)dp);
	uint16_t len = exchange_byte(*(uint16_t *)(packet + 4));
	printf("Length: %d\n", len);
	uint16_t checksum = exchange_byte(*(uint16_t *)(packet + 6));
	printf("Checksum: 0x%04x\n", checksum);
	show_DNS_Mes(packet + 8);
}

void show_DNS_Mes(const u_char * packet)
{
	char res[] = "Message is a query response";
	char que[] = "Message is a query";
	printf("Domain Name System:\n");
	uint16_t id = exchange_byte(*(uint16_t *)packet);
	printf("Transaction ID: 0x%04x\n", id);
	uint16_t flag = exchange_byte(*(uint16_t *)(packet + 2));
	// printf("Flags: 0x%04x Standard query\n", flag);
	// printf("%d... .... .... .... = Response: %s\n", (flag & 0x8000) != 0, (flag & 0x8000) ? res : que);
	// printf(".000 %d... .... .... = Opcode: %d ;0. QUERY;1. IQUERY;2. STATUS;5. UPDATE\n",(flag & 0x800) != 0, (flag & 0x7800));
	// printf(".... .%d.. .... .... = Authoritative: Server is %san authority for domain\n",(flag & 0x400) != 0, (flag & 0x8000) ? "" : "not ");
	// printf(".... ..%d. .... .... = Truncated: Message is %struncated\n", (flag & 0x200) != 0, (flag & 0x200) ? "" : "not ");
	// printf(".... ...%d .... .... = Recursion desired: Do %squery recursively\n", (flag & 0x100) != 0, (flag & 0x100) ? "" : "not ");
	// printf(".... .... %d... .... = Recursion available: Server can %sdo recursive queries\n", (flag & 0x80) != 0, (flag & 0x80) ? "" : "not ");
	// printf(".... .... .000 .... = Zero: reserved (0)\n");
	// printf(".... .... .... %04x = Reply code: %s\n", (flag & 0xf), (flag & 0xf) ? "Error" : "No Error");
	// if(flag & 0xf)
	// {
	// 	printf("Error List *****************************\n");
	// 	switch(flag & 0xf)
	// 	{
	// 		case 1:printf("Format error\n");break;
	// 		case 2:printf("Server failure\n");break;
	// 		case 3:printf("Name Error\n");break;
	// 		case 4:printf("Not Implemented\n");break;
	// 		case 5:printf("Refused\n");break;
	// 		default: printf("No Error Message!\n");
	// 	}
	// 	printf("***************************************\n");
	// }
	uint16_t question = exchange_byte(*(uint16_t *)(packet + 4));
	printf("Question: %d\n", question);
	uint16_t ans = exchange_byte(*(uint16_t *)(packet + 6));
	printf("Answer RRs: %d\n", ans);
	uint16_t nscount = exchange_byte(*(uint16_t *)(packet + 8));
	//printf("Authority RRs: %d\n", nscount);
	uint16_t arcount = exchange_byte(*(uint16_t *)(packet + 10));
	//printf("Additional RRs: %d\n", arcount);
	showQueriesAndAns(packet + 12, question, ans);
}

void showQueriesAndAns(const u_char * packet, uint16_t question, uint16_t ans)
{
	int i = 0;
	char *p = (char *)packet;
	printf("Question:**********************************\n");
	while(question --)
	{
		printf("Name: ");
		print_name(packet, p, &i);
		putchar(10);
		uint16_t type = exchange_byte(*(uint16_t *)(packet + i));
		switch(type)
		{
			case 1:printf("Type: A (HostAddress)\n");break;
			case 2:printf("Type: NS\n");break;
			case 5:printf("Type: CNAME\n");break;
			case 6:printf("Type: SOA\n");break;
			case 12:printf("Type: PTR(IP To HoseName)\n");break;
			case 13:printf("Type: HINFO\n");break;
			case 28:printf("Type: AAAA (IPv6)\n");break;
			default:printf("Unknown(0x%04x)\n", type);
		}
		uint16_t class = exchange_byte(*(uint16_t *)(packet + i + 2));
		printf("Class: IN (0x%04x)\n", class);
	}
	i = i + 4;

	printf("Answer:************************************\n");
	while(ans--)
	{
		printf("Name: ");
		print_name(packet, p, &i);
		putchar(10);
		uint16_t type = exchange_byte(*(uint16_t *)(packet + i));
		switch(type)
		{
			case 1:printf("Type: A (HostAddress)\n");break;
			case 2:printf("Type: NS\n");break;
			case 5:printf("Type: CNAME\n");break;
			case 6:printf("Type: SOA\n");break;
			case 12:printf("Type: PTR(IP To HoseName)\n");break;
			case 13:printf("Type: HINFO\n");break;
			case 28:printf("Type: AAAA (IPv6)\n");break;
			default:printf("Type: Unknown(0x%04x)\n", type);
		}
		uint16_t class = exchange_byte(*(uint16_t *)(packet + i + 2));
		printf("Class: IN (0x%04x)\n", class);
		uint32_t ttl = *(uint32_t *)(packet + i + 4);
		ttl = ((uint32_t)(ttl & 0xff000000) >> 24) |
		 ((uint32_t)(ttl & 0x00ff0000) >> 8) |
		 ((uint32_t)(ttl & 0x0000ff00) << 8) |
		 ((uint32_t)(ttl & 0x000000ff) << 24);
		printf("TTL: 0x%08x (%d)\n", ttl, ttl);
		uint16_t datalen = exchange_byte(*(uint16_t *)(packet + i + 8));
		i += 10;
		printf("Datalen: %04x (%d)\n", datalen, datalen);
		if(datalen != 4 && *(p + i) <0x40)
		{
			printf("Primaryname: ");
			print_name(packet, p, &i);
			putchar(10);
		}
		else
		{
			printf("IP Address: ");
			showIPAddr(*(uint32_t *)(p + i));
			i += 4;
		}
		putchar(10);
	}
}

void print_name2(const char * packet, char *p)
{
	int i = 0;
	int flag = 0;
	(*p) ++;
	while(*(p + i) != 0)
	{
		if((*(p + i) & 0xff) == 0xc0)
		{
			if(flag)
				printf(".");
			char * old = (char *)(packet);
			old -= 12;
			old += *(uint8_t *)(p + i + 1);
			print_name2(packet, old);
			i += 2;
			return; 
		} 
		if(*(p + i) > 48)
		{
			printf("%c", *(p + i));
		}
		else if(i != 0)
			printf(".");
		(i) ++;
		flag = 1;
	}
}

int print_name(const u_char *packet, char *p, int *i)
{
	int flag = 0;
	while(*(p + *i) != 0)
	{
		if((*(p + *i) & 0xff) == 0xc0)
		{
			if(flag)
				printf(".");
			char * old = (char *)(packet);
			old -= 12;
			old += *(uint8_t *)(p + *i + 1);
			print_name2(packet, old);
			(*i) += 2;
			return; 
		}
		else
		{
			if(*(p + *i) > 48)
			{
				printf("%c", *(p + *i));
			}
			else if(flag)
				printf(".");
			(*i) ++;
		}
		flag = 1;
	}
	if(*(p + *i) == 0)
		(*i) ++;
}

void show_ICMP_PacketMes(const u_char * packet)
{
	printf("\nInternet Control Message Protocol(ICMP):\n");
	uint8_t type = (*(uint8_t *)packet);
	printf("Type: %d\n", type);
	uint8_t code = (*(uint8_t *)(packet + 1));
	printf("Code: %d\n", code);
	uint16_t checksum = exchange_byte(*(uint16_t *)(packet + 2));
	printf("Checksum: 0x%04x(%d)\n", checksum, checksum);
}

void show_ARP_PacketMes(const u_char * packet)
{
	ARPFrameData * apr_packet = (ARPFrameData *)(packet);

	printf("Hardware type: Ethernet\n");
	printf("Protocol Type: %04x\n", exchange_byte(apr_packet->Arphdr.ProtocolType));
	printf("HardWare Size: %d\n", apr_packet->Arphdr.HardWareSize);
	printf("Protocol Size: %d\n", apr_packet->Arphdr.ProtocolSize);
	if(exchange_byte(apr_packet->Arphdr.Opcode) == 0x01)
		printf("Opcode: request(1)\n");
	else
		printf("Opcode: reply(2)\n");
	printf("Sender MAC address:");
	showMacAddr(apr_packet->Arphdr.SenderMAC);
	printf("Sender IP address : ");
	showIPAddr(apr_packet->Arphdr.SenderIP);
	printf("Target MAC address:");
	showMacAddr(apr_packet->Arphdr.TargetMAC);
	printf("Target IP address : ");
	showIPAddr(apr_packet->Arphdr.TargetIP);
}

void show_RARP_PacketMes(const u_char * packet)
{
	show_ARP_PacketMes(packet);
}

void showMacAddr(const char * mac_Addr)
{
	int i;
	for(i = 0; i < 6; i++){
		printf(" %02x",(uint8_t)mac_Addr[i]);
	}
	printf("\n");
}

void showIPAddr(uint32_t ipAddr)
{
	int i;
	uint32_t tmp = ipAddr;
	for(i = 0; i < 4; i++)
	{
		tmp = tmp & 0xff;
		printf("%d",tmp);
		if(i != 3)
			printf(".");
		tmp = ipAddr;
		tmp = tmp >> ((i + 1) * 8);
	}
	putchar(10);
}

void showProtocol(uint8_t Protocol)
{
	printf("Protocol :");
	switch(Protocol)
	{
		case 0x01:printf("ICMP\n");break;
		case 0x02:printf("IGMP\n");break;
		case 0x06:printf("TCP\n");break;
		case 0x11:printf("UDP\n");break;
		default:printf("Unknown\n");
	}
}

uint16_t exchange_byte(uint16_t num)
{
	uint16_t tmp = num;
	tmp = (tmp >> 8) + (tmp << 8);
	return tmp;
}
