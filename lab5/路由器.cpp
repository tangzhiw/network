#pragma once
#include<iostream>
#include <ws2tcpip.h>
#include <conio.h>
#include "pcap.h"
#include "winsock2.h"
#include "stdio.h"
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
#pragma warning( disable : 4996 )//要使用旧函数
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define RT_TABLE_SIZE 32   //路由表大小
using namespace std;
#pragma pack(1)//以1byte方式对齐
//路由表结构


string* Byte2Hex(unsigned char bArray[], int bArray_len)//将mac地址转化
{
	string* strHex = new string();
	int nIndex = 0;
	for (int i = 0; i < bArray_len; i++)
	{
		char hex1;
		char hex2;
		int value = bArray[i];
		int S = value / 16;//高八位
		int Y = value % 16;//低八位
		//将两部分换算为16进制数
		if (S >= 0 && S <= 9)
			hex1 = (char)(48 + S);//从数字0-9转换为‘0’-‘9’        
		else
			hex1 = (char)(55 + S);//从数字10-15转换为'a'-'f'
		if (Y >= 0 && Y <= 9)
			hex2 = (char)(48 + Y);
		else
			hex2 = (char)(55 + Y);
		if (i != bArray_len - 1) {
			*strHex = *strHex + hex1 + hex2 + "-";//将计算好的2位16进制数拼接到原字符串上，若后续还有数据，则添加 - 进行分割
		}
		else
			*strHex = *strHex + hex1 + hex2;
	}

	return strHex;
}
typedef struct FrameHeader_t//帧首部
{
	BYTE DesMac[6];
	BYTE SrcMac[6];
	WORD FrameType;
}FrameHeader_t;

typedef struct IPHeader_t {		//IP首部
	BYTE	Ver_HLen;   //版本与协议类型
	BYTE	TOS;        //服务类型
	WORD	TotalLen;   //总长度
	WORD	ID;         //标识
	WORD	Flag_Segment; //标志和片偏移
	BYTE	TTL;        //生存周期
	BYTE	Protocol;   //协议
	WORD	Checksum;   //校验和
	ULONG	SrcIP;      //源IP地址
	ULONG	DstIP;      //目的IP地址
} IPHeader_t;

typedef struct IPData_t {	//包含帧首部和IP首部的数据包
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} IPData_t;
struct rtable {
	ULONG netmask;         //网络掩码
	ULONG desnet;          //目的网络
	ULONG nexthop;         //下一站路由
};
typedef struct ARPFrame_t//ARP帧
{
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
}ARPFrame_t;

#pragma pack()//恢复对齐方式

//选路 实现最长匹配
ULONG search(rtable* t, int tLength, ULONG DesIP)//返回下一跳步的IP
{
	ULONG best_desnet = 0;  //最优匹配的目的网络
	int best = -1;   //最优匹配路由表项的下标
	for (int i = 0; i < tLength; i++)
	{
		if ((t[i].netmask & DesIP) == t[i].desnet) //目的IP和网络掩码相与后和目的网络比较
		{
			if (t[i].desnet >= best_desnet)//最长匹配
			{
				best_desnet = t[i].desnet;  //保存最优匹配的目的网络
				best = i;    //保存最优匹配路由表项的下标
			}
		}
	}
	if (best == -1)
		return 0xffffffff;      //没有匹配项
	else
		return t[best].nexthop;  //获得匹配项
}
//向路由表中添加项（没有做插入时排序的优化）
bool additem(rtable* t, int& tLength, rtable item)
{
	if (tLength == RT_TABLE_SIZE)  //路由表满则不能添加
		return false;
	for (int i = 0; i < tLength; i++)
		if ((t[i].desnet == item.desnet) && (t[i].netmask == item.netmask) && (t[i].nexthop == item.nexthop))   //路由表中已存在该项，则不能添加
			return false;
	t[tLength] = item;   //添加到表尾
	tLength = tLength + 1;
	return true;
}
//从路由表中删除项
bool deleteitem(rtable* t, int& tLength, int index)
{
	if (tLength == 0)   //路由表空则不能删除
		return false;
	for (int i = 0; i < tLength; i++)
		if (i == index)   //删除以index索引的表项
		{
			for (; i < tLength - 1; i++)
				t[i] = t[i + 1];
			tLength = tLength - 1;
			return true;
		}
	return false;   //路由表中不存在该项则不能删除
}

void printIP(ULONG IP)
{
	BYTE* p = (BYTE*)&IP;
	for (int i = 0; i < 3; i++)
	{
		cout << dec << (int)*p << ".";
		p++;
	}
	cout << dec << (int)*p << " ";
}



void print_rt(rtable* t, int& tLength)
{
	for (int i = 0; i < tLength; i++)
	{
		cout << "\t网络掩码\t" << "目的网络\t" << "下一站路由\t" << endl;
		cout << i << "  ";
		printIP(t[i].netmask);
		printIP(t[i].desnet);
		printIP(t[i].nexthop);
		cout << endl;
	}
}


ULONG cksum(ULONG* mes, int size) {
	int count = (size + 1) / 2;//不能被二整除时填充字节
	u_short* a = (u_short*)malloc(size + 1);
	memset(a, 0, size + 1);//将a全部填充为0
	memcpy(a, mes, size);//将message中的数据进行拷贝
	u_long sum = 0;
	while (count--) {
		sum += *a++;	//将2个16进制数相加
		sum = (sum >> 16) + (sum & 0xffff); //取相加结果的低16位与高16位相加
	}
	return ~sum;
}
void printAddressInfo(const pcap_addr_t* a) {
	char str[INET_ADDRSTRLEN];

	if (a->addr->sa_family == AF_INET) {
		inet_ntop(AF_INET, &((struct sockaddr_in*)a->addr)->sin_addr, str, sizeof(str));
		cout << "IP地址：" << str << endl;

		inet_ntop(AF_INET, &((struct sockaddr_in*)a->netmask)->sin_addr, str, sizeof(str));
		cout << "网络掩码：" << str << endl;

		inet_ntop(AF_INET, &((struct sockaddr_in*)a->broadaddr)->sin_addr, str, sizeof(str));
		cout << "广播地址：" << str << endl;
	}
}
//循环打印设备信息
void printInterfaceList(pcap_if_t* alldevs) {
	int n = 1;

	for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
		cout << n++ << "." << endl;

		if (d->description)
			cout << "(" << d->description << ")" << endl << endl;
		else
			cout << "(No description)\n";

		for (pcap_addr_t* a = d->addresses; a != NULL; a = a->next) {
			printAddressInfo(a);
		}
	}

	if (n == 1) {
		std::cout << "\nNo interfaces found!\n";
	}
}
pcap_if_t* getInterfaceList() {
	pcap_if_t* alldevs = nullptr;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) {
		std::cerr << "Error " << errbuf << std::endl;
		return nullptr;
	}

	return alldevs;
}
void initializeMAC(unsigned char* address, unsigned char value) {
	for (int i = 0; i < 6; i++) {
		address[i] = value;
	}
}
void SET_ARP_HOST(ARPFrame_t& ARPFrame1, ULONG ip) {
	initializeMAC(ARPFrame1.FrameHeader.DesMac, 0xff);
	initializeMAC(ARPFrame1.FrameHeader.SrcMac, 0x66);
	initializeMAC(ARPFrame1.SendHa, 0x66);
	initializeMAC(ARPFrame1.RecvHa, 0x00);

	ARPFrame1.FrameHeader.FrameType = htons(0x0806);
	ARPFrame1.HardwareType = htons(0x0001);
	ARPFrame1.ProtocolType = htons(0x0800);
	ARPFrame1.HLen = 6;
	ARPFrame1.PLen = 4;
	ARPFrame1.Operation = htons(0x0001);
	ARPFrame1.SendIP = inet_addr("112.112.112.112");
	ARPFrame1.RecvIP = ip;
}

void SET_ARP_DEST(ARPFrame_t& ARPFrame, ULONG ip,ULONG ip2, const BYTE* mac) {
	initializeMAC(ARPFrame.FrameHeader.DesMac, 0xff);
	initializeMAC(ARPFrame.RecvHa, 0x00);
	memcpy(ARPFrame.FrameHeader.SrcMac, mac, 6); // Set to the local network card's MAC address
	memcpy(ARPFrame.SendHa, mac, 6); // Set to the local network card's MAC address

	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	ARPFrame.HardwareType = htons(0x0001);
	ARPFrame.ProtocolType = htons(0x0800);
	ARPFrame.HLen = 6;
	ARPFrame.PLen = 4;
	ARPFrame.Operation = htons(0x0001);
	ARPFrame.SendIP = ip;
	ARPFrame.RecvIP = ip2;
}
int main()
{
	
	bool flag = 0;//标志位，表示是否得到IPv4包，0为没有得到。
	BYTE my_mac[6];
	BYTE its_mac[6];
	ULONG my_ip;

	rtable* rt = new rtable[RT_TABLE_SIZE];//使用链表维护路由表
	int rt_length = 0;//路由表的初始长度

	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;

	ULONG targetIP;//定义目标ip

	//char errbuf[PCAP_ERRBUF_SIZE];
	alldevs = getInterfaceList();
	//获取网卡
	d = alldevs;
	printInterfaceList(getInterfaceList());//打印所有设备
	

	
		//打开网卡获取IP
	cout <<endl<< "选择网卡" << endl;
	int in;
	cin >> in;
	
	int i = 0;
	while (i < in - 1) {
		i++;
		d = d->next;
	}
	//打印选择网卡的IP、子网掩码、广播地址并将其作为默认添加至路由表中
	for (a = d->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			cout << "IP地址：";
			printIP((((sockaddr_in*)a->addr)->sin_addr).s_addr);
			cout <<endl<< "子网掩码：";
			printIP((((sockaddr_in*)a->netmask)->sin_addr).s_addr);
			cout << endl << "广播地址：";
			printIP((((sockaddr_in*)a->broadaddr)->sin_addr).s_addr);
			cout << endl;
			cout << endl;
			ULONG NetMask, DesNet, NextHop;
			DesNet = (((sockaddr_in*)a->addr)->sin_addr).s_addr;
			NetMask = (((sockaddr_in*)a->netmask)->sin_addr).s_addr;
			DesNet = DesNet & NetMask;
			NextHop = NULL;
			rtable temp;
			temp.netmask = NetMask;
			temp.desnet = DesNet;
			temp.nexthop = NextHop;
			additem(rt, rt_length, temp);//本机信息作为默认路由
		}
	}



	char errbuf1[PCAP_ERRBUF_SIZE];
	pcap_t* p;//记录调用pcap_open()的返回值，即句柄。

	p = pcap_open(d->name, 1500, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf1);//打开网卡

	int count = 1;
	//增加或删除路由表项
	while (true) {
		ULONG NetMask, DesNet, NextHop;
		char* netmask = new char[20];
		char* desnet = new char[20];
		char* nexthop = new char[20];
		bool flags = 1;//标志位，为0时停止修改路由表
		if (count == 0) {
			cout << "退出(1),继续(0)";
			int control;
			cin >> control;
			if (control) {
				break;
			}
		}
		else {
			count--;
		}
		cout << "输入yes对路由表进行操作 " << endl;
		string ch1;
		cin >> ch1;
		if (ch1 != "yes")
		{
			flags = 0;
			cout << "路由表如下:" << endl;
			print_rt(rt, rt_length);
		}
		while (flags)
		{
			
			
			cout << "显示(2) 添加（1） 删除（0）" << endl;
			int operate;
			cin >> operate;

			if (operate == 1)
			{
				cout << "请输入路由表项" << endl;
				cin >> desnet;
				cin >> netmask;
				cin >> nexthop;
				DesNet = inet_addr(desnet);
				NetMask = inet_addr(netmask);
				NextHop = inet_addr(nexthop);

				rtable temp;
				temp.netmask = NetMask;
				temp.desnet = DesNet;
				temp.nexthop = NextHop;

				additem(rt, rt_length, temp);

				int operate2;
				cout << "输入1继续添加，输入0停止添加" << endl;
				print_rt(rt, rt_length);//打印路由表
				cin >> operate2;
				if (operate2 == 0)
				{
					flags = 0;
					cout << "路由表如下:" << endl;
					print_rt(rt, rt_length);
					break;
				}

			}
			else if (operate == 0)
			{
				int index;
				cout << "请输入要删除的表项" << endl;
				cin >> index;//从下标0开始
				deleteitem(rt, rt_length, index);
				int operate2;
				cout << "输入1继续添加，输入0停止添加" << endl;
				cin >> operate2;
				if (operate2 == 0)
				{
					flags = 0;
					cout << "路由表如下:" << endl;
					print_rt(rt, rt_length);
					break;
				}

			}
			else if (operate == 2) {
				cout << "路由表如下" << endl;
				print_rt(rt, rt_length);
			}
		}

		//获取本机的MAC
		BYTE scrMAC[6];
		ULONG scrIP;
		for (i = 0; i < 6; i++)
		{
			scrMAC[i] = 0x66;
		}
		scrIP = inet_addr("112.112.112.112");//虚拟IP


		//for (d = alldevs, i = 0; i < in; i++, d = d->next);
		for (a = d->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET)
			{
				targetIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
				my_ip = targetIP;
			}
		}

		ARPFrame_t ARPFrame;
		SET_ARP_HOST(ARPFrame, my_ip);
		int ret_send = pcap_sendpacket(p, (u_char*)&ARPFrame, sizeof(ARPFrame_t));

		//要默认发包成功  不然会出错
		/*if (ret_send)
		{
			cout << "向自己发包失败" << endl;
		}*/
		//else
		//{
		cout << "获取本机MAC" << endl;


		//截获自己的MAC
		pcap_pkthdr* pkt_header1 = new pcap_pkthdr[1500];
		const u_char* pkt_data1;

		ARPFrame_t* ARPFrame1;

		while (!flag)
		{

			if ((pcap_next_ex(p, &pkt_header1, &pkt_data1) == 0))
			{
				continue;
			}
			if ((pcap_next_ex(p, &pkt_header1, &pkt_data1) == 1))
			{
				ARPFrame1 = (ARPFrame_t*)pkt_data1;
				if (ARPFrame1->SendIP == targetIP && ARPFrame1->RecvIP == scrIP)
				{
					cout << "本机IP:";
					printIP(ARPFrame1->SendIP);
					cout << endl;

					cout << "本机MAC:" << *(Byte2Hex(ARPFrame1->SendHa, 6)) << endl;
					for (int i = 0; i < 6; i++)
					{
						my_mac[i] = ARPFrame1->SendHa[i];

					}
					flag = 1;

				}

			}

		}
		//}


	

		//获取目的mac为本机mac，目的ip非本机ip的ip数据报

		ULONG nextIP;//路由的下一站
		flag = 0;

		IPData_t* IPPacket;


		pcap_pkthdr* pkt_header = new pcap_pkthdr[1500];
		const u_char* pkt_data;
		//不断收包
		while (1)
		{
			//数据包的获取
			int ret;
			ret = pcap_next_ex(p, &pkt_header, &pkt_data);//在打开的网络接口卡上获取网络数据包
			if (ret)
			{
				//cout << "数据包len:" << pkt_header->len << endl;
				WORD RecvChecksum;
				WORD FrameType;

				IPPacket = (IPData_t*)pkt_data;

				ULONG Len = pkt_header->len + sizeof(FrameHeader_t);//数据包大小包括帧数据部分长度和帧首部长度
				u_char* sendAllPacket = new u_char[Len];
				for (i = 0; i < Len; i++)
				{
					sendAllPacket[i] = pkt_data[i];
				}

				RecvChecksum = IPPacket->IPHeader.Checksum;
				IPPacket->IPHeader.Checksum = 0;
				FrameType = IPPacket->FrameHeader.FrameType;
				bool desmac_equal = 1;//目的mac地址与本机mac地址是否相同，相同为1；
				for (int i = 0; i < 6; i++)
				{
					if (my_mac[i] != IPPacket->FrameHeader.DesMac[i])
					{
						desmac_equal = 0;
					}
				}
				bool desIP_equal = 0;//目的IP与本机IP是否相同，不相同为1；
				if (IPPacket->IPHeader.DstIP != my_ip)
				{
					desIP_equal = 1;
					targetIP = IPPacket->IPHeader.DstIP;
				}
				bool Is_ipv4 = 0;
				if (FrameType == 0x0008)
				{
					Is_ipv4 = 1;
				}

				if (Is_ipv4 && desmac_equal && desIP_equal)//处理目的IP不是本机IP，目的MAC为本机MAC的IPv4包 
				{
					cout << endl<<"转发中" << endl;

					int version = (IPPacket->IPHeader.Ver_HLen & 0xf0) >> 4;
					int headlen = (IPPacket->IPHeader.Ver_HLen & 0x0f);
					int tos = IPPacket->IPHeader.TOS;//服务类型

					int totallen = ntohs(IPPacket->IPHeader.TotalLen);//数据包总长度

					int id = ntohs(IPPacket->IPHeader.ID);//标识
					int ttl = IPPacket->IPHeader.TTL;
					int protocol = IPPacket->IPHeader.Protocol;



					cout << "版本：" << version << endl;
					cout << "头长度：" << headlen << endl;
					cout << "tos：" << dec << tos << endl;
					cout << "总长度：" << dec << totallen << endl;
					cout << "标识符" << "0x" << id << endl;
					cout << "生存周期" << dec << ttl << endl;
					cout << "协议：" << dec << protocol << endl;

					cout << "数据包源地址：";
					printIP(IPPacket->IPHeader.SrcIP);
					cout << endl;
					cout << "数据包目的地址：";
					printIP(IPPacket->IPHeader.DstIP);
					cout << endl <<endl;

					//选路投递
					nextIP = search(rt, rt_length, IPPacket->IPHeader.DstIP);
					
					cout << "下一跳:";
					printIP(nextIP);
					cout << endl;
					if (nextIP == 0)
					{
						nextIP = IPPacket->IPHeader.DstIP;
					}
					else if (nextIP == 0xffffffff)
					{
						cout << "出错，将抛弃该包" << endl;
					}

					flag = 1;



					//向下一跳发送arp获取MAC地址

					memcpy(&scrMAC, &my_mac, 6);
					scrIP = my_ip;
					//获取下一跳的mac地址

					targetIP = nextIP;

					//组装ARP包
					SET_ARP_DEST(ARPFrame, scrIP, targetIP, scrMAC);
					int send_ret = pcap_sendpacket(p, (u_char*)&ARPFrame, sizeof(ARPFrame_t));


					
					cout << "发包成功" << endl;


					//截获它的MAC

					pcap_pkthdr* pkt_header2 = new pcap_pkthdr[1500];
					const u_char* pkt_data2;

					int res;
					ARPFrame_t* ARPFrame2;

					int flag1 = 0;
					while (!flag1)
					{
						res = pcap_next_ex(p, &pkt_header2, &pkt_data2);

						if ((res == 0))
						{
							continue;

						}
						if (res == 1)
						{
							ARPFrame2 = (ARPFrame_t*)pkt_data2;

							if (ARPFrame2->SendIP == nextIP && ARPFrame2->RecvIP == my_ip)
							{
								cout << "下一跳的MAC地址:" << *(Byte2Hex(ARPFrame2->SendHa, 6)) << endl;
								memcpy(&its_mac, &ARPFrame2->FrameHeader.SrcMac, 6);
								flag1 = 1;
								cout << "下一跳的IP:";
								printIP(ARPFrame2->SendIP);
								cout << endl;
							}
						}

					}

					//}




	
	
					//转发包
					IPData_t* TempIP;
					TempIP = (IPData_t*)sendAllPacket;
					
					memcpy(&TempIP->FrameHeader.DesMac, &its_mac, 6);
					memcpy(&TempIP->FrameHeader.SrcMac, &my_mac, 6);
					if (!pcap_sendpacket(p, sendAllPacket, Len))
					{
						cout << endl;
						cout << "完成转发" << endl;
						IPData_t* t;
						t = (IPData_t*)sendAllPacket;
						cout << "源IP地址：";
						printIP(t->IPHeader.SrcIP);
						cout << endl;
						cout << "源mac地址：" << *(Byte2Hex(t->FrameHeader.SrcMac, 6)) << endl;
						cout << endl;
						cout << "目的IP地址：";
						printIP(t->IPHeader.DstIP);
						cout << endl;

						cout << "目的mac地址："<< *(Byte2Hex(t->FrameHeader.DesMac, 6)) << endl;
						
					}


				}
			}
			if (_kbhit()) {//跳出发包收包重新进入路由表编辑
				// 获取键盘输入
				char ch = _getch();

				// 处理键盘输入
				if (ch == 'q' || ch == 'Q') {
					// 如果输入是 'q' 或 'Q'，退出循环
					break;
					
				}
				
				else {
					// 处理其他输入
					cout << "你按下了键：" << ch << endl;
				}
			}
		}
		
	}
	
	cout << "结束" << endl;
	pcap_freealldevs(alldevs);//释放设备列表
	return 0;

}








