#pragma once
#include<iostream>
#include <ws2tcpip.h>
#include <conio.h>
#include "pcap.h"
#include "winsock2.h"
#include "stdio.h"
#pragma comment(lib,"ws2_32.lib")//��ʾ���ӵ�ʱ����ws2_32.lib
#pragma warning( disable : 4996 )//Ҫʹ�þɺ���
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define RT_TABLE_SIZE 32   //·�ɱ��С
using namespace std;
#pragma pack(1)//��1byte��ʽ����
//·�ɱ�ṹ


string* Byte2Hex(unsigned char bArray[], int bArray_len)//��mac��ַת��
{
	string* strHex = new string();
	int nIndex = 0;
	for (int i = 0; i < bArray_len; i++)
	{
		char hex1;
		char hex2;
		int value = bArray[i];
		int S = value / 16;//�߰�λ
		int Y = value % 16;//�Ͱ�λ
		//�������ֻ���Ϊ16������
		if (S >= 0 && S <= 9)
			hex1 = (char)(48 + S);//������0-9ת��Ϊ��0��-��9��        
		else
			hex1 = (char)(55 + S);//������10-15ת��Ϊ'a'-'f'
		if (Y >= 0 && Y <= 9)
			hex2 = (char)(48 + Y);
		else
			hex2 = (char)(55 + Y);
		if (i != bArray_len - 1) {
			*strHex = *strHex + hex1 + hex2 + "-";//������õ�2λ16������ƴ�ӵ�ԭ�ַ����ϣ��������������ݣ������ - ���зָ�
		}
		else
			*strHex = *strHex + hex1 + hex2;
	}

	return strHex;
}
typedef struct FrameHeader_t//֡�ײ�
{
	BYTE DesMac[6];
	BYTE SrcMac[6];
	WORD FrameType;
}FrameHeader_t;

typedef struct IPHeader_t {		//IP�ײ�
	BYTE	Ver_HLen;   //�汾��Э������
	BYTE	TOS;        //��������
	WORD	TotalLen;   //�ܳ���
	WORD	ID;         //��ʶ
	WORD	Flag_Segment; //��־��Ƭƫ��
	BYTE	TTL;        //��������
	BYTE	Protocol;   //Э��
	WORD	Checksum;   //У���
	ULONG	SrcIP;      //ԴIP��ַ
	ULONG	DstIP;      //Ŀ��IP��ַ
} IPHeader_t;

typedef struct IPData_t {	//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} IPData_t;
struct rtable {
	ULONG netmask;         //��������
	ULONG desnet;          //Ŀ������
	ULONG nexthop;         //��һվ·��
};
typedef struct ARPFrame_t//ARP֡
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

#pragma pack()//�ָ����뷽ʽ

//ѡ· ʵ���ƥ��
ULONG search(rtable* t, int tLength, ULONG DesIP)//������һ������IP
{
	ULONG best_desnet = 0;  //����ƥ���Ŀ������
	int best = -1;   //����ƥ��·�ɱ�����±�
	for (int i = 0; i < tLength; i++)
	{
		if ((t[i].netmask & DesIP) == t[i].desnet) //Ŀ��IP����������������Ŀ������Ƚ�
		{
			if (t[i].desnet >= best_desnet)//�ƥ��
			{
				best_desnet = t[i].desnet;  //��������ƥ���Ŀ������
				best = i;    //��������ƥ��·�ɱ�����±�
			}
		}
	}
	if (best == -1)
		return 0xffffffff;      //û��ƥ����
	else
		return t[best].nexthop;  //���ƥ����
}
//��·�ɱ�������û��������ʱ������Ż���
bool additem(rtable* t, int& tLength, rtable item)
{
	if (tLength == RT_TABLE_SIZE)  //·�ɱ����������
		return false;
	for (int i = 0; i < tLength; i++)
		if ((t[i].desnet == item.desnet) && (t[i].netmask == item.netmask) && (t[i].nexthop == item.nexthop))   //·�ɱ����Ѵ��ڸ���������
			return false;
	t[tLength] = item;   //��ӵ���β
	tLength = tLength + 1;
	return true;
}
//��·�ɱ���ɾ����
bool deleteitem(rtable* t, int& tLength, int index)
{
	if (tLength == 0)   //·�ɱ������ɾ��
		return false;
	for (int i = 0; i < tLength; i++)
		if (i == index)   //ɾ����index�����ı���
		{
			for (; i < tLength - 1; i++)
				t[i] = t[i + 1];
			tLength = tLength - 1;
			return true;
		}
	return false;   //·�ɱ��в����ڸ�������ɾ��
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
		cout << "\t��������\t" << "Ŀ������\t" << "��һվ·��\t" << endl;
		cout << i << "  ";
		printIP(t[i].netmask);
		printIP(t[i].desnet);
		printIP(t[i].nexthop);
		cout << endl;
	}
}


ULONG cksum(ULONG* mes, int size) {
	int count = (size + 1) / 2;//���ܱ�������ʱ����ֽ�
	u_short* a = (u_short*)malloc(size + 1);
	memset(a, 0, size + 1);//��aȫ�����Ϊ0
	memcpy(a, mes, size);//��message�е����ݽ��п���
	u_long sum = 0;
	while (count--) {
		sum += *a++;	//��2��16���������
		sum = (sum >> 16) + (sum & 0xffff); //ȡ��ӽ���ĵ�16λ���16λ���
	}
	return ~sum;
}
void printAddressInfo(const pcap_addr_t* a) {
	char str[INET_ADDRSTRLEN];

	if (a->addr->sa_family == AF_INET) {
		inet_ntop(AF_INET, &((struct sockaddr_in*)a->addr)->sin_addr, str, sizeof(str));
		cout << "IP��ַ��" << str << endl;

		inet_ntop(AF_INET, &((struct sockaddr_in*)a->netmask)->sin_addr, str, sizeof(str));
		cout << "�������룺" << str << endl;

		inet_ntop(AF_INET, &((struct sockaddr_in*)a->broadaddr)->sin_addr, str, sizeof(str));
		cout << "�㲥��ַ��" << str << endl;
	}
}
//ѭ����ӡ�豸��Ϣ
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
	
	bool flag = 0;//��־λ����ʾ�Ƿ�õ�IPv4����0Ϊû�еõ���
	BYTE my_mac[6];
	BYTE its_mac[6];
	ULONG my_ip;

	rtable* rt = new rtable[RT_TABLE_SIZE];//ʹ������ά��·�ɱ�
	int rt_length = 0;//·�ɱ�ĳ�ʼ����

	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;

	ULONG targetIP;//����Ŀ��ip

	//char errbuf[PCAP_ERRBUF_SIZE];
	alldevs = getInterfaceList();
	//��ȡ����
	d = alldevs;
	printInterfaceList(getInterfaceList());//��ӡ�����豸
	

	
		//��������ȡIP
	cout <<endl<< "ѡ������" << endl;
	int in;
	cin >> in;
	
	int i = 0;
	while (i < in - 1) {
		i++;
		d = d->next;
	}
	//��ӡѡ��������IP���������롢�㲥��ַ��������ΪĬ�������·�ɱ���
	for (a = d->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			cout << "IP��ַ��";
			printIP((((sockaddr_in*)a->addr)->sin_addr).s_addr);
			cout <<endl<< "�������룺";
			printIP((((sockaddr_in*)a->netmask)->sin_addr).s_addr);
			cout << endl << "�㲥��ַ��";
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
			additem(rt, rt_length, temp);//������Ϣ��ΪĬ��·��
		}
	}



	char errbuf1[PCAP_ERRBUF_SIZE];
	pcap_t* p;//��¼����pcap_open()�ķ���ֵ���������

	p = pcap_open(d->name, 1500, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf1);//������

	int count = 1;
	//���ӻ�ɾ��·�ɱ���
	while (true) {
		ULONG NetMask, DesNet, NextHop;
		char* netmask = new char[20];
		char* desnet = new char[20];
		char* nexthop = new char[20];
		bool flags = 1;//��־λ��Ϊ0ʱֹͣ�޸�·�ɱ�
		if (count == 0) {
			cout << "�˳�(1),����(0)";
			int control;
			cin >> control;
			if (control) {
				break;
			}
		}
		else {
			count--;
		}
		cout << "����yes��·�ɱ���в��� " << endl;
		string ch1;
		cin >> ch1;
		if (ch1 != "yes")
		{
			flags = 0;
			cout << "·�ɱ�����:" << endl;
			print_rt(rt, rt_length);
		}
		while (flags)
		{
			
			
			cout << "��ʾ(2) ��ӣ�1�� ɾ����0��" << endl;
			int operate;
			cin >> operate;

			if (operate == 1)
			{
				cout << "������·�ɱ���" << endl;
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
				cout << "����1������ӣ�����0ֹͣ���" << endl;
				print_rt(rt, rt_length);//��ӡ·�ɱ�
				cin >> operate2;
				if (operate2 == 0)
				{
					flags = 0;
					cout << "·�ɱ�����:" << endl;
					print_rt(rt, rt_length);
					break;
				}

			}
			else if (operate == 0)
			{
				int index;
				cout << "������Ҫɾ���ı���" << endl;
				cin >> index;//���±�0��ʼ
				deleteitem(rt, rt_length, index);
				int operate2;
				cout << "����1������ӣ�����0ֹͣ���" << endl;
				cin >> operate2;
				if (operate2 == 0)
				{
					flags = 0;
					cout << "·�ɱ�����:" << endl;
					print_rt(rt, rt_length);
					break;
				}

			}
			else if (operate == 2) {
				cout << "·�ɱ�����" << endl;
				print_rt(rt, rt_length);
			}
		}

		//��ȡ������MAC
		BYTE scrMAC[6];
		ULONG scrIP;
		for (i = 0; i < 6; i++)
		{
			scrMAC[i] = 0x66;
		}
		scrIP = inet_addr("112.112.112.112");//����IP


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

		//ҪĬ�Ϸ����ɹ�  ��Ȼ�����
		/*if (ret_send)
		{
			cout << "���Լ�����ʧ��" << endl;
		}*/
		//else
		//{
		cout << "��ȡ����MAC" << endl;


		//�ػ��Լ���MAC
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
					cout << "����IP:";
					printIP(ARPFrame1->SendIP);
					cout << endl;

					cout << "����MAC:" << *(Byte2Hex(ARPFrame1->SendHa, 6)) << endl;
					for (int i = 0; i < 6; i++)
					{
						my_mac[i] = ARPFrame1->SendHa[i];

					}
					flag = 1;

				}

			}

		}
		//}


	

		//��ȡĿ��macΪ����mac��Ŀ��ip�Ǳ���ip��ip���ݱ�

		ULONG nextIP;//·�ɵ���һվ
		flag = 0;

		IPData_t* IPPacket;


		pcap_pkthdr* pkt_header = new pcap_pkthdr[1500];
		const u_char* pkt_data;
		//�����հ�
		while (1)
		{
			//���ݰ��Ļ�ȡ
			int ret;
			ret = pcap_next_ex(p, &pkt_header, &pkt_data);//�ڴ򿪵�����ӿڿ��ϻ�ȡ�������ݰ�
			if (ret)
			{
				//cout << "���ݰ�len:" << pkt_header->len << endl;
				WORD RecvChecksum;
				WORD FrameType;

				IPPacket = (IPData_t*)pkt_data;

				ULONG Len = pkt_header->len + sizeof(FrameHeader_t);//���ݰ���С����֡���ݲ��ֳ��Ⱥ�֡�ײ�����
				u_char* sendAllPacket = new u_char[Len];
				for (i = 0; i < Len; i++)
				{
					sendAllPacket[i] = pkt_data[i];
				}

				RecvChecksum = IPPacket->IPHeader.Checksum;
				IPPacket->IPHeader.Checksum = 0;
				FrameType = IPPacket->FrameHeader.FrameType;
				bool desmac_equal = 1;//Ŀ��mac��ַ�뱾��mac��ַ�Ƿ���ͬ����ͬΪ1��
				for (int i = 0; i < 6; i++)
				{
					if (my_mac[i] != IPPacket->FrameHeader.DesMac[i])
					{
						desmac_equal = 0;
					}
				}
				bool desIP_equal = 0;//Ŀ��IP�뱾��IP�Ƿ���ͬ������ͬΪ1��
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

				if (Is_ipv4 && desmac_equal && desIP_equal)//����Ŀ��IP���Ǳ���IP��Ŀ��MACΪ����MAC��IPv4�� 
				{
					cout << endl<<"ת����" << endl;

					int version = (IPPacket->IPHeader.Ver_HLen & 0xf0) >> 4;
					int headlen = (IPPacket->IPHeader.Ver_HLen & 0x0f);
					int tos = IPPacket->IPHeader.TOS;//��������

					int totallen = ntohs(IPPacket->IPHeader.TotalLen);//���ݰ��ܳ���

					int id = ntohs(IPPacket->IPHeader.ID);//��ʶ
					int ttl = IPPacket->IPHeader.TTL;
					int protocol = IPPacket->IPHeader.Protocol;



					cout << "�汾��" << version << endl;
					cout << "ͷ���ȣ�" << headlen << endl;
					cout << "tos��" << dec << tos << endl;
					cout << "�ܳ��ȣ�" << dec << totallen << endl;
					cout << "��ʶ��" << "0x" << id << endl;
					cout << "��������" << dec << ttl << endl;
					cout << "Э�飺" << dec << protocol << endl;

					cout << "���ݰ�Դ��ַ��";
					printIP(IPPacket->IPHeader.SrcIP);
					cout << endl;
					cout << "���ݰ�Ŀ�ĵ�ַ��";
					printIP(IPPacket->IPHeader.DstIP);
					cout << endl <<endl;

					//ѡ·Ͷ��
					nextIP = search(rt, rt_length, IPPacket->IPHeader.DstIP);
					
					cout << "��һ��:";
					printIP(nextIP);
					cout << endl;
					if (nextIP == 0)
					{
						nextIP = IPPacket->IPHeader.DstIP;
					}
					else if (nextIP == 0xffffffff)
					{
						cout << "�����������ð�" << endl;
					}

					flag = 1;



					//����һ������arp��ȡMAC��ַ

					memcpy(&scrMAC, &my_mac, 6);
					scrIP = my_ip;
					//��ȡ��һ����mac��ַ

					targetIP = nextIP;

					//��װARP��
					SET_ARP_DEST(ARPFrame, scrIP, targetIP, scrMAC);
					int send_ret = pcap_sendpacket(p, (u_char*)&ARPFrame, sizeof(ARPFrame_t));


					
					cout << "�����ɹ�" << endl;


					//�ػ�����MAC

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
								cout << "��һ����MAC��ַ:" << *(Byte2Hex(ARPFrame2->SendHa, 6)) << endl;
								memcpy(&its_mac, &ARPFrame2->FrameHeader.SrcMac, 6);
								flag1 = 1;
								cout << "��һ����IP:";
								printIP(ARPFrame2->SendIP);
								cout << endl;
							}
						}

					}

					//}




	
	
					//ת����
					IPData_t* TempIP;
					TempIP = (IPData_t*)sendAllPacket;
					
					memcpy(&TempIP->FrameHeader.DesMac, &its_mac, 6);
					memcpy(&TempIP->FrameHeader.SrcMac, &my_mac, 6);
					if (!pcap_sendpacket(p, sendAllPacket, Len))
					{
						cout << endl;
						cout << "���ת��" << endl;
						IPData_t* t;
						t = (IPData_t*)sendAllPacket;
						cout << "ԴIP��ַ��";
						printIP(t->IPHeader.SrcIP);
						cout << endl;
						cout << "Դmac��ַ��" << *(Byte2Hex(t->FrameHeader.SrcMac, 6)) << endl;
						cout << endl;
						cout << "Ŀ��IP��ַ��";
						printIP(t->IPHeader.DstIP);
						cout << endl;

						cout << "Ŀ��mac��ַ��"<< *(Byte2Hex(t->FrameHeader.DesMac, 6)) << endl;
						
					}


				}
			}
			if (_kbhit()) {//���������հ����½���·�ɱ�༭
				// ��ȡ��������
				char ch = _getch();

				// �����������
				if (ch == 'q' || ch == 'Q') {
					// ��������� 'q' �� 'Q'���˳�ѭ��
					break;
					
				}
				
				else {
					// ������������
					cout << "�㰴���˼���" << ch << endl;
				}
			}
		}
		
	}
	
	cout << "����" << endl;
	pcap_freealldevs(alldevs);//�ͷ��豸�б�
	return 0;

}








