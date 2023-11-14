//#include <iostream>
//#include <pcap.h>
//using namespace std;
//
//int main() {
//    char err[PCAP_ERRBUF_SIZE];
//    pcap_if_t* alldevs;
//
//    if (pcap_findalldevs(&alldevs, err) == -1) {
//        cout << "Error in pcap_findalldevs: " << err << endl;
//        return 1;
//    }
//    for (pcap_if_t* device = alldevs; device != NULL; device = device->next) {
//        cout << "Device Name: " << device->name << std::endl;
//        if (device->description)
//           cout << "Description: " << device->description << endl;
//        cout << endl;
//    }
//    pcap_freealldevs(alldevs);
//    return 0;
//}





//#include <pcap.h>
//using namespace std;
//#include<iostream>
//int main() {
//    char errbuf[PCAP_ERRBUF_SIZE];//���Խ��ܴ�����Ϣ
//    const char* deviceName = "\\Device\\NPF_{A456CE68-5523-481A-820C-EFE500CE411E}";//��IPv6 ����ͨ�ŵ� WAN Miniport �豸���в���
//    pcap_t* dev;
//
//    dev = pcap_open_live(deviceName, 65535, 1, 1000, errbuf);
//
//    if (dev == NULL) {
//        cout<<"Could not open" <<deviceName;
//        return 1;
//    }
//    else {
//        cout << "you succeed";
//    }
//    // �ɹ��������豸�����Կ�ʼ�������ݰ�
//
//    pcap_close(dev);
//    
//    return 0;
//}





//#include <pcap.h>
//#include <iostream>
//
//int main() {
//    int device_num = 0;
//    pcap_if_t* alldevs;
//    char err[PCAP_ERRBUF_SIZE]; // ���Խ��ܴ�����Ϣ
//
//    if (pcap_findalldevs(&alldevs, err) == -1) {
//        std::cerr << "Error in pcap_findalldevs: " << err << std::endl;
//        return 1;
//    }
//
//    for (pcap_if_t* device = alldevs; device != nullptr; device = device->next) {
//        std::cout << "Device Name: " << device->name << std::endl;
//        device_num++;
//        if (device->description)
//            std::cout << "Description: " << device->description << std::endl;
//        std::cout << std::endl;
//    }
//    std::cout << "Total devices: " << device_num << std::endl;
//
//    int device_number;
//    std::cout << "������Ҫ���ҵ��豸: ";
//    std::cin >> device_number;
//
//    if (device_number >= device_num) {
//        std::cerr << "��Ч���豸���" << std::endl;
//        pcap_freealldevs(alldevs);
//        return 1;
//    }
//    pcap_if_t* device = alldevs;
//    for (int i = 0; i < device_number; i++) {
//        device = device->next;
//    }
//    pcap_t* handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, err);
//    while (true) {
//        struct pcap_pkthdr* header;
//        const u_char* packet;
//        int result = pcap_next_ex(handle, &header, &packet);
//        if (result == 1) {
//            std::cout << "===== Got a packet with length of " << header->len << " =====" << std::endl;
//            // ��ӡ���ݰ��ļ�Ҫ��Ϣ
//            for (int i = 0; i < header->len; i++) {
//                std::cout << std::hex << (int)packet[i] << " ";
//            }
//            std::cout << std::endl;
//        }
//        else if (result == 0) {
//            // δ�յ����ݰ�����������
//        }
//        else if (result == -1) {
//            std::cerr << "pcap_next_ex error: " << pcap_geterr(handle) << std::endl;
//            break;
//        }
//        else if (result == -2) {
//            std::cerr << "����" << std::endl;
//            break;
//        }
//    }
//    pcap_freealldevs(alldevs);
//    pcap_close(handle);
//    return 0;
//}





#include<iostream>
#include "pcap.h"
#include <string>
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable : 4996)
using namespace std;

class Frame {
public:
    uint8_t DesMAC[6];  // Ŀ�ĵ�ַ
    uint8_t SrcMAC[6];  // Դ��ַ
    uint16_t FrameType; // ֡����
};

class IPHead {
public:
    uint8_t Ver_HLen;      // IPЭ��汾��IP�ײ�����
    uint16_t TotalLen;     // �ܳ���
    uint8_t TTL;           // ��������
    uint8_t Protocol;      // Э��
    uint16_t Checksum;     // ͷ��У���
    uint32_t SrcIP;        // ԴIP
    uint32_t DstIP;        // Ŀ��IP
};

class Data {
public:
    Frame FrameHeader;
    IPHead IPHeader;
};



void PacketHandle(u_char*, const struct pcap_pkthdr*, const u_char*);
void IP_Packet_Handle(const struct pcap_pkthdr*, const u_char*);

int main()
{
	pcap_if_t* devs;//ָ���豸�����ײ���ָ��
	pcap_if_t* f;
	char err[PCAP_ERRBUF_SIZE];	//������Ϣ������
	int device_num = 0;//�ӿ�����
	int n;
	int read_count;
	//��ñ������豸�б�
	if (pcap_findalldevs(&devs, err) ==  -1)
	{
		//������
		cout << "������Ϣ" << err << endl;
		pcap_freealldevs(devs);
		return 0;
	}
	//��ʾ�ӿ��б�
	for (f = devs; f != NULL; f = f->next)
	{
		device_num++;
		cout << dec << device_num << ":" << f->name << endl;
		if (f->description != NULL)
		{
			cout << f->description << endl;
		}
		else
		{
			return -1;
		}
	}
	cout << "�������豸��"    << endl;
	cin >> n;
	if (n > device_num) {
		cout << "�������" << endl;
		return -1;
	}
	device_num = 0;
	for (f = devs; device_num < (n - 1); device_num++)
	{
		f = f->next;
	}
	pcap_t* handle;
	handle = pcap_open_live(f->name,65536,1,1000,NULL);
	if (handle == NULL)
	{
		cout << "���豸ʧ��" << endl;
		pcap_freealldevs(devs);
		return 0;
	}
	
	
	pcap_loop(handle, 5, (pcap_handler)PacketHandle, NULL);
	pcap_close(handle);
	return 0;
}

void PacketHandle(u_char* argunment, const struct pcap_pkthdr* pkt_head, const u_char* pkt_data)
{
	Frame* ethernet_protocol;		//��̫��Э��
	u_short ethernet_type;		//��̫������
	u_char* mac_addr;			//��̫����ַ
	//��ȡ��̫����������
	ethernet_protocol = (Frame*)pkt_data;
	ethernet_type = ntohs(ethernet_protocol->FrameType);
	printf("��̫������ :\t");
	printf("%04x\n", ethernet_type);
	switch (ethernet_type)
	{
	case 0x0800:
		printf("IPv4\n");
		break;
	case 0x0806:
		printf("ARP\n");
		break;
	case 0x8035:
		printf("RARP\n");
		break;
	default:
		cout << "unknown" << endl;
		break;
	}
	mac_addr = ethernet_protocol->SrcMAC;
	printf("MacԴ��ַ��\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",
		mac_addr[0],
		mac_addr[1],
		mac_addr[2],
		mac_addr[3],
		mac_addr[4],
		mac_addr[5]
	);
	mac_addr = ethernet_protocol->DesMAC;
	printf("MacĿ�ĵ�ַ��\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",
		mac_addr[0],
		mac_addr[1],
		mac_addr[2],
		mac_addr[3],
		mac_addr[4],
		mac_addr[5]
	);
	
		IP_Packet_Handle(pkt_head, pkt_data);
	
}

void IP_Packet_Handle(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	IPHead* IPHeader;
	IPHeader = (IPHead*)(pkt_data + 14);//IP����������ԭ������֡��14�ֽڿ�ʼ
	sockaddr_in source, dest;
	char sourceIP[16], destIP[16];
	source.sin_addr.s_addr = IPHeader->SrcIP;
	dest.sin_addr.s_addr = IPHeader->DstIP;
	strncpy(sourceIP, inet_ntoa(source.sin_addr), 16);
	strncpy(destIP, inet_ntoa(dest.sin_addr), 16);
	cout << "�汾��" << (IPHeader->Ver_HLen >> 4) << endl;
	cout << "IPЭ���ײ����ȣ�" << (IPHeader->Ver_HLen & 0x0f) * 4 << " Bytes" << endl;
	cout << "�ܳ��ȣ�" << ntohs(IPHeader->TotalLen) << endl;
	cout << "����ʱ�䣺" << IPHeader->TTL << endl;
	cout << "Э��ţ�" << static_cast<int>(IPHeader->Protocol) << endl;
	cout << "Э�����ࣺ";
	switch (IPHeader->Protocol)
	{
	case 1:
		printf("ICMP\n");
		break;
	case 2:
		printf("IGMP\n");
		break;
	case 6:
		printf("TCP\n");
		break;
	case 17:
		printf("UDP\n");
		break;
	default:
		break;
	}
	cout << "�ײ�����ͣ�0x" << std::hex  << ntohs(IPHeader->Checksum) << std::dec << std::endl;
	cout << "Դ��ַ��" << sourceIP << endl;
	cout << "Ŀ�ĵ�ַ��" << destIP << endl;
	cout << "==============" << endl;
}


