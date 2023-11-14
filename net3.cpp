#include "pcap.h"
#include <iostream>
#include <WinSock2.h>
#include <bitset>
#include <process.h>
using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)


//����ַת��Ϊ16�����ַ�������
string* Byte2Hex(unsigned char bArray[], int bArray_len)
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



#pragma pack(1)
#define BYTE unsigned char

//֡�ײ�
typedef struct FrameHeader_t {
    BYTE DesMAC[6]; //ԴMAC��ַ
    BYTE SrcMAC[6]; //Ŀ��MAC��ַ
    WORD FrameType; //֡����
}FrameHeader_t;

//ARP֡
typedef struct ARPFrame_t {
    FrameHeader_t FrameHeader; //֡�ײ�
    WORD HardwareType; //Ӳ������
    WORD ProtocolType; //Э������
    BYTE HLen;//Ӳ����ַ����
    BYTE PLen;//Э���ַ����
    WORD Operation;//��������
    BYTE SendHa[6];//ԴMAC��ַ
    DWORD SendIP;//ԴIP��ַ
    BYTE RecvHa[6];//Ŀ��MAC��ַ
    DWORD RecvIP;//Ŀ��IP��ַ
}ARPFrame_t;


#pragma pack()
ARPFrame_t ARPFrame;//Ҫ���͵�APR���ݰ�(����������
ARPFrame_t ARPF_Send;//Ҫ���͵�APR���ݰ���������
unsigned char mac[44], desmac[44];//Ŀ������������������mac

//
void ARP_show(struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct ARPFrame_t* arp;
    arp = (struct ARPFrame_t*)(pkt_data);
    in_addr source, aim;
    memcpy(&source, &arp->SendIP, sizeof(in_addr));
    memcpy(&aim, &arp->RecvIP, sizeof(in_addr));
    cout << "ԴMAC��ַ��  " << *(Byte2Hex(arp->FrameHeader.SrcMAC, 6)) << endl;
    cout << "ԴIP��ַ��   " << inet_ntoa(source) << endl;
    cout << "Ŀ��MAC��ַ��" << *(Byte2Hex(arp->FrameHeader.DesMAC, 6)) << endl;
    cout << "Ŀ��IP��ַ  " << inet_ntoa(aim) << endl;
    cout << endl;
}

//��ȡ��������ӿڵ�MAC��ַ��IP��ַ
void printAddressInfo(const pcap_addr_t* a) {
    char str[INET_ADDRSTRLEN];

    if (a->addr->sa_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in*)a->addr)->sin_addr, str, sizeof(str));
        std::cout << "IP��ַ��" << str << std::endl;

        inet_ntop(AF_INET, &((struct sockaddr_in*)a->netmask)->sin_addr, str, sizeof(str));
        std::cout << "�������룺" << str << std::endl;

        inet_ntop(AF_INET, &((struct sockaddr_in*)a->broadaddr)->sin_addr, str, sizeof(str));
        std::cout << "�㲥��ַ��" << str << std::endl;
    }
}
//ѭ����ӡ�豸��Ϣ
void printInterfaceList(pcap_if_t* alldevs) {
    int n = 1;

    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        std::cout << n++ << "." << std::endl;

        if (d->description)
            std::cout << "(" << d->description << ")" << std::endl << std::endl;
        else
            std::cout << "(No description)\n";

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
        std::cerr << "Error in pcap_findalldevs_ex: " << errbuf << std::endl;
        return nullptr;
    }

    return alldevs;
}

void initializeMACAddress(unsigned char* address, unsigned char value) {
    for (int i = 0; i < 6; i++) {
        address[i] = value;
    }
}

void SET_ARP_HOST(ARPFrame_t& ARPFrame1, const char* ip) {
    initializeMACAddress(ARPFrame1.FrameHeader.DesMAC, 0xff);
    initializeMACAddress(ARPFrame1.FrameHeader.SrcMAC, 0x1f);
    initializeMACAddress(ARPFrame1.SendHa, 0x1f);
    initializeMACAddress(ARPFrame1.RecvHa, 0x00);

    ARPFrame1.FrameHeader.FrameType = htons(0x0806);
    ARPFrame1.HardwareType = htons(0x0001);
    ARPFrame1.ProtocolType = htons(0x0800);
    ARPFrame1.HLen = 6;
    ARPFrame1.PLen = 4;
    ARPFrame1.Operation = htons(0x0001);
    ARPFrame1.SendIP = inet_addr("192.168.120.110");
    ARPFrame1.RecvIP = inet_addr(ip);
}

void SET_ARP_DEST(ARPFrame_t& ARPFrame, const char* ip, const unsigned char* mac) {
    initializeMACAddress(ARPFrame.FrameHeader.DesMAC, 0xff);
    initializeMACAddress(ARPFrame.RecvHa, 0x00);
    memcpy(ARPFrame.FrameHeader.SrcMAC, mac, 6); // Set to the local network card's MAC address
    memcpy(ARPFrame.SendHa, mac, 6); // Set to the local network card's MAC address

    ARPFrame.FrameHeader.FrameType = htons(0x0806);
    ARPFrame.HardwareType = htons(0x0001);
    ARPFrame.ProtocolType = htons(0x0800);
    ARPFrame.HLen = 6;
    ARPFrame.PLen = 4;
    ARPFrame.Operation = htons(0x0001);
    ARPFrame.SendIP = inet_addr(ip);
}



int main() {

    pcap_if_t* alldevs = getInterfaceList();//ָ���豸�����ײ���ָ��
    pcap_if_t* d;
    pcap_addr_t* a;
    if (alldevs != NULL) {

        printInterfaceList(alldevs);
    }
    char errbuf[PCAP_ERRBUF_SIZE];//������Ϣ������

    cout << endl << endl;

    //�豸�����ײ���ָ��
    d = alldevs;

    int j;
    cout << "��ѡ�������ݰ���������";
    cin >> j;
    int i = 0;
    //��ȡָ��ѡ�������ݰ�������ָ��

    while (i < j - 1) {
        i++;
        d = d->next;
    }


    //���û�ѡ���豸������
    pcap_t* dev = pcap_open(d->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);


    //����������ip��ַ��ָ�򻺳�����ָ�룬���ڴ洢 IP ��ַ�� NULL ��ֹ�ַ�����ʾ��ʽ����
    char ip[INET_ADDRSTRLEN];


    for (a = d->addresses; a != NULL; a = a->next) {
        //�жϸõ�ַ�Ƿ�ΪIP��ַ
        if (a->addr->sa_family == AF_INET) {
            //������IP��ַת��Ϊ�ı���ʽ��IP��ַ
            inet_ntop(AF_INET, &((struct sockaddr_in*)a->addr)->sin_addr, ip, sizeof(ip));
        }
    }
    cout << ip;
    cout << endl << d->description << endl;

    //��ȡ������MAC��ַ

    //����ARP֡���
    SET_ARP_HOST(ARPF_Send, ip);

    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    struct pcap_pkthdr* header = new pcap_pkthdr;
    int k;
    //���͹���õ����ݰ�
    //pcap_next_ex()�������ݰ�
    while ((k = pcap_next_ex(dev, &pkt_header, &pkt_data)) >= 0) {
        //�������ݰ�

        pcap_sendpacket(dev, (u_char*)&ARPF_Send, sizeof(ARPFrame_t));
        struct ARPFrame_t* arp_message;
        arp_message = (struct ARPFrame_t*)(pkt_data);
        if (k == 1)

        {   //֡����ΪARP���Ҳ�������ΪARP��Ӧ��SendIpΪ���͵����ݰ��е�RecvIP

            if (arp_message->FrameHeader.FrameType == htons(0x0806) && arp_message->Operation == htons(0x0002)) {
                cout << "ARP���ݰ���\n";
                ARP_show(header, pkt_data);//��ӡ��Ӧ����Ϣ
                //��MAC��ַ��¼������MAC��ַ�����ں�������ARP���ݰ�
                memcpy(mac, &(pkt_data[22]), 6);
                cout << "����MAC��" << *(Byte2Hex(mac, 6)) << endl;
                break;
            }
        }
    }

    if (k < 0) {
        cout << "Error in pcap_next_ex." << endl;
    }
    cout << endl;

    //����ARP֡

    SET_ARP_DEST(ARPFrame, ip, mac);

    cout << "������Ŀ��������IP��ַ��";
    char desip[INET_ADDRSTRLEN];
    cin >> desip;
    ARPFrame.RecvIP = inet_addr(desip); //����Ϊ�����IP��ַ

    while ((k = pcap_next_ex(dev, &pkt_header, &pkt_data)) >= 0) {

        pcap_sendpacket(dev, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
        struct ARPFrame_t* arp_message;
        arp_message = (struct ARPFrame_t*)(pkt_data);
        if (k == 0)continue;
        else

            if (arp_message->FrameHeader.FrameType == htons(0x0806) && arp_message->Operation == htons(0x0002) && *(unsigned long*)(pkt_data + 28) == ARPFrame.RecvIP) {
                cout << "ARP���ݰ���\n";
                ARP_show(header, pkt_data);
                memcpy(desmac, &(pkt_data[22]), 6);
                cout << "Ŀ��������MAC��" << *(Byte2Hex(desmac, 6)) << endl;
                break;
            }
    }
    pcap_freealldevs(alldevs);
    system("pause");
}