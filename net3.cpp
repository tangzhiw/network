#include "pcap.h"
#include <iostream>
#include <WinSock2.h>
#include <bitset>
#include <process.h>
using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)


//将地址转换为16进制字符串类型
string* Byte2Hex(unsigned char bArray[], int bArray_len)
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



#pragma pack(1)
#define BYTE unsigned char

//帧首部
typedef struct FrameHeader_t {
    BYTE DesMAC[6]; //源MAC地址
    BYTE SrcMAC[6]; //目的MAC地址
    WORD FrameType; //帧类型
}FrameHeader_t;

//ARP帧
typedef struct ARPFrame_t {
    FrameHeader_t FrameHeader; //帧首部
    WORD HardwareType; //硬件类型
    WORD ProtocolType; //协议类型
    BYTE HLen;//硬件地址长度
    BYTE PLen;//协议地址长度
    WORD Operation;//操作类型
    BYTE SendHa[6];//源MAC地址
    DWORD SendIP;//源IP地址
    BYTE RecvHa[6];//目的MAC地址
    DWORD RecvIP;//目的IP地址
}ARPFrame_t;


#pragma pack()
ARPFrame_t ARPFrame;//要发送的APR数据包(其他主机）
ARPFrame_t ARPF_Send;//要发送的APR数据包（本机）
unsigned char mac[44], desmac[44];//目的主机和其他主机的mac

//
void ARP_show(struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct ARPFrame_t* arp;
    arp = (struct ARPFrame_t*)(pkt_data);
    in_addr source, aim;
    memcpy(&source, &arp->SendIP, sizeof(in_addr));
    memcpy(&aim, &arp->RecvIP, sizeof(in_addr));
    cout << "源MAC地址：  " << *(Byte2Hex(arp->FrameHeader.SrcMAC, 6)) << endl;
    cout << "源IP地址：   " << inet_ntoa(source) << endl;
    cout << "目的MAC地址：" << *(Byte2Hex(arp->FrameHeader.DesMAC, 6)) << endl;
    cout << "目的IP地址  " << inet_ntoa(aim) << endl;
    cout << endl;
}

//获取本机网络接口的MAC地址和IP地址
void printAddressInfo(const pcap_addr_t* a) {
    char str[INET_ADDRSTRLEN];

    if (a->addr->sa_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in*)a->addr)->sin_addr, str, sizeof(str));
        std::cout << "IP地址：" << str << std::endl;

        inet_ntop(AF_INET, &((struct sockaddr_in*)a->netmask)->sin_addr, str, sizeof(str));
        std::cout << "网络掩码：" << str << std::endl;

        inet_ntop(AF_INET, &((struct sockaddr_in*)a->broadaddr)->sin_addr, str, sizeof(str));
        std::cout << "广播地址：" << str << std::endl;
    }
}
//循环打印设备信息
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

    pcap_if_t* alldevs = getInterfaceList();//指向设备链表首部的指针
    pcap_if_t* d;
    pcap_addr_t* a;
    if (alldevs != NULL) {

        printInterfaceList(alldevs);
    }
    char errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区

    cout << endl << endl;

    //设备链表首部的指针
    d = alldevs;

    int j;
    cout << "请选择发送数据包的网卡：";
    cin >> j;
    int i = 0;
    //获取指向选择发送数据包网卡的指针

    while (i < j - 1) {
        i++;
        d = d->next;
    }


    //打开用户选择设备的网卡
    pcap_t* dev = pcap_open(d->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);


    //保存网卡的ip地址（指向缓冲区的指针，用于存储 IP 地址的 NULL 终止字符串表示形式。）
    char ip[INET_ADDRSTRLEN];


    for (a = d->addresses; a != NULL; a = a->next) {
        //判断该地址是否为IP地址
        if (a->addr->sa_family == AF_INET) {
            //二进制IP地址转换为文本形式的IP地址
            inet_ntop(AF_INET, &((struct sockaddr_in*)a->addr)->sin_addr, ip, sizeof(ip));
        }
    }
    cout << ip;
    cout << endl << d->description << endl;

    //获取本机的MAC地址

    //设置ARP帧相关
    SET_ARP_HOST(ARPF_Send, ip);

    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    struct pcap_pkthdr* header = new pcap_pkthdr;
    int k;
    //发送构造好的数据包
    //pcap_next_ex()捕获数据包
    while ((k = pcap_next_ex(dev, &pkt_header, &pkt_data)) >= 0) {
        //发送数据包

        pcap_sendpacket(dev, (u_char*)&ARPF_Send, sizeof(ARPFrame_t));
        struct ARPFrame_t* arp_message;
        arp_message = (struct ARPFrame_t*)(pkt_data);
        if (k == 1)

        {   //帧类型为ARP，且操作类型为ARP响应，SendIp为发送的数据包中的RecvIP

            if (arp_message->FrameHeader.FrameType == htons(0x0806) && arp_message->Operation == htons(0x0002)) {
                cout << "ARP数据包：\n";
                ARP_show(header, pkt_data);//打印相应的信息
                //用MAC地址记录本机的MAC地址，用于后续构造ARP数据包
                memcpy(mac, &(pkt_data[22]), 6);
                cout << "本机MAC：" << *(Byte2Hex(mac, 6)) << endl;
                break;
            }
        }
    }

    if (k < 0) {
        cout << "Error in pcap_next_ex." << endl;
    }
    cout << endl;

    //设置ARP帧

    SET_ARP_DEST(ARPFrame, ip, mac);

    cout << "请输入目的主机的IP地址：";
    char desip[INET_ADDRSTRLEN];
    cin >> desip;
    ARPFrame.RecvIP = inet_addr(desip); //设置为请求的IP地址

    while ((k = pcap_next_ex(dev, &pkt_header, &pkt_data)) >= 0) {

        pcap_sendpacket(dev, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
        struct ARPFrame_t* arp_message;
        arp_message = (struct ARPFrame_t*)(pkt_data);
        if (k == 0)continue;
        else

            if (arp_message->FrameHeader.FrameType == htons(0x0806) && arp_message->Operation == htons(0x0002) && *(unsigned long*)(pkt_data + 28) == ARPFrame.RecvIP) {
                cout << "ARP数据包：\n";
                ARP_show(header, pkt_data);
                memcpy(desmac, &(pkt_data[22]), 6);
                cout << "目的主机的MAC：" << *(Byte2Hex(desmac, 6)) << endl;
                break;
            }
    }
    pcap_freealldevs(alldevs);
    system("pause");
}