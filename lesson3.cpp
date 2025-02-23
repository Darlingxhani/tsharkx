#include"printjson.h"
#include<fstream>
struct PcapHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

// 每一个数据报文前面的头
struct PacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
};
int main()
{

    std::ifstream file("E:\\Pcap\\capture.pcap",std::ios::binary);
    if(!file) {
        std::cerr<<"file not found\n";
        return 1;
    }
    // 读取pcap头
    PcapHeader pcapHeader;
    file.read(reinterpret_cast<char*>(&pcapHeader), sizeof(PcapHeader));
    while(file) {
        PacketHeader packetHeader;
        file.read(reinterpret_cast<char*>(&packetHeader), sizeof(PacketHeader));
        if(!file) {
            break;
        }
        std::vector<unsigned char> packetData(packetHeader.caplen);
        file.read(reinterpret_cast<char*>(packetData.data()), packetHeader.caplen);
        printf("数据包[时间：%d  长度：%d]:", packetHeader.ts_sec, packetHeader.caplen);
        for (unsigned char byte :packetData) {
            printf("%02X ", byte);
        }
        std::cout << "\n";
    }
    file.close();
    return 0;
}