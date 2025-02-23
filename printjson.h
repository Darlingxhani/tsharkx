#include "third_library/rapidjson/document.h"
#include "third_library/rapidjson/writer.h"
#include "third_library/rapidjson/prettywriter.h"
#include "third_library/rapidjson/stringbuffer.h"
#include <iostream>
#include<cstdio>
#include<iostream>
#include<string>
#include<sstream>
#include<vector>
#include<fstream>
struct Packet{
    int frame_number;
    std::string time;
    uint32_t cap_len;
    std::string src_ip;
    std::string src_location;
    uint16_t src_port;
    std::string dst_ip;
    std::string dst_location;
    uint16_t dst_port;
    std::string protocol;
    std::string info;
    uint32_t file_offset;  
};
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
void printPacket(const Packet &packet) {

    // 构建JSON对象
    rapidjson::Document pktObj;
    rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();

    // 设置JSON为Object对象类型
    pktObj.SetObject();

    // 添加JSON字段
    pktObj.AddMember("frame_number", packet.frame_number, allocator);
    pktObj.AddMember("timestamp", rapidjson::Value(packet.time.c_str(), allocator), allocator);
    pktObj.AddMember("cap_len", packet.cap_len, allocator);
    pktObj.AddMember("src_ip", rapidjson::Value(packet.src_ip.c_str(), allocator), allocator);
    pktObj.AddMember("src_location", rapidjson::Value(packet.src_location.c_str(), allocator), allocator);
    pktObj.AddMember("src_port", packet.src_port, allocator);
    pktObj.AddMember("dst_ip", rapidjson::Value(packet.dst_ip.c_str(), allocator), allocator);
    pktObj.AddMember("dst_location", rapidjson::Value(packet.dst_location.c_str(), allocator), allocator);
    pktObj.AddMember("dst_port", packet.dst_port, allocator);
    pktObj.AddMember("protocol", rapidjson::Value(packet.protocol.c_str(), allocator), allocator);
    pktObj.AddMember("info", rapidjson::Value(packet.info.c_str(), allocator), allocator);
    
    // 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    pktObj.Accept(writer);

    // 打印JSON输出
    std::cout << buffer.GetString() << std::endl;
}
// #ifdef _WIN32
// #include <windows.h>
// // UTF-8转ANSI
// static std::string UTF8ToANSIString(const std::string& utf8Str) {
//     // 获取UTF-8字符串的长度
//     int utf8Length = static_cast<int>(utf8Str.length());

//     // 将UTF-8转换为宽字符（UTF-16）
//     int wideLength = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), utf8Length, nullptr, 0);
//     std::wstring wideStr(wideLength, L'\0');
//     MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), utf8Length, &wideStr[0], wideLength);

//     // 将宽字符（UTF-16）转换为ANSI
//     int ansiLength = WideCharToMultiByte(CP_ACP, 0, wideStr.c_str(), wideLength, nullptr, 0, nullptr, nullptr);
//     std::string ansiStr(ansiLength, '\0');
//     WideCharToMultiByte(CP_ACP, 0, wideStr.c_str(), wideLength, &ansiStr[0], ansiLength, nullptr, nullptr);

//     return ansiStr;
// }
// #endif