#include "tshark_datatype.h"
#include "third_library/rapidjson/document.h"
#include "third_library/rapidjson/writer.h"
#include "third_library/rapidjson/prettywriter.h"
#include "third_library/rapidjson/stringbuffer.h"
#include "third_library/ip2region/ip2region_util.h"
#include "third_library/loguru/loguru.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include<unordered_map>
#include<ctime>
#include<thread>
#include<algorithm>
#include <pthread.h>
class TsharkManager {

public:
    TsharkManager(std::string Workdir);
    ~TsharkManager();

    std::vector<AdapterInfo> getNetworkAdapters();

    // 分析数据包文件
    bool analysisFile(std::string filePath);

    // 打印所有数据包的信息
    void printAllPackets();

    // 获取指定编号数据包的十六进制数据

    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char> &data);

	// 开始抓包
	bool startCapture(std::string adapterName);

	// 停止抓包
	bool stopCapture();	


    std::string pcappath = "E:\\Pcap\\capture1.pcap";


private:
    // 解析每一行
    bool parseLine(std::string line, std::shared_ptr<Packet> packet);

private:

    std::string tsharkPath="F:\\CTFMisc_tool\\Misc_tool\\Wireshark-4.2.4-x64\\Wireshark\\tshark.exe";

    // 当前分析的文件路径
    std::string currentFilePath;

    // 分析得到的所有数据包信息，key是数据包ID，value是数据包信息指针，方便根据编号获取指定数据包信息
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;

private:
    // 在线采集数据包的工作线程
    void captureWorkThreadEntry(std::string adapterName);

    // 在线分析线程
    std::shared_ptr<std::thread> captureWorkThread;

    // 是否停止抓包的标记
    bool stopFlag;

};