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
#include <unordered_map>
#include <ctime>
#include <thread>
#include <pthread.h>
#include <windows.h>
#include <map>
#include <mutex>

#ifdef _WIN32
typedef uint32_t  PID_T;
#else
typedef pid_t PID_T;
#endif

class TsharkManager {

public:
    TsharkManager(std::string Workdir);
    ~TsharkManager();
    std::vector<AdapterInfo> getNetworkAdapters();


    // 工作目录 
    std::string workdir;
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

    // 抓包的存储位置
    std::string pcappath = "E:\\Pcap\\capture1.pcap";
  
    class AdapterMonitorInfo {
        public:
            AdapterMonitorInfo() {
                monitorTsharkPipe = nullptr;
                tsharkPid = 0;
            }
            std::string adapterName;                            // 网卡名称
            std::map<long, long> flowTrendData;                 // 流量趋势数据
            std::shared_ptr<std::thread> monitorThread;         // 负责监控该网卡输出的线程
            FILE* monitorTsharkPipe;                            // 线程与tshark通信的管道
            PID_T tsharkPid;                                    // 负责捕获该网卡数据的tshark进程PID
    };
      
    // 停止监控所有网卡流量统计数据
    void startMonitorAdaptersFlowTrend();
    
    // 获取指定网卡的流量趋势数据
    void adapterFlowTrendMonitorThreadEntry(std::string adapterName);
    
    // 停止监控所有网卡流量统计数据
    void stopMonitorAdaptersFlowTrend();

        // 获取所有网卡流量统计数据
    void getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData);

    
    bool getPacketDetailInfo(uint32_t frameNumber, std::string &result);

private:
    // 解析每一行
    bool parseLine(std::string line, std::shared_ptr<Packet> packet);
    // tshark.exe的路径
    std::string tsharkPath="F:\\CTFMisc_tool\\Misc_tool\\Wireshark-4.2.4-x64\\Wireshark\\tshark.exe";

    // 当前分析的文件路径
    std::string currentFilePath;
public:
    // 分析得到的所有数据包信息，key是数据包ID，value是数据包信息指针，方便根据编号获取指定数据包信息
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;

private:
    // 在线采集数据包的工作线程
    void captureWorkThreadEntry(std::string adapterName);

    // 在线分析线程
    std::shared_ptr<std::thread> captureWorkThread;

    // 是否停止抓包的标记
    bool stopFlag;

    // 在线抓包的tshark进程PID
    PID_T captureTsharkPid = 0;
private:
    // 访问上面流量趋势数据的锁
    std::recursive_mutex adapterFlowTrendMapLock;
    
    // 后台流量趋势监控信息
    std::map<std::string, AdapterMonitorInfo> adapterFlowTrendMonitorMap;

    long adapterFlowTrendMonitorStartTime = 0;

    std::string editcapPath="F:\\CTFMisc_tool\\Misc_tool\\Wireshark-4.2.4-x64\\Wireshark\\editcap.exe";

};