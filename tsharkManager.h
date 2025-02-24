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
#include<algorithm>

class TsharkManager {

public:
    TsharkManager(std::string workDir);
    ~TsharkManager();

    std::vector<AdapterInfo> getNetworkAdapters();

    // 分析数据包文件
    bool analysisFile(std::string filePath);

    // 打印所有数据包的信息
    void printAllPackets();

    // 获取指定编号数据包的十六进制数据
    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char> &data);

private:
    // 解析每一行
    bool parseLine(std::string line, std::shared_ptr<Packet> packet);

private:

    std::string tsharkPath;

    // 当前分析的文件路径
    std::string currentFilePath;

    // 分析得到的所有数据包信息，key是数据包ID，value是数据包信息指针，方便根据编号获取指定数据包信息
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;
};
