#include "tsharkManager.h"
#include "MiscUtil.h"
#include "ProcessUtil.h"
bool TsharkManager::parseLine(std::string line, std::shared_ptr<Packet> packet)
{

    if(line.back()=='\n') {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string filed;
    std::vector<std::string> fields;
    
    size_t start=0,end;
    while((end=line.find("\t",start)) != std::string::npos) {
        fields.push_back(line.substr(start,end-start));
        start=end+1;
    } 
    fields.push_back(line.substr(start));
    // while(std::getline(ss,filed,'\t')) {
    //     fields.push_back(filed);
    // }
    // 字段顺序：
    // 0: frame.number
    // 1: frame.time_epoch
    // 2: frame.len
    // 3: frame.cap_len
    // 4: eth.src
    // 5: eth.dst
    // 6: ip.src
    // 7: ipv6.src
    // 8: ip.dst
    // 9: ipv6.dst
    // 10: tcp.srcport
    // 11: udp.srcport
    // 12: tcp.dstport
    // 13: udp.dstport
    // 14: _ws.col.Protocol
    // 15: _ws.col.Info

    if(fields.size()>=16) {
        packet->frame_number = std::stoi(fields[0]);
        packet->time = packet->time = fields[1];
        packet->len = std::stoi(fields[2]);
        packet->cap_len = std::stoi(fields[3]);
        packet->src_mac = fields[4];
        packet->dst_mac = fields[5]; 
        packet->src_ip = fields[6].empty() ?fields[7]:fields[6];
        packet->dst_ip = fields[8].empty() ?fields[9]:fields[8];
        if(!fields[10].empty() || !fields[11].empty()) {
            packet->src_port = std::stoi(fields[11].empty()?fields[10]:fields[11]);
        }
        if(!fields[13].empty() || !fields[12].empty()) {
            packet->src_port = std::stoi(fields[13].empty()?fields[12]:fields[13]);
        }
        packet->protocol = fields[14];
        packet->info = fields[15];
        
        size_t  pos=packet->time.find('.');
        std::string secondsStr = packet->time.substr(0, pos); // 秒部分
        std::string microsecondsStr = packet->time.substr(pos + 1); // 微秒部分
        
        std::stringstream ss(secondsStr);
        time_t seconds;
        ss >> seconds;
    
        // 将微秒部分字符串截取前6位（微秒精度）
        microsecondsStr = microsecondsStr.substr(0, 6); // 只保留6位微秒
    
        // 将秒部分转换为本地时间
        std::tm* localTime = std::localtime(&seconds);
    
        // 格式化日期和时间部分
        char buffer[80];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localTime);
    
        // 拼接完整的日期时间字符串（包括微秒）
        packet->time = std::string(buffer) + "." + microsecondsStr;

        return true;
    } else {
        return false;
    }
}
bool TsharkManager::analysisFile(std::string filePath)
{
    std::vector<std::string> tsharkArgs = {
        tsharkPath,
        "-r", filePath,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "frame.cap_len",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    };
    
    std::string commod;

    for(auto arg : tsharkArgs) {
        commod += arg;
        commod += " ";
    }

    FILE *pipe = popen(commod.c_str(),"r");
    if (!pipe) {
        LOG_F(ERROR,"Failed to run tshark command!");
        return false;
    }

    char buffer[4096];
    std::vector<Packet> packets;
    uint32_t file_offset=sizeof(PcapHeader);
    while(fgets(buffer,sizeof(buffer),pipe)) {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();   
        parseLine(buffer,packet);

        packet->file_offset=file_offset+sizeof(PacketHeader);
        file_offset=packet->cap_len+packet->file_offset;
        // 计算地理位置
        packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
        packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);

        allPackets.insert(std::make_pair<>(packet->frame_number, packet));
    }
    
    pclose(pipe);

    // 记录当前分析的文件路径
    currentFilePath = filePath;


    return true;
}
void TsharkManager::printAllPackets() {

    for (auto pair : allPackets) {

        std::shared_ptr<Packet> packet = pair.second;
         
        // 构建JSON对象
        rapidjson::Document pktObj;
        rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();
        pktObj.SetObject();

        pktObj.AddMember("frame_number", packet->frame_number, allocator);
        pktObj.AddMember("timestamp", rapidjson::Value(packet->time.c_str(), allocator), allocator);
        pktObj.AddMember("src_mac", rapidjson::Value(packet->src_mac.c_str(), allocator), allocator);
        pktObj.AddMember("dst_mac", rapidjson::Value(packet->dst_mac.c_str(), allocator), allocator);
        pktObj.AddMember("src_ip", rapidjson::Value(packet->src_ip.c_str(), allocator), allocator);
        pktObj.AddMember("src_location", rapidjson::Value(packet->src_location.c_str(), allocator), allocator);
        pktObj.AddMember("src_port", packet->src_port, allocator);
        pktObj.AddMember("dst_ip", rapidjson::Value(packet->dst_ip.c_str(), allocator), allocator);
        pktObj.AddMember("dst_location", rapidjson::Value(packet->dst_location.c_str(), allocator), allocator);
        pktObj.AddMember("dst_port", packet->dst_port, allocator);
        pktObj.AddMember("protocol", rapidjson::Value(packet->protocol.c_str(), allocator), allocator);
        pktObj.AddMember("info", rapidjson::Value(packet->info.c_str(), allocator), allocator);
        pktObj.AddMember("file_offset", packet->file_offset, allocator);
        pktObj.AddMember("cap_len", packet->cap_len, allocator);
        pktObj.AddMember("len", packet->len, allocator);

        // 序列化为 JSON 字符串
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        pktObj.Accept(writer);

        
        LOG_F(INFO,buffer.GetString());

        //std::cout<<buffer.GetString()<<std::endl;

        getPacketHexData(packet->frame_number, packet->data);
        
        std::cout<<"Packet Hex Data: ";
        for(auto byte : packet->data) {
            printf("%02x ", byte);
        }   
        std::cout<<std::endl<<std::endl;
    }
    std::cout<<allPackets.size()<<std::endl;
    LOG_F(INFO,"%d packets have been printed.",allPackets.size());
}

bool TsharkManager::getPacketHexData(uint32_t frameNumber, std::vector<unsigned char> &data)
{
    std::shared_ptr<Packet> packet = allPackets.find(frameNumber)->second;
    std::ifstream file(currentFilePath, std::ios::binary);
    if(!file.is_open()) {
        return false;
    }
    file.seekg(packet->file_offset, std::ios::beg);
    data.resize(packet->cap_len);
    file.read(reinterpret_cast<char*>(data.data()), packet->cap_len);

    file.close();
    
    return true;
}

TsharkManager::TsharkManager(std::string config) {
    workdir = config;
    IP2RegionUtil ip2RegionUtil;
    ip2RegionUtil.init("../third_library/ip2region/ip2region.xdb");
}

TsharkManager::~TsharkManager() {

}
// 打印出网卡的信息
std::vector<AdapterInfo> TsharkManager::getNetworkAdapters()
{
    std::vector<std::string> others={"Event Tracing for Windows (ETW) reader",
        "蓝牙网络连接",
        "VMware Network Adapter VMnet","USBPcap"};
    std::vector<AdapterInfo> adapters;
    AdapterInfo adapter;
    std::string command = tsharkPath+" -D";
    FILE *pipe=popen(command.c_str(),"r");
    if(!pipe)
    {

        LOG_F(ERROR,"Adapter popen error");
        return std::vector<AdapterInfo>();
    }

    char buffer[4096];
    while(fgets(buffer,sizeof(buffer),pipe)) {
        std::string line(buffer);
        // 去除重复命令
        bool enflag=false;
        for(auto Other:others) {
            if((line.find(Other)!= std::string::npos)) {
                enflag=true;
                break;
            }
        }
        if(enflag) {
            continue;
        }
        size_t lflag = line.find('(');
        size_t rflag = line.find(')');
        size_t lflag2 = line.find('\\');
        if(lflag != std::string::npos && rflag != std::string::npos) {
            
            adapter.id = std::stoi(line.substr(0,2))? std::stoi(line.substr(0,2)) : std::stoi(line.substr(0,1));
            adapter.name = line.substr(lflag+1,rflag-lflag-1);
            adapter.remark = line.substr(lflag2,lflag-1-lflag2);
        }
        adapters.push_back(adapter);       
    }
    pclose(pipe);
    return adapters;
}
void TsharkManager::captureWorkThreadEntry(std::string adapterName)
{
    // 包的存储
    std::string captureFile = pcappath;
    
    std::vector<std::string> tsharkArgs = {
        tsharkPath,
        "-i", ("\""+adapterName+"\"").c_str(),
        "-w", captureFile,               // 默认将采集到的数据包写入到这个文件下
        "-F", "pcap",                    // 指定存储的格式为PCAP格式
        "-l",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "frame.cap_len",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    };

    std::string  command;

    for(auto arg : tsharkArgs) {
        command += arg + " ";
    }

    FILE *pipe = ProcessUtil::PopenEx(command.c_str(), &captureTsharkPid);
    if (!pipe) {
        LOG_F(ERROR,"Failed to run tshark command!");
        assert(false);
    }
    
    char buffer[4096];
    uint32_t file_offset = sizeof(PcapHeader);
    while(fgets(buffer, sizeof(buffer), pipe) != nullptr && !stopFlag) {
        std::string line=buffer;
        if (line.find("Capturing on") != std::string::npos) {
            continue;
        }
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();   
        parseLine(line,packet);

        packet->file_offset = sizeof(PacketHeader) + file_offset ;
        file_offset = packet->cap_len + packet->file_offset;

        // 获取地理位置
        packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
        packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);

        allPackets.insert(std::make_pair<>(packet->frame_number, packet));

    }

    pclose(pipe);
    currentFilePath = captureFile;
    return ;
}

bool TsharkManager::startCapture(std::string adapterName) {

    LOG_F(INFO, "即将开始抓包，网卡：%s", adapterName.c_str());

    // 关闭停止标记
    stopFlag = false;

	// 启动抓包线程
    captureWorkThread = std::make_shared<std::thread>(&TsharkManager::captureWorkThreadEntry, this,adapterName);
    return true;
}

// 停止抓包
bool TsharkManager::stopCapture() {

    LOG_F(INFO, "即将停止抓包");
    stopFlag = true;

    ProcessUtil::Kill(captureTsharkPid);
    captureWorkThread->join();

    return true;
}
// 获取指定网卡的流量趋势数据
void TsharkManager::adapterFlowTrendMonitorThreadEntry(std::string adapterName) {
    // adapterFlowTrendMonitorMap   map<adapterName(string), adapterFlowTrendMonitor(Class)>
    if (adapterFlowTrendMonitorMap.find(adapterName) == adapterFlowTrendMonitorMap.end()) {
        return;
    }

    char buffer[256] = { 0 };
    std::map<long, long>& trafficPerSecond = adapterFlowTrendMonitorMap[adapterName].flowTrendData;

    // Tshark命令，指定网卡，实时捕获时间戳和数据包长度
    std::string tsharkCmd = tsharkPath + " -i \"" + adapterName + "\" -T fields -e frame.time_epoch -e frame.len";

    LOG_F(INFO, "启动网卡流量监控: %s", tsharkCmd.c_str());

    PID_T tsharkPid = 0;
    FILE* pipe = ProcessUtil::PopenEx(tsharkCmd.c_str(), &tsharkPid);
    if (!pipe) {
        throw std::runtime_error("Failed to run tshark command.");
    }

    // 将管道保存起来
    adapterFlowTrendMapLock.lock();
    adapterFlowTrendMonitorMap[adapterName].monitorTsharkPipe = pipe;
    adapterFlowTrendMonitorMap[adapterName].tsharkPid = tsharkPid;
    adapterFlowTrendMapLock.unlock();

    // 逐行读取tshark输出
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::string line(buffer);
        std::istringstream iss(line);
        std::string timestampStr, lengthStr;

        if (line.find("Capturing") != std::string::npos || line.find("captured") != std::string::npos) {
            continue;
        }

        // 解析每行的时间戳和数据包长度
        if (!(iss >> timestampStr >> lengthStr)) {
            continue;
        }

        try {
            // 转换时间戳为long类型，秒数部分
            long timestamp = static_cast<long>(std::stod(timestampStr));

            // 转换数据包长度为long类型
            long packetLength = std::stol(lengthStr);

            // 每秒的字节数累加
            trafficPerSecond[timestamp] += packetLength;

            // 如果trafficPerSecond超过300秒，则删除最早的数据，始终只存储最近300秒的数据
            while (trafficPerSecond.size() > 300) {
                // 访问并删除最早的时间戳数据
                auto it = trafficPerSecond.begin();
                LOG_F(INFO, "Removing old data for second: %ld, Traffic: %ld bytes", it->first, it->second);
                trafficPerSecond.erase(it);
            }

        }
        catch (const std::exception& e) {
            // 处理转换错误
            LOG_F(ERROR, "Error parsing tshark output: %s", line.c_str());
        }
    }

    LOG_F(INFO, "adapterFlowTrendMonitorThreadEntry 已结束");
}
// 开始监控所有网卡流量统计数据
void TsharkManager::startMonitorAdaptersFlowTrend() {

    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    adapterFlowTrendMonitorStartTime = time(nullptr);

    // 第一步：获取网卡列表
    std::vector<AdapterInfo> adapterList = getNetworkAdapters();

    // 第二步：每个网卡启动一个线程，统计对应网卡的数据
    for (auto adapter : adapterList) {

        adapterFlowTrendMonitorMap.insert(std::make_pair<>(adapter.name, AdapterMonitorInfo()));
        AdapterMonitorInfo& monitorInfo = adapterFlowTrendMonitorMap.at(adapter.name);

        monitorInfo.monitorThread = std::make_shared<std::thread>(&TsharkManager::adapterFlowTrendMonitorThreadEntry, this, adapter.name);
        if (monitorInfo.monitorThread == nullptr) {
            LOG_F(ERROR, "监控线程创建失败，网卡名：%s", adapter.name.c_str());
        } else {
            LOG_F(INFO, "监控线程创建成功，网卡名：%s,monitorThread: %p", adapter.name.c_str(), monitorInfo.monitorThread.get());
        }
    }
}
// 停止监控所有网卡流量统计数据
void TsharkManager::stopMonitorAdaptersFlowTrend() {

    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    // 先杀死对应的tshark进程
    for (auto adapterPipePair : adapterFlowTrendMonitorMap) {
        ProcessUtil::Kill(adapterPipePair.second.tsharkPid);
    }

    // 然后关闭管道
    for (auto adapterPipePair : adapterFlowTrendMonitorMap) {

        // 然后关闭管道
        pclose(adapterPipePair.second.monitorTsharkPipe);

        // 最后等待对应线程退出
        adapterPipePair.second.monitorThread->join();

        LOG_F(INFO, "网卡：%s 流量监控已停止", adapterPipePair.first.c_str());
    }

    // 清空记录的流量趋势数据
    adapterFlowTrendMonitorMap.clear();
}
// 获取所有网卡流量统计数据
void TsharkManager::getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData) {

    long timeNow = time(nullptr);

    // 数据从最左边冒出来
    // 一开始：以最开始监控时间为左起点，终点为未来300秒
    // 随着时间推移，数据逐渐填充完这300秒
    // 超过300秒之后，结束节点就是当前，开始节点就是当前-300
    long startWindow = timeNow - adapterFlowTrendMonitorStartTime > 300 ? timeNow - 300 : adapterFlowTrendMonitorStartTime;
    long endWindow = timeNow - adapterFlowTrendMonitorStartTime > 300 ? timeNow : adapterFlowTrendMonitorStartTime + 300;

    adapterFlowTrendMapLock.lock();
    for (auto adapterPipePair : adapterFlowTrendMonitorMap) {
        flowTrendData.insert(std::make_pair<>(adapterPipePair.first, std::map<long, long>()));

        // 从当前时间戳向前倒推300秒，构造map
        for (long t = startWindow; t <= endWindow; t++) {
            // 如果trafficPerSecond中存在该时间戳，则使用已有数据；否则填充为0
            if (adapterPipePair.second.flowTrendData.find(t) != adapterPipePair.second.flowTrendData.end()) {
                flowTrendData[adapterPipePair.first][t] = adapterPipePair.second.flowTrendData.at(t);
            } else {
                flowTrendData[adapterPipePair.first][t] = 0;
            }
        }
    }

    adapterFlowTrendMapLock.unlock();
}
bool TsharkManager::getPacketDetailInfo(uint32_t frameNumber, std::string &result) {

    // 先通过editcap将这一帧数据包从文件中摘出来，然后再获取详情，这样会快一些
    std::string tmpFilePath = MiscUtil::getDefaultDataDir() + MiscUtil::getRandomString(10) + ".pcap";
    std::string splitCmd = editcapPath + " -r " + currentFilePath + " " + tmpFilePath + " " + std::to_string(frameNumber) + "-" + std::to_string(frameNumber);
    if (!ProcessUtil::Exec(splitCmd)) {
        LOG_F(ERROR, "Error in executing command: %s", splitCmd.c_str());
        remove(tmpFilePath.c_str());
        return false;
    }

    // 通过tshark获取指定数据包详细信息，输出格式为XML
    // 启动'tshark -r ${currentFilePath} -T pdml'命令，获取指定数据包的详情
    std::string cmd = tsharkPath + " -r " + tmpFilePath + " -T pdml";
    std::unique_ptr<FILE, decltype(&pclose)> pipe(ProcessUtil::PopenEx(cmd.c_str()), pclose);
    if (!pipe) {
        std::cout << "Failed to run tshark command." << std::endl;
        remove(tmpFilePath.c_str());
        return false;
    }

    // 读取tshark输出
    char buffer[8192] = { 0 };
    std::string tsharkResult;
    setvbuf(pipe.get(), NULL, _IOFBF, sizeof(buffer));
    int count = 0;
    while (fgets(buffer, sizeof(buffer) - 1, pipe.get()) != nullptr) {
        tsharkResult += buffer;
        memset(buffer, 0, sizeof(buffer));
    }

    remove(tmpFilePath.c_str());

    // 将xml内容转换为JSON
    rapidjson::Document detailJson;
    if (!MiscUtil::xml2JSON(tsharkResult, detailJson)) {
        LOG_F(ERROR, "XML转JSON失败");
        return false;
    }

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer stringBuffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(stringBuffer);
    detailJson.Accept(writer);

    // 设置数据包详情结果
    result = stringBuffer.GetString();

    return true;
}