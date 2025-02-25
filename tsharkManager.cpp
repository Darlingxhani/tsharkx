#include "tsharkManager.h"
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

    FILE *pipe = popen(command.c_str(), "r");
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
    captureWorkThread->join();

    return true;
}
