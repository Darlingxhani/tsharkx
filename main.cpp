#include "tsharkManager.h"
// int main(int argc, char* argv[]) {
    
//     TsharkManager tsharkManager("F:\\code\\vscodecpp\\tshark");
//     tsharkManager.startCapture("\\Device\\NPF_{432FD487-F313-4D97-92D4-3FCF0BA4E3CD}");
//     // \\Device\\NPF_{AF966622-2F0D-43CD-9B76-BBAA9280F083} wlan
//     // \\Device\\NPF_{432FD487-F313-4D97-92D4-3FCF0BA4E3CD} 蓝牙
//      // 主线程进入命令等待停止抓包
//     std::string input;
//     while (true) {
//          std::cout << "请输入q退出抓包: ";
//          std::cin >> input;
//          if (input == "q") {
//              tsharkManager.stopCapture();
//              break;
//          }
//     }
 
//     // 打印所有捕获到的数据包信息
//     tsharkManager.printAllPackets(); 
//     return 0;
// }

// int main(int argc, char* argv[]) {

//     loguru::init(argc, argv);
//     loguru::add_file("log.txt", loguru::Append, loguru::Verbosity_MAX);

//     TsharkManager tsharkManager("F:\\code\\vscodecpp\\tshark");

//     // 启动监控
//     tsharkManager.startMonitorAdaptersFlowTrend();

//     // 睡眠10秒，等待监控网卡数据
//     std::this_thread::sleep_for(std::chrono::seconds(10));

//     // 读取监控到的数据
//     std::map<std::string, std::map<long, long>> trendData;
//     tsharkManager.getAdaptersFlowTrendData(trendData);

//     // 停止监控
//     tsharkManager.stopMonitorAdaptersFlowTrend();

//     // 把获取到的数据打印输出
//     rapidjson::Document resDoc;
//     rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
//     resDoc.SetObject();
//     rapidjson::Value dataObject(rapidjson::kObjectType);
//     for (const auto &adaptorItem : trendData) {
//         rapidjson::Value adaptorDataList(rapidjson::kArrayType);
//         for (const auto &timeItem : adaptorItem.second) {
//             rapidjson::Value timeObj(rapidjson::kObjectType);
//             timeObj.AddMember("time", (unsigned int)timeItem.first, allocator);
//             timeObj.AddMember("bytes", (unsigned int)timeItem.second, allocator);
//             adaptorDataList.PushBack(timeObj, allocator);
//         }

//         dataObject.AddMember(rapidjson::StringRef(adaptorItem.first.c_str()), adaptorDataList, allocator);
//     }

//     resDoc.AddMember("data", dataObject, allocator);

//     // 序列化为 JSON 字符串
//     rapidjson::StringBuffer buffer;
//     rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
//     resDoc.Accept(writer);

//     LOG_F(INFO, "网卡流量监控数据: %s", buffer.GetString());

//     return 0;
// }
int main(int argc, char* argv[]) {


    loguru::init(argc, argv);
    loguru::add_file("log.txt", loguru::Append, loguru::Verbosity_MAX);

    std::string filepath;
    
    LOG_F(INFO,"请输入pcap文件路径: ");

    std::cin>>filepath;

    TsharkManager tsharkManager("F:\\code\\vscodecpp\\tshark");
    tsharkManager.analysisFile(filepath);
    tsharkManager.printAllPackets();

    std::cout<<std::endl<<std::endl;

    LOG_F(INFO,"请输入要获取详情的数据包编号:(1---%d)",tsharkManager.allPackets.size());    
    uint32_t frameNumberend=1;
    std::cin>>frameNumberend;
    std::vector<std::string> results(frameNumberend+1);
    for (uint32_t i = 1; i <= frameNumberend; i++) {
        std::string result;
        tsharkManager.getPacketDetailInfo(i,result);
        results.push_back(result);
    }
    for(auto &result:results) {
        LOG_F(INFO,"%s",result.c_str());
    }
    return 0;
}