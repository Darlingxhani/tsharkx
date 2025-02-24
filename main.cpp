#include "tsharkManager.h"

int main(int argc, char* argv[]) {
    loguru::init(argc, argv);
    loguru::add_file("log.txt", loguru::Append, loguru::Verbosity_MAX);
    TsharkManager tsharkManager("F:\\code\\vscodecpp\\tshark");
    tsharkManager.analysisFile("E:\\Pcap\\capture.pcap");

    tsharkManager.printAllPackets();

    std::vector<AdapterInfo> adaptors = tsharkManager.getNetworkAdapters();
    for (auto item : adaptors) {
        LOG_F(INFO, "网卡[%d]: name[%s] remark[%s]", item.id, item.name.c_str(), item.remark.c_str());
    }
    return 0;
}