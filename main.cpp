#include "tsharkManager.h"

int main(int argc, char* argv[]) {
    loguru::init(argc, argv);
    loguru::add_file("log.txt", loguru::Append, loguru::Verbosity_MAX);
    TsharkManager tsharkManager("F:\\code\\vscodecpp\\tshark");
    tsharkManager.analysisFile("E:\\Pcap\\capture.pcap");

    tsharkManager.printAllPackets();

    return 0;
}