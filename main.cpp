#include "tsharkManager.h"

int main(int argc, char* argv[]) {
    loguru::init(argc, argv);
    loguru::add_file("log.txt", loguru::Append, loguru::Verbosity_MAX);
    TsharkManager tsharkManager("F:\\code\\vscodecpp\\tshark");
    tsharkManager.startCapture("\\Device\\NPF_{432FD487-F313-4D97-92D4-3FCF0BA4E3CD}");
     // 主线程进入命令等待停止抓包
    std::string input;
    while (true) {
         std::cout << "请输入q退出抓包: ";
         std::cin >> input;
         if (input == "q") {
             tsharkManager.stopCapture();
             break;
         }
    }
 
     // 打印所有捕获到的数据包信息
    tsharkManager.printAllPackets(); 
    return 0;
}