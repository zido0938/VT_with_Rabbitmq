#include <string>
#include <SimpleAmqpClient/SimpleAmqpClient.h>
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>

std::string usingQueue;
AmqpClient::Channel::ptr_t channel;
std::string selected_path = "upload_path.txt";

void receiveFile(const std::string& queue, const std::string& saveDirectory) {
    AmqpClient::Envelope::ptr_t envelope;
    bool no_ack = false;

    boost::uint16_t message_prefetch_count = 2;
    std::string consumer = channel->BasicConsume(queue, "", no_ack, message_prefetch_count);

    bool isConsume = channel->BasicConsumeMessage(consumer, envelope);

    if (!isConsume) {
        std::cerr << "Error to consume the content: " << queue << std::endl;
        exit(1);
    }

    std::string jsonString = envelope->Message()->Body();

    nlohmann::json jsonContent = nlohmann::json::parse(jsonString);

    std::string fileName = jsonContent["filename"];
    std::string content = jsonContent["content"];

    std::ofstream file(saveDirectory + "/" + fileName, std::ios::binary);
    if (!file) {
        std::cerr << "Error to open file for write" << std::endl;
        exit(1);
    }
    file.write(content.data(), content.size());
    file.close();
}

int main () {
    int queueNumber;
    std::cout << "Enter a Queue number: ";
    std::cin >> queueNumber;
    usingQueue = "B_to_A" + std::to_string(queueNumber);

    std::cout << "1" << std::endl;
    AmqpClient::Channel::OpenOpts opts;
    std::cout << "1.1" << std::endl;
    opts.auth = AmqpClient::Channel::OpenOpts::BasicAuth("try1", "1234");
    opts.host = "166.104.245.156";
    opts.vhost = "/1";
    opts.port = 5672;
    opts.frame_max = 131072;
    std::cout << "1.2" << std::endl;

    channel = AmqpClient::Channel::Open(opts);
    std::cout << "2" << std::endl;
   
    std::ifstream pathFile(selected_path);
    if (!pathFile.is_open()) {
        std::cerr << "Error to open selected path: " << selected_path << std::endl;
        return 1;
    }
    std::cout << "3" << std::endl;

    std::string saveDirectory;
    std::getline(pathFile, saveDirectory);
    pathFile.close(); // 저장할 디렉토리
    std::cout << "4" << std::endl;

    receiveFile(usingQueue, saveDirectory);
    return 0;
}
