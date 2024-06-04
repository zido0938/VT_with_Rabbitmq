#include <string>
#include <SimpleAmqpClient/SimpleAmqpClient.h>
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>

std::string usingQueue;
AmqpClient::Channel::ptr_t channel;
std::string selected_path_file = "selected_file_path.txt";

void sendFile(const std::string& filePath, const std::string& queue) {
    std::string fileName = filePath.substr(filePath.find_last_of("/\\") + 1);

    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Error to open file for read: " << filePath << std::endl;
        exit(1);
    }
    std::string content(std::istreambuf_iterator<char>{file}, {});
    file.close();

    nlohmann::json jsonContent;
    jsonContent["filename"] = fileName;
    jsonContent["content"] = content;

    std::string jsonString = jsonContent.dump();

    channel->BasicPublish("", queue, AmqpClient::BasicMessage::Create(jsonString));
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

    bool passive = false, durable = true, exclusive = false, auto_delete = false;
    channel->DeclareQueue(usingQueue, passive, durable, exclusive, auto_delete);
    std::cout << "3" << std::endl;

    std::ifstream pathFile(selected_path_file);
    if (!pathFile.is_open()) {
        std::cerr << "Error to open selected file path: " << selected_path_file << std::endl;
        return 1;
    }
    std::string sendFilePath;
    std::getline(pathFile, sendFilePath);
    pathFile.close();
    sendFile(sendFilePath, usingQueue);
    std::cout << "4" << std::endl;
    return 0;
}
