#include <iostream>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <thread>
#include "MerkleTreeHash.h"
using namespace boost::filesystem;

std::string selected_path = "upload_path.txt";
bool isMonitoring = true;

void monitorDirectoryChange(const std::string& directoryPath) {
    path dir(directoryPath);

    if (!exists(dir) || !is_directory(dir)) {
        std::cerr << "Error: Directory " << directoryPath << " does not Exist." << std::endl;
        return;
    }

    std::cout << "Monitoring directory: " << directoryPath << std::endl;
    std::cout << "Start monitoring " << std::endl;
    
    std::map<std::string, std::time_t> currentFiles;
    for (directory_iterator it(dir); it != directory_iterator(); it++) {
        if (is_regular_file(*it)) {
            currentFiles[it->path().filename().string()] = last_write_time(*it);
        }
    }
    printAllFileHashesAndMerkleTreeHash(directoryPath, currentFiles);
    
    while (isMonitoring) {
        for (directory_iterator it(dir); it != directory_iterator(); it++) {
            if (is_regular_file(*it)) {
                std::string filename = it->path().filename().string();
                std::time_t lastWriteTime = last_write_time(*it);

                if (currentFiles.find(filename) == currentFiles.end()) {
                    std::cout << "New file is created: " << it->path() << std::endl;
                    std::cout << "Created File Hash: " << calculateFileHash(it->path().string()) << std::endl;
                    currentFiles[filename] = lastWriteTime;
                    std::vector <std::string> currentFilesVector;
                    for (auto it = currentFiles.begin(); it != currentFiles.end(); it++) {
                        std::string fileHash = calculateFileHash(directoryPath + "/" + it->first);
                        currentFilesVector.push_back(fileHash);
                    }   
                    MerkleNode* rootnode = constructMerkleTree(currentFilesVector);
                    std::cout << "Updated MerkleTree RootNode Hash: " << rootnode->hash << std::endl;
                } 
                else if (currentFiles[filename] != lastWriteTime) {
                    std::cout << "File modified: " << it->path() << std::endl;
                    std::cout << "Modified File Hash: " << calculateFileHash(it->path().string()) << std::endl;
                    currentFiles[filename] = lastWriteTime;
                    std::vector <std::string> currentFilesVector;
                    for (auto it = currentFiles.begin(); it != currentFiles.end(); it++) {
                        std::string fileHash = calculateFileHash(directoryPath + "/" + it->first);
                        currentFilesVector.push_back(fileHash);
                    }
                    MerkleNode* rootnode = constructMerkleTree(currentFilesVector);
                    std::cout << "Updated MerkleTree RootNode Hash: " << rootnode->hash << std::endl;
                }
            }
        }
        
        for (auto it = currentFiles.begin(); it != currentFiles.end();) {
            if (!exists(dir / it->first)) {
                std::cout << "File deleted: " << dir / it->first << std::endl;
                it = currentFiles.erase(it);
                std::vector <std::string> currentFilesVector;
                for (auto it = currentFiles.begin(); it != currentFiles.end(); it++) {
                    std::string fileHash = calculateFileHash(directoryPath + "/" + it->first);
                    currentFilesVector.push_back(fileHash);
                }
                MerkleNode* rootnode = constructMerkleTree(currentFilesVector);
                std::cout << "Updated MerkleTree RootNode Hash: " << rootnode->hash << std::endl;
            } 
            else {
                it++;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

int main() {
    std::ifstream pathFile(selected_path);
    if (!pathFile.is_open()) {
        std::cerr << "Error to open selected file path: " << selected_path << std::endl;
        return 1;
    }
    std::string saveDirectory;
    std::getline(pathFile, saveDirectory);
    pathFile.close();
    monitorDirectoryChange(saveDirectory);
  
    return 0;
}

