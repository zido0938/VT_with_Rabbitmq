#include <openssl/sha.h>
#include <openssl/evp.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include "merklenode.h"
#include "MerkleTreeHash.h"


/*
 입력한 문자열 값을 SHA-256으로 바이너리로 전환하고 이를 16진수 문자열로 변환하는 함수,
 caculateFileHash 함수 내부에 쓰기위해 구현
*/

std::array<char, SHA256_DIGEST_LENGTH * 2> convertBinaryToHexadecimal(std::string content) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    //unsigned char hash[SHA256_DIGEST_LENGTH];
    std::array<unsigned char, SHA256_DIGEST_LENGTH> hash;
    /* Open SSL 3.0버전부터는 아래 주석 코드를 사용하지 않음. */
    /* SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, content.c_str(), content.length());
    SHA256_Final(hash.data(), &sha256); */
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, content.c_str(), content.length());
    EVP_DigestFinal_ex(mdctx, hash.data(), NULL);
    EVP_MD_CTX_free(mdctx);

    std::array<char, SHA256_DIGEST_LENGTH * 2> hexHash;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hexHash[i * 2], "%02x", hash[i]);
    }
    /* hexHash[SHA256_DIGEST_LENGTH * 2] = '\0'; 
    -> 이경우 std::array hexHash<char, SHA256_DIGEST_LENGTH * 2 +1> */

    return hexHash;
}
/* 
 파일을 열고 파일 내용을 읽어 파일 해시값으로 변환하는 함수
 SHA-256 바이너리 해시값을 16진수 문자열로 반환.
*/
std::string calculateFileHash(const std::string filePath) {

    std::ifstream file(filePath.c_str(), std::ios::binary);

    if (!file.is_open()) {
        std::cerr << "Error to open file(Calculate FileHash): " << filePath << std::endl;
        return "";
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::array<char, SHA256_DIGEST_LENGTH * 2> hexHash = convertBinaryToHexadecimal(content);
    std::string hexString(hexHash.data(), hexHash.size());
    
    return hexString;
}

/*
 MerkelTree 구성 함수
 FileHash값들이 저장된 Vector를 넣어주면. 순서대로 머킅트리 Leaf를 구성하고 Root노드의 32바이트 해시값을 리턴
*/
MerkleNode* constructMerkleTree(std::vector<std::string>& fileHashes) {
    std::vector<MerkleNode*> nodes;
    for (const auto& hash : fileHashes) {
        MerkleNode* node = new MerkleNode{hash, nullptr, nullptr};
        nodes.push_back(node);
    }

    while (nodes.size() > 1) {
        std::vector<MerkleNode*> parentLevel; //바로 위 레벨을 나타내는 변수
        for (size_t i = 0; i < nodes.size(); i += 2) {
            MerkleNode* left = nodes[i];
            MerkleNode* right = (i + 1 < nodes.size()) ? nodes[i + 1] : nullptr;
            std::string combinedHash = left->hash + (right ? right->hash : "");

            /* Tree의 left + right를 다시 해시처리 */
            std::array <char, SHA256_DIGEST_LENGTH * 2> hexHash = convertBinaryToHexadecimal(combinedHash);
            std::string hexHashStr(hexHash.data(), hexHash.size());
            MerkleNode* parent = new MerkleNode{hexHashStr, left, right};
            parentLevel.push_back(parent);
        }
        nodes = parentLevel;
    }
    return nodes.front();
}

void printAllFileHashesAndMerkleTreeHash(const std::string& directoryPath, std::map <std::string, std::time_t> currentFilesMap) {
    std::vector <std::string> currentFilesVector;
    for (auto it = currentFilesMap.begin(); it != currentFilesMap.end(); it++) {
        std::string fileHash = calculateFileHash(directoryPath + "/" + it->first);
        std::cout << directoryPath << "/" << it->first <<": " << fileHash << std::endl;
        currentFilesVector.push_back(fileHash);
    }
    MerkleNode* rootnode = constructMerkleTree(currentFilesVector);
    std::cout << "MerkleTree RootNode Hash: " << rootnode->hash << std::endl;
}
/* int main() {
    std::string filePath;
    std::cout << "파일 경로를 입력하세요: " ;
    std::getline(std::cin, filePath);

    std::cout << "입력된 파일 경로: " << filePath << std::endl;
    std::cout << "입력된 파일 경로 해시값: " << calculateFileHash(filePath) << std::endl;
    return 0;
} */