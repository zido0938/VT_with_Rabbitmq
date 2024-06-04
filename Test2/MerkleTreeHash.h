#ifndef MERKLETREEHASH_H
#define MERKLETREEHASH_H

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <array>
#include "merklenode.h"


std::array<char, SHA256_DIGEST_LENGTH * 2> convertBinaryToHexadecimal(std::string content);

std::string calculateFileHash(const std::string filePath);

MerkleNode* constructMerkleTree(std::vector<std::string>& fileHashes);

void printAllFileHashesAndMerkleTreeHash(const std::string& directoryPath, std::map <std::string, std::time_t> currentFilesMap);

#endif
