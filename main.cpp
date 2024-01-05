#include <iostream>
#include <bitset>
#include <sstream>
#include <valarray>
#include <vector>
#include <cstdint>
#include "sha1.h"

const uint32_t kValues[K_SIZE] = K_VALUES;
uint32_t h[INITIAL_H_VALUES_SIZE] = INITIAL_H_VALUES;

std::string parseMessageToBinary(std::string message) {
    std::ostringstream parsedMessageStream;
    for (char& c : message) {
        int asciiValue = static_cast<int>(c);
        std::string binaryString = std::bitset<8>(asciiValue).to_string();
        parsedMessageStream<<binaryString;
    }
    std::string parsedMessage = parsedMessageStream.str();
    return parsedMessage;
}

void padMessage(std::string & message) {
    message+='1';
    while (message.length() % SHA_SIZE != SHA_SIZE_WITHOUT_MESSAGE_SIZE) {
        message.push_back('0');
    }
}
std::string fromBnToHex(std::string binaryMessage) {
    std::ostringstream hexStream;

    for (size_t i = 0; i < binaryMessage.length(); i += 4) {
        std::string fourBits = binaryMessage.substr(i, 4);
        std::bitset<4> bitset(fourBits);
        int hexValue = bitset.to_ulong();
        hexStream << std::hex << hexValue;
    }
    return hexStream.str();
}
std::string hexSize(unsigned long long number) {
    std::ostringstream hexedSize;
    hexedSize << std::hex << number;
    std::string hexedNumber = hexedSize.str();
    if(hexedNumber.length() < 16) hexedNumber = std::string(16-hexedNumber.length(),'0') + hexedNumber;
    return hexedNumber;
}
uint32_t rotateLeft(uint32_t value, int shift) {
    return (((value) << (shift)) | ((value) >> (32-(shift))));
}
std::vector<std::string> divideByBlocks(std::string message) {
    std::vector<std::string> blocks;
    for(unsigned long long i =0; i < message.length();i+=SHA_BLOCK_SIZE) {
        std::string block = message.substr(i,SHA_BLOCK_SIZE);
        blocks.push_back(block);
    }
    return blocks;
}
std::vector<uint32_t> divideStringByWords(std::string message) {
    std::vector<uint32_t> words;
    for (int i = 0; i < message.size(); i += 8) {
        std::string wordStr = message.substr(i, 8);
        uint32_t word;
        std::istringstream(wordStr) >> std::hex >> word;
        words.push_back(word);
    }
    return words;
}

void encryptBlock(std::string & block) {
    std::vector<uint32_t> words =  divideStringByWords(block);

    for(int i = 16; i < 80;i++) {
        uint32_t result = rotateLeft((words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16]),1);
        words.push_back(result);
    }

    uint32_t A = h[0];
    uint32_t B = h[1];
    uint32_t C = h[2];
    uint32_t D = h[3];
    uint32_t E = h[4];


    for (unsigned int i = 0; i < 80; i++) {
        uint32_t f;
        uint32_t k;
        if (i <= 19) {
            f = (B & C) | (((~B) & D));
            k = kValues[0];
        } else if (i <= 39) {
            f = B ^ C ^ D;
            k = kValues[1];
        } else if (i <= 59) {
            f = (B & C) | (B & D) | (C & D);
            k = kValues[2];
        } else {
            f = B ^ C ^ D;
            k = kValues[3];
        }

        uint32_t temp = rotateLeft(A,5) + f + E + k + words[i];
        E = D;
        D = C;
        C = rotateLeft(B,30);
        B = A;
        A = temp;
    }
    h[0] +=A;
    h[1] +=B;
    h[2] +=C;
    h[3] +=D;
    h[4] +=E;
}
std::string makeHash() {
    std::ostringstream hashStream;
    for (unsigned short i = 0; i < INITIAL_H_VALUES_SIZE; i++) {
        std::ostringstream hexStream;
        hexStream << std::hex << h[i];
        std::string hexH = hexStream.str();
        if(hexH.length() < 8) {
            hexH = std::string(8 - hexH.length(),'0' ) + hexH;
        }
        hashStream<<hexH;
    }
    return hashStream.str();
}
std::string SHA_1(std::string initialMessage) {
    std::string message = parseMessageToBinary(initialMessage);
    unsigned long long size = message.size();

    if(message.length() % SHA_SIZE != SHA_SIZE_WITHOUT_MESSAGE_SIZE) padMessage(message);
    std::string hexedMessage = fromBnToHex(message);

    hexedMessage += hexSize(size);
    std::vector<std::string> blocks = divideByBlocks(hexedMessage);

    for (auto & block : blocks) {
        encryptBlock(block);
    }
    std::string hash = makeHash();
    return hash;
}
int main() {
    std::string message;
    std::cout << "Enter the message: ";
    std::cin >> message;
    std::cout<<"\n SHA-1 hash: "<<SHA_1(message)<<std::endl;
    return 0;
}
