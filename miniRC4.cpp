#include <iostream>
#include <vector>
#include <algorithm>

class MiniRC4 {
private:
    unsigned char S[8]; // 8-byte state (instead of 256)
    unsigned char i, j;

    // Key scheduling with reduced state
    void initialize(const std::vector<unsigned char>& key) {
        // Initialize state
        for (int k = 0; k < 8; k++) {
            S[k] = k;
        }

        // Scramble state with key
        j = 0;
        for (i = 0; i < 8; i++) {
            j = (j + S[i] + key[i % key.size()]) % 8;
            std::swap(S[i], S[j]);
        }
        i = j = 0;
    }

    // Byte generation with reduced state
    unsigned char generate() {
        i = (i + 1) % 8;
        j = (j + S[i]) % 8;
        std::swap(S[i], S[j]);
        return S[(S[i] + S[j]) % 8];
    }

public:
    MiniRC4(const std::vector<unsigned char>& key) {
        initialize(key);
    }

    // Process data (encrypt/decrypt)
    std::vector<unsigned char> process(const std::vector<unsigned char>& data) {
        std::vector<unsigned char> result;
        for (unsigned char byte : data) {
            result.push_back(byte ^ generate());
        }
        return result;
    }
};

int main() {
    // Example usage with tiny key and data
    std::vector<unsigned char> key = {0x01, 0x02, 0x03};
    std::vector<unsigned char> data = {'H', 'e', 'l', 'l', 'o'};

    MiniRC4 rc4(key);

    // Encrypt
    auto ciphertext = rc4.process(data);
    std::cout << "Ciphertext: ";
    for (auto b : ciphertext) std::cout << std::hex << (int)b << " ";
    std::cout << std::endl;

    // Reset with same key to decrypt
    MiniRC4 rc4_decrypt(key);
    auto decrypted = rc4_decrypt.process(ciphertext);
    std::cout << "Decrypted: ";
    for (auto b : decrypted) std::cout << (char)b;
    std::cout << std::endl;

    return 0;
}
