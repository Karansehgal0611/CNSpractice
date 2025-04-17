#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

class RC4 {
private:
    std::vector<unsigned char> S;
    size_t i, j;

    // Key Scheduling Algorithm (KSA)
    void initialize(const std::vector<unsigned char>& key) {
        S.resize(256);
        for (int k = 0; k < 256; k++) {
            S[k] = k;
        }

        j = 0;
        for (i = 0; i < 256; i++) {
            j = (j + S[i] + key[i % key.size()]) % 256;
            std::swap(S[i], S[j]);
        }

        i = j = 0;
    }

    // Pseudo-Random Generation Algorithm (PRGA)
    unsigned char generate() {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        return S[(S[i] + S[j]) % 256];
    }

public:
    RC4(const std::vector<unsigned char>& key) {
        initialize(key);
    }

    // Encrypt/Decrypt function (same operation for RC4)
    std::vector<unsigned char> process(const std::vector<unsigned char>& data) {
        std::vector<unsigned char> result;
        for (unsigned char byte : data) {
            result.push_back(byte ^ generate());
        }
        return result;
    }
};

// Helper function to print hex
void print_hex(const std::vector<unsigned char>& data) {
    for (unsigned char byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
}

int main() {
    // Example usage
    std::string key_str = "SecretKey";
    std::string plaintext = "Hello, RC4!";

    // Convert strings to byte vectors
    std::vector<unsigned char> key(key_str.begin(), key_str.end());
    std::vector<unsigned char> data(plaintext.begin(), plaintext.end());

    // Initialize RC4 with key
    RC4 rc4(key);

    // Encrypt
    std::vector<unsigned char> ciphertext = rc4.process(data);
    std::cout << "Ciphertext: ";
    print_hex(ciphertext);

    // Re-initialize with same key for decryption
    RC4 rc4_decrypt(key);
    std::vector<unsigned char> decrypted = rc4_decrypt.process(ciphertext);
    std::string decrypted_str(decrypted.begin(), decrypted.end());
    std::cout << "Decrypted: " << decrypted_str << std::endl;

    return 0;
}
