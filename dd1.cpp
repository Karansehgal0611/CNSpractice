#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <ctime>
#include <cstdint>

class CryptoAlgorithms {
private:
    // Helper functions for bit manipulation and conversion
    static uint64_t rotr64(uint64_t x, int shift) {
        return (x >> shift) | (x << (64 - shift));
    }

    static uint32_t rotr32(uint32_t x, int shift) {
        return (x >> shift) | (x << (32 - shift));
    }

    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static uint32_t sigma0_32(uint32_t x) {
        return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
    }

    static uint32_t sigma1_32(uint32_t x) {
        return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
    }

    static uint64_t sigma0_64(uint64_t x) {
        return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
    }

    static uint64_t sigma1_64(uint64_t x) {
        return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
    }

    // SHA-512 constants
    static const uint64_t SHA512_K[80];

    // MD5 constants
    static const uint32_t MD5_K[64];
    static const uint32_t MD5_S[64];

public:
    // SHA-512 Implementation
    static std::string sha512(const std::string& input) {
        // Initial hash values
        std::vector<uint64_t> H = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };

        // Preprocessing
        std::vector<uint8_t> message(input.begin(), input.end());
        uint64_t ml = message.size() * 8;
        message.push_back(0x80);

        // Padding
        while ((message.size() * 8 + 128) % 1024 != 0) {
            message.push_back(0);
        }

        // Append message length
        for (int i = 7; i >= 0; --i) {
            message.push_back((ml >> (i * 8)) & 0xFF);
        }

        // Process message in 1024-bit blocks
        for (size_t i = 0; i < message.size(); i += 128) {
            std::vector<uint64_t> W(80, 0);

            // Prepare message schedule
            for (int t = 0; t < 16; ++t) {
                W[t] = ((uint64_t)message[i + t*8] << 56) |
                       ((uint64_t)message[i + t*8 + 1] << 48) |
                       ((uint64_t)message[i + t*8 + 2] << 40) |
                       ((uint64_t)message[i + t*8 + 3] << 32) |
                       ((uint64_t)message[i + t*8 + 4] << 24) |
                       ((uint64_t)message[i + t*8 + 5] << 16) |
                       ((uint64_t)message[i + t*8 + 6] << 8) |
                       ((uint64_t)message[i + t*8 + 7]);
            }

            // Extend message schedule
            for (int t = 16; t < 80; ++t) {
                uint64_t s0 = rotr64(W[t-15], 1) ^ rotr64(W[t-15], 8) ^ (W[t-15] >> 7);
                uint64_t s1 = rotr64(W[t-2], 19) ^ rotr64(W[t-2], 61) ^ (W[t-2] >> 6);
                W[t] = W[t-16] + s0 + W[t-7] + s1;
            }

            // Working variables
            uint64_t a = H[0], b = H[1], c = H[2], d = H[3],
                     e = H[4], f = H[5], g = H[6], h = H[7];

            // Main compression loop
            for (int t = 0; t < 80; ++t) {
                uint64_t S1 = sigma1_64(e);
                uint64_t ch = (e & f) ^ (~e & g);
                uint64_t temp1 = h + S1 + ch + SHA512_K[t] + W[t];
                uint64_t S0 = sigma0_64(a);
                uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint64_t temp2 = S0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            // Update hash values
            H[0] += a; H[1] += b; H[2] += c; H[3] += d;
            H[4] += e; H[5] += f; H[6] += g; H[7] += h;
        }

        // Generate final hash
        std::stringstream ss;
        for (int i = 0; i < 8; ++i) {
            ss << std::hex << std::setw(16) << std::setfill('0') << H[i];
        }
        return ss.str();
    }

    // MD5 Implementation
    static std::string md5(const std::string& input) {
        // Initial hash values
        uint32_t a0 = 0x67452301;
        uint32_t b0 = 0xefcdab89;
        uint32_t c0 = 0x98badcfe;
        uint32_t d0 = 0x10325476;

        // Preprocessing
        std::vector<uint8_t> message(input.begin(), input.end());
        uint64_t ml = message.size() * 8;
        message.push_back(0x80);

        // Padding
        while ((message.size() * 8 + 64) % 512 != 0) {
            message.push_back(0);
        }

        // Append message length (little-endian)
        for (int i = 0; i < 8; ++i) {
            message.push_back((ml >> (i * 8)) & 0xFF);
        }

        // Process message in 512-bit blocks
        for (size_t i = 0; i < message.size(); i += 64) {
            uint32_t a = a0, b = b0, c = c0, d = d0;

            // Main loop
            for (int j = 0; j < 64; ++j) {
                uint32_t f, g;
                if (j < 16) {
                    f = (b & c) | (~b & d);
                    g = j;
                } else if (j < 32) {
                    f = (d & b) | (~d & c);
                    g = (5 * j + 1) % 16;
                } else if (j < 48) {
                    f = b ^ c ^ d;
                    g = (3 * j + 5) % 16;
                } else {
                    f = c ^ (b | ~d);
                    g = (7 * j) % 16;
                }

                // Extract 32-bit word from message
                uint32_t word = 0;
                for (int k = 0; k < 4; ++k) {
                    word |= (uint32_t)message[i + g*4 + k] << (k * 8);
                }

                uint32_t temp = d;
                d = c;
                c = b;
                b = b + ((a + f + MD5_K[j] + word) << MD5_S[j] | 
                         (a + f + MD5_K[j] + word) >> (32 - MD5_S[j]));
                a = temp;
            }

            // Update hash values
            a0 += a; b0 += b; c0 += c; d0 += d;
        }

        // Generate final hash
        std::stringstream ss;
        ss << std::hex << std::setw(8) << std::setfill('0') << a0
           << std::setw(8) << std::setfill('0') << b0
           << std::setw(8) << std::setfill('0') << c0
           << std::setw(8) << std::setfill('0') << d0;
        return ss.str();
    }

    // Digital Signature Simulation (simplified ElGamal-like approach)
    class DigitalSignature {
    private:
        // Prime modulus
        static const long long P = 23;
        // Primitive root
        static const long long G = 5;
        // Private key
        long long privateKey;
        // Public key
        long long publicKey;

    public:
        DigitalSignature() {
            // Simulate key generation
            srand(time(nullptr));
            privateKey = rand() % (P - 2) + 1;
            publicKey = modPow(G, privateKey, P);
        }

        // Modular exponentiation
        static long long modPow(long long base, long long exp, long long mod) {
            long long result = 1;
            base %= mod;
            while (exp > 0) {
                if (exp & 1)
                    result = (result * base) % mod;
                base = (base * base) % mod;
                exp >>= 1;
            }
            return result;
        }

        // Sign message
        std::pair<long long, long long> signMessage(const std::string& message) {
            // Simulate signature generation
            long long hash = 0;
            for (char c : message) {
                hash = (hash * 31 + c) % P;
            }

            // Random ephemeral key
            long long k = rand() % (P - 2) + 1;
            
            // Signature components
            long long r = modPow(G, k, P);
            long long s = ((hash - privateKey * r) * modPow(k, P-2, P)) % (P-1);

            return {r, s};
        }

        // Verify signature
        bool verifySignature(const std::string& message, 
                             long long r, long long s) {
            // Hash message
            long long hash = 0;
            for (char c : message) {
                hash = (hash * 31 + c) % P;
            }

            // Verification calculation
            long long v1 = modPow(publicKey, r, P) * modPow(r, s, P) % P;
            long long v2 = modPow(G, hash, P);

            return v1 == v2;
        }

        // Getters for keys
        long long getPublicKey() const { return publicKey; }
    };
};

// SHA-512 constants (complete set)
const uint64_t CryptoAlgorithms::SHA512_K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

// MD5 constants 
const uint32_t CryptoAlgorithms::MD5_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// MD5 shift values
const uint32_t CryptoAlgorithms::MD5_S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

// Menu display function
void displayMenu() {
    std::cout << "\n=== Cryptographic Algorithms Simulator ===\n";
    std::cout << "1. SHA-512 Hash\n";
    std::cout << "2. MD5 Hash\n";
    std::cout << "3. Digital Signature\n";
    std::cout << "4. Exit\n";
    std::cout << "Enter your choice: ";
}

// Main function with error handling and input validation
int main() {
    CryptoAlgorithms::DigitalSignature ds;

    while (true) {
        displayMenu();
        
        int choice;
        std::cin >> choice;
        
        // Clear input buffer to handle potential invalid inputs
        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid input. Please enter a number.\n";
            continue;
        }
        std::cin.ignore(); // Clear newline from input buffer

        switch (choice) {
            case 1: {
                std::string input;
                std::cout << "Enter message to hash with SHA-512: ";
                std::getline(std::cin, input);
                
                if (input.empty()) {
                    std::cout << "Error: Empty input not allowed.\n";
                    break;
                }

                std::string hash = CryptoAlgorithms::sha512(input);
                std::cout << "SHA-512 Hash: " << hash << std::endl;
                break;
            }
            case 2: {
                std::string input;
                std::cout << "Enter message to hash with MD5: ";
                std::getline(std::cin, input);
                
                if (input.empty()) {
                    std::cout << "Error: Empty input not allowed.\n";
                    break;
                }

                std::string hash = CryptoAlgorithms::md5(input);
                std::cout << "MD5 Hash: " << hash << std::endl;
                break;
            }
            case 3: {
                std::string message;
                std::cout << "Enter message to sign: ";
                std::getline(std::cin, message);
                
                if (message.empty()) {
                    std::cout << "Error: Empty input not allowed.\n";
                    break;
                }

                // Sign the message
                auto signature = ds.signMessage(message);
                std::cout << "Digital Signature Components:\n";
                std::cout << "r: " << signature.first << std::endl;
                std::cout << "s: " << signature.second << std::endl;

                // Verify the signature
                bool verified = ds.verifySignature(message, 
                                                   signature.first, 
                                                   signature.second);
                std::cout << "Signature Verification: " 
                          << (verified ? "Successful" : "Failed") 
                          << std::endl;
                break;
            }
            case 4:
                std::cout << "Exiting program...\n";
                return 0;
            default:
                std::cout << "Invalid choice. Please select a number between 1 and 4.\n";
        }
    }

    return 0;
}