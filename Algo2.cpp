#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <bitset>
#include <sstream>
#include <stdexcept>
#include <algorithm>

using namespace std;

// S-DES Constants
const int P10[10] = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
const int P8[8] = {6, 3, 7, 4, 8, 5, 10, 9};
const int IP[8] = {2, 6, 3, 1, 4, 8, 5, 7};
const int EP[8] = {4, 1, 2, 3, 2, 3, 4, 1};
const int P4[4] = {2, 4, 3, 1};

const int S0[4][4] = {
    {1, 0, 3, 2},
    {3, 2, 1, 0},
    {0, 2, 1, 3},
    {3, 1, 3, 2}
};

const int S1[4][4] = {
    {0, 1, 2, 3},
    {2, 0, 1, 3},
    {3, 0, 1, 0},
    {2, 1, 0, 3}
};

// AES S-Box (useful for encryption)
const unsigned char SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Corresponding Inverse S-Box (useful for decryption)
const unsigned char INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

class AES {
private:
    vector<vector<unsigned char>> state;
    vector<vector<unsigned char>> roundKeys;
    int Nr; // Number of rounds

    void printState(const string& label) {
        cout << label << ":" << endl;
        for(const auto& row : state) {
            for(unsigned char byte : row) {
                cout << hex << setw(2) << setfill('0') << static_cast<int>(byte) << " ";
            }
            cout << endl;
        }
        cout << endl;
    }

    void subBytes() {
        for(auto& row : state) {
            transform(row.begin(), row.end(), row.begin(), 
                [](unsigned char byte) { return SBOX[byte]; });
        }
        printState("After SubBytes");
    }

    void shiftRows() {
        // First row remains unchanged
        // Second row shifts left by 1
        rotate(state[1].begin(), state[1].begin() + 1, state[1].end());
        
        // Third row shifts left by 2
        rotate(state[2].begin(), state[2].begin() + 2, state[2].end());
        
        // Fourth row shifts left by 3 (or right by 1)
        rotate(state[3].begin(), state[3].begin() + 3, state[3].end());
        
        printState("After ShiftRows");
    }

    unsigned char gmul(unsigned char a, unsigned char b) {
        unsigned char result = 0;
        while (b) {
            if (b & 1) result ^= a;
            bool hi_bit_set = (a & 0x80);
            a <<= 1;
            if (hi_bit_set) a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1
            b >>= 1;
        }
        return result;
    }

    void mixColumns() {
        vector<vector<unsigned char>> temp = state;
        for (int c = 0; c < 4; ++c) {
            state[0][c] = gmul(temp[0][c], 2) ^ gmul(temp[1][c], 3) ^ 
                          temp[2][c] ^ temp[3][c];
            state[1][c] = temp[0][c] ^ gmul(temp[1][c], 2) ^ 
                          gmul(temp[2][c], 3) ^ temp[3][c];
            state[2][c] = temp[0][c] ^ temp[1][c] ^ 
                          gmul(temp[2][c], 2) ^ gmul(temp[3][c], 3);
            state[3][c] = gmul(temp[0][c], 3) ^ temp[1][c] ^ 
                          temp[2][c] ^ gmul(temp[3][c], 2);
        }
        printState("After MixColumns");
    }

    void addRoundKey(int round) {
        for(int i = 0; i < 4; ++i) {
            for(int j = 0; j < 4; ++j) {
                state[i][j] ^= roundKeys[round*4 + i][j];
            }
        }
        printState("After AddRoundKey");
    }

    void keyExpansion(const vector<unsigned char>& key) {
        roundKeys.clear();
        // Simplified key expansion for 128-bit key
        for(int i = 0; i < 44; ++i) {
            vector<unsigned char> roundKey(4, 0);
            if(i < 4) {
                // First 4 words are directly from the key
                for(int j = 0; j < 4; ++j) {
                    roundKey[j] = key[i*4 + j];
                }
            } else {
                // Subsequent words are XORed
                roundKey = roundKeys[i-1];
                if(i % 4 == 0) {
                    // RotWord and SubWord
                    rotate(roundKey.begin(), roundKey.begin() + 1, roundKey.end());
                    transform(roundKey.begin(), roundKey.end(), roundKey.begin(), 
                        [](unsigned char byte) { return SBOX[byte]; });
                    // XOR with round constant
                    roundKey[0] ^= (1 << ((i/4 - 1) % 10));
                }
                
                // XOR with previous round key
                for(int j = 0; j < 4; ++j) {
                    roundKey[j] ^= roundKeys[i-4][j];
                }
            }
            roundKeys.push_back(roundKey);
        }
    }

public:
    AES(const vector<unsigned char>& key) : Nr(10) {
        // Initialize state and perform key expansion
        state = vector<vector<unsigned char>>(4, vector<unsigned char>(4));
        keyExpansion(key);
    }

    vector<unsigned char> encrypt(const vector<unsigned char>& plaintext) {
        // Initialize state from plaintext
        for(int i = 0; i < 4; ++i) {
            for(int j = 0; j < 4; ++j) {
                state[j][i] = plaintext[i*4 + j];
            }
        }
        printState("Initial State");

        // Initial round key
        addRoundKey(0);

        // Main rounds
        for(int round = 1; round < Nr; ++round) {
            cout<< "\nRound " << round << ":" << endl;
            subBytes();
            shiftRows();
            mixColumns();
            addRoundKey(round);
        }

        // Final round (no MixColumns)
        subBytes();
        shiftRows();
        addRoundKey(Nr);

        // Convert state back to vector
        vector<unsigned char> ciphertext;
        for(int i = 0; i < 4; ++i) {
            for(int j = 0; j < 4; ++j) {
                ciphertext.push_back(state[j][i]);
            }
        }
        return ciphertext;
    }

    // Helper method to convert hex string to bytes
    static vector<unsigned char> hexToBytes(const string& hex) {
        vector<unsigned char> bytes;
        for(size_t i = 0; i < hex.length(); i += 2) {
            string byteString = hex.substr(i, 2);
            unsigned char byte = stoi(byteString, nullptr, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

    // Helper method to convert bytes to hex string
    static string bytesToHex(const vector<unsigned char>& bytes) {
        stringstream ss;
        ss << hex << setfill('0');
        for(unsigned char byte : bytes) {
            ss << setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }
};


class SDES {
private:
    string key;
    vector<string> subKeys;

    string permute(const string& input, const int* pattern, int patternSize) {
        string output;
        for(int i = 0; i < patternSize; i++) {
            output += input[pattern[i] - 1];
        }
        return output;
    }

    string leftShift(const string& s, int positions) {
        return s.substr(positions) + s.substr(0, positions);
    }

    void generateSubKeys() {
        cout << "Generating Subkeys:" << endl;
        string permuted = permute(key, P10, 10);
        string left = permuted.substr(0, 5);
        string right = permuted.substr(5, 5);
        
        left = leftShift(left, 1);
        right = leftShift(right, 1);
        subKeys.push_back(permute(left + right, P8, 8));
        cout << "Subkey 1: " << subKeys.back() << endl;

        left = leftShift(left, 2);
        right = leftShift(right, 2);
        subKeys.push_back(permute(left + right, P8, 8));
        cout << "Subkey 2: " << subKeys.back() << endl;
    }

    string sBox(const string& input, const int sbox[4][4]) {
        int row = (input[0] - '0') * 2 + (input[3] - '0');
        int col = (input[1] - '0') * 2 + (input[2] - '0');
        return bitset<2>(sbox[row][col]).to_string();
    }

    string fFunction(const string& right, const string& subkey) {
        string expanded = permute(right, EP, 8);
        cout << "Expanded Right: " << expanded << endl;
        
        string xored;
        for(size_t i = 0; i < expanded.length(); i++) {
            xored += (expanded[i] != subkey[i]) ? '1' : '0';
        }
        cout << "XOR with Subkey: " << xored << endl;

        string s0Result = sBox(xored.substr(0, 4), S0);
        string s1Result = sBox(xored.substr(4, 4), S1);
        string combined = s0Result + s1Result;
        cout << "S-Box Output: " << combined << endl;
        
        return permute(combined, P4, 4);
    }

public:
    SDES(const string& inputKey) : key(inputKey) {
        generateSubKeys();
    }

    string encrypt(const string& plaintext) {
        string current = permute(plaintext, IP, 8);
        cout << "Initial Permutation: " << current << endl;

        for(int round = 0; round < 2; round++) {
            string left = current.substr(0, 4);
            string right = current.substr(4, 4);
            
            string fResult = fFunction(right, subKeys[round]);
            
            string newRight;
            for(int i = 0; i < 4; i++) {
                newRight += (left[i] != fResult[i]) ? '1' : '0';
            }
            cout << "Round " << round + 1 << " - Left: " << left << " Right: " << right << " NewRight: " << newRight << endl;

            current = (round == 0) ? (right + newRight) : (newRight + right);
        }

        return permute(current, IP, 8);
    }

    string decrypt(const string& ciphertext) {
        string current = permute(ciphertext, IP, 8);
        cout << "Initial Permutation: " << current << endl;

        for(int round = 0; round < 2; round++) {
            string left = current.substr(0, 4);
            string right = current.substr(4, 4);
            
            string fResult = fFunction(right, subKeys[1 - round]);
            
            string newRight;
            for(int i = 0; i < 4; i++) {
                newRight += (left[i] != fResult[i]) ? '1' : '0';
            }
            cout << "Round " << round + 1 << " - Left: " << left << " Right: " << right << " NewRight: " << newRight << endl;

            current = (round == 0) ? (right + newRight) : (newRight + right);
        }

        return permute(current, IP, 8);
    }

    static string hexToBinary(const string& hex) {
        stringstream binary;
        for(char c : hex) {
            int value = (c >= 'A') ? (c - 'A' + 10) : (c - '0');
            binary << bitset<4>(value);
        }
        return binary.str();
    }

    static string binaryToHex(const string& binary) {
        stringstream hex;
        hex << std::hex << std::setfill('0');
        for(size_t i = 0; i < binary.length(); i += 4) {
            string chunk = binary.substr(i, 4);
            hex << std::setw(1) << std::stoi(chunk, nullptr, 2);
        }
        return hex.str();
    }
};


class RC4 {
public:
    string processToHex(const string& input, const string& keyHex, bool encrypt = true) {
        vector<unsigned char> inputBytes = hexToBytes(input);
        vector<unsigned char> keyBytes = hexToBytes(keyHex);
        
        vector<int> S(256);
        for(int k = 0; k < 256; k++) S[k] = k;
        
        int j = 0;
        cout << "\nKey-Scheduling Algorithm (KSA) steps:" << endl;
        for(int k = 0; k < 256; k++) {
            j = (j + S[k] + keyBytes[k % keyBytes.size()]) % 256;
            swap(S[k], S[j]);
            cout << "S[" << k << "] swapped with S[" << j << "]" << endl;
        }

        vector<unsigned char> outputBytes;
        int i = 0;
        j = 0;
        
        string processType = encrypt ? "Encryption" : "Decryption";
        cout << "\nPseudo-Random Generation Algorithm (PRGA) steps (" 
             << processType << "):" << endl;
        
        for(size_t index = 0; index < inputBytes.size(); index++) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            swap(S[i], S[j]);
            int k = S[(S[i] + S[j]) % 256];
            outputBytes.push_back(inputBytes[index] ^ k);
            
            cout << "Step " << index + 1 << ": i=" << i << ", j=" << j 
                 << ", Key Stream Byte=" << hex << setw(2) << setfill('0') 
                 << static_cast<int>(k) << dec << " XOR with " 
                 << static_cast<int>(inputBytes[index]) << " = " 
                 << static_cast<int>(outputBytes.back()) << endl;
        }

        return bytesToHex(outputBytes);
    }

private:
    vector<unsigned char> hexToBytes(const string& hex) {
        vector<unsigned char> bytes;
        for(size_t i = 0; i < hex.length(); i += 2) {
            string byteString = hex.substr(i, 2);
            unsigned char byte = stoi(byteString, nullptr, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

    string bytesToHex(const vector<unsigned char>& bytes) {
        stringstream ss;
        ss << hex << setfill('0');
        for(unsigned char byte : bytes) {
            ss << setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }
};


class SymmetricEncryptionTool {
private:
    SDES sdes;
    RC4 rc4;

public:
    SymmetricEncryptionTool() : sdes("1010101010") {}

    void runMainMenu() {
        while(true) {
            cout << "\n=== Symmetric Encryption Tool ===\n";
            cout << "1. S-DES Encryption\n";
            cout << "2. S-DES Decryption\n";
            cout << "3. RC4 Encryption\n";
            cout << "4. RC4 Decryption\n";
            cout << "5. AES Encryption\n";
            cout << "6. Exit\n";
            cout << "Enter your choice (1-6): ";
            int choice;
            cin >> choice;

            switch(choice) {
                case 1: {
                    string plaintext, key;
                    cout << "Enter plaintext (8-bit binary or 2-digit hex): ";
                    cin >> plaintext;
                    cout << "Enter key (10-bit binary or 3-digit hex): ";
                    cin >> key;

                    if(plaintext.length() == 2) plaintext = SDES::hexToBinary(plaintext);
                    if(plaintext.length() != 8) {
                        cerr << "Invalid plaintext /  key length!\n";
                        break;
                    }
                    if(key.length() == 3) key = SDES::hexToBinary(key);
                    if(key.length() != 10) {
                        cerr << "Invalid key length!\n";
                        break;
                    }

                    SDES currentSdes(key);
                    string encrypted = currentSdes.encrypt(plaintext);
                    cout << "Encrypted (binary): " << encrypted << endl;
                    cout << "Encrypted (hex): " << SDES::binaryToHex(encrypted) << endl;
                    break;
                }
                case 2: {
                    string ciphertext, key;
                    cout << "Enter ciphertext (8-bit binary or 2-digit hex): ";
                    cin >> ciphertext;
                    cout << "Enter key (10-bit binary or 3-digit hex): ";
                    cin >> key;

                    if(ciphertext.length() == 2) ciphertext = SDES::hexToBinary(ciphertext);
                    if(key.length() == 3) key = SDES::hexToBinary(key);

                    SDES currentSdes(key);
                    string decrypted = currentSdes.decrypt(ciphertext);
                    cout << "Decrypted (binary): " << decrypted << endl;
                    cout << "Decrypted (hex): " << SDES::binaryToHex(decrypted) << endl;
                    break;
                }
                case 3: {
                    string input, key;
                    cout << "Enter input in hex: ";
                    cin >> input;
                    cout << "Enter key in hex: ";
                    cin >> key;

                    string result = rc4.processToHex(input, key, true);
                    cout << "Encrypted Result: " << result << endl;
                    break;
                }
                case 4: {
                    string input, key;
                    cout << "Enter input in hex: ";
                    cin >> input;
                    cout << "Enter key in hex: ";
                    cin >> key;

                    string result = rc4.processToHex(input, key, false);
                    cout << "Decrypted Result: " << result << endl;
                    break;
                }
                case 5: {
                    string input, keyHex;
                    cout << "Enter 128-bit input in hex (32 hex characters): ";
                    cin >> input;
                    cout << "Enter 128-bit key in hex (32 hex characters): ";
                    cin >> keyHex;

                    try {
                        vector<unsigned char> inputBytes = AES::hexToBytes(input);
                        vector<unsigned char> keyBytes = AES::hexToBytes(keyHex);

                        AES aes(keyBytes);
                        vector<unsigned char> ciphertext = aes.encrypt(inputBytes);

                        cout << "Ciphertext (hex): " 
                             << AES::bytesToHex(ciphertext) << endl;
                    } catch(const exception& e) {
                        cerr << "Error: " << e.what() << endl;
                    }
                    break;
                }
                case 6:
                    cout << "Exiting...\n";
                    return;
                default:
                    cout << "Invalid choice. Please try again.\n";
            }
        }
    }
};

int main() {
    try {
        SymmetricEncryptionTool tool;
        tool.runMainMenu();
    } catch(const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}