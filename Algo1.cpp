#include <iostream>
#include <string>
#include <vector>
#include <bitset>
#include <iomanip>
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

// Utility Functions
string toBinary(string hex) {
    string binary;
    for(char c : hex) {
        int value = (c >= 'A') ? (c - 'A' + 10) : (c - '0');
        binary += bitset<4>(value).to_string();
    }
    return binary;
}

string toHex(string binary) {
    string hex;
    for(size_t i = 0; i < binary.length(); i += 4) {
        string chunk = binary.substr(i, 4);
        int value = bitset<4>(chunk).to_ulong();
        hex += (value < 10) ? ('0' + value) : ('A' + value - 10);
    }
    return hex;
}

// S-DES Implementation
class SDES {
private:
    string key;
    vector<string> subKeys;

    // Permutation helper functions (unchanged)
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
        // Clear previous subkeys
        subKeys.clear();
        
        cout << "Generating Subkeys:" << endl;
        // Initial 10-bit key permutation
        string permuted = permute(key, P10, 10);
        
        // Split into left and right halves
        string left = permuted.substr(0, 5);
        string right = permuted.substr(5, 5);
        
        // First round key generation
        left = leftShift(left, 1);
        right = leftShift(right, 1);
        subKeys.push_back(permute(left + right, P8, 8));
        cout << "Subkey 1: " << subKeys.back() << endl;

        // Second round key generation
        left = leftShift(left, 2);
        right = leftShift(right, 2);
        subKeys.push_back(permute(left + right, P8, 8));
        cout << "Subkey 2: " << subKeys.back() << endl;
    }

    string sBox(const string& input, const int sbox[4][4]) {
        // Convert 4-bit input to row and column for S-Box
        int row = (input[0] - '0') * 2 + (input[3] - '0');
        int col = (input[1] - '0') * 2 + (input[2] - '0');
        
        // Get value from S-Box and convert to 2-bit binary
        return bitset<2>(sbox[row][col]).to_string();
    }

    string fFunction(const string& right, const string& subkey) {
        // Expand right half from 4 to 8 bits using expansion permutation
        string expanded = permute(right, EP, 8);
        cout << "Expanded Right: " << expanded << endl;
        
        // XOR expanded right half with subkey
        string xored;
        for(size_t i = 0; i < expanded.length(); i++) {
            xored += (expanded[i] != subkey[i]) ? '1' : '0';
        }
        cout << "XOR with Subkey: " << xored << endl;

        // Split XORed result and apply S-Boxes
        string s0Result = sBox(xored.substr(0, 4), S0);
        string s1Result = sBox(xored.substr(4, 4), S1);
        string combined = s0Result + s1Result;
        cout << "S-Box Output: " << combined << endl;
        
        // Permute the S-Box output
        return permute(combined, P4, 4);
    }

    // Simplified Feistel network logic with symmetric encryption/decryption
    string feistelRound(const string& input, const string& subkey, bool isEncrypt) {
        // Split input into left and right halves
        string left = input.substr(0, 4);
        string right = input.substr(4, 4);
        
        // Apply F-function to right half
        string fResult = fFunction(right, subkey);
        
        // XOR left half with F-function result
        string newRight;
        for(int i = 0; i < 4; i++) {
            newRight += (left[i] != fResult[i]) ? '1' : '0';
        }
        
        // Swap in first round, keep as-is in second round
        return isEncrypt ? (right + newRight) : (newRight + right);
    }

public:
    SDES(const string& inputKey) : key(inputKey) {
        // Ensure 10-bit key
        if (key.length() != 10) {
            throw runtime_error("Key must be exactly 10 bits long");
        }
        generateSubKeys();
    }

    string encrypt(const string& plaintext) {
        // Ensure 8-bit input
        if (plaintext.length() != 8) {
            throw runtime_error("Plaintext must be exactly 8 bits long");
        }

        // Initial permutation
        string current = permute(plaintext, IP, 8);
        cout << "Initial Permutation: " << current << endl;

        // First round with first subkey (left to right)
        current = feistelRound(current, subKeys[0], true);
        cout << "After First Round: " << current << endl;

        // Second round with second subkey (right to left)
        current = feistelRound(current, subKeys[1], true);
        cout << "After Second Round: " << current << endl;

        // Inverse initial permutation to get final ciphertext
        return permute(current, IP, 8);
    }

    string decrypt(const string& ciphertext) {
        // Ensure 8-bit input
        if (ciphertext.length() != 8) {
            throw runtime_error("Ciphertext must be exactly 8 bits long");
        }

        // Initial permutation
        string current = permute(ciphertext, IP, 8);
        cout << "Initial Permutation: " << current << endl;

        // First round with second subkey (right to left)
        current = feistelRound(current, subKeys[1], false);
        cout << "After First Round: " << current << endl;

        // Second round with first subkey (left to right)
        current = feistelRound(current, subKeys[0], false);
        cout << "After Second Round: " << current << endl;

        // Inverse initial permutation to get original plaintext
        return permute(current, IP, 8);
    }

    // Existing static conversion methods remain the same
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

// AES Constants and Tables
const unsigned char SBOX[256] = {
    // Standard AES S-box
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    // ... (rest of S-box values)
};

class AES {
private:
    vector<vector<unsigned char>> state;
    vector<vector<unsigned char>> roundKeys;

    void subBytes() {
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                state[i][j] = SBOX[state[i][j]];
            }
        }
    }

    void shiftRows() {
        // Implement row shifting
        vector<unsigned char> temp = state[1];
        state[1] = {state[1][1], state[1][2], state[1][3], state[1][0]};
        temp = state[2];
        state[2] = {state[2][2], state[2][3], state[2][0], state[2][1]};
        temp = state[3];
        state[3] = {state[3][3], state[3][0], state[3][1], state[3][2]};
    }

    void mixColumns() {
        // Implement mix columns operation
        // (Simplified version shown here)
        vector<vector<unsigned char>> temp = state;
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                state[i][j] = temp[i][j] ^ temp[(i+1)%4][j] ^ temp[(i+2)%4][j];
            }
        }
    }

    void addRoundKey(int round) {
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                state[i][j] ^= roundKeys[round*4 + i][j];
            }
        }
    }

public:
    AES(vector<unsigned char> key) {
        // Initialize state and generate round keys
        state = vector<vector<unsigned char>>(4, vector<unsigned char>(4));
        // Key expansion would go here
    }

    vector<unsigned char> encrypt(vector<unsigned char> plaintext) {
        // Initialize state with plaintext
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                state[i][j] = plaintext[i*4 + j];
            }
        }

        // Initial round
        addRoundKey(0);

        // Main rounds
        for(int round = 1; round < 10; round++) {
            subBytes();
            shiftRows();
            mixColumns();
            addRoundKey(round);
        }

        // Final round
        subBytes();
        shiftRows();
        addRoundKey(10);

        // Convert state back to vector
        vector<unsigned char> ciphertext;
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                ciphertext.push_back(state[i][j]);
            }
        }
        return ciphertext;
    }
};

int main() {
    int choice;
    string input, key;

    while(true) {
        cout << "\n=== Symmetric Encryption Menu ===\n";
        cout << "1. S-DES Encryption\n";
        cout << "2. S-DES Decryption\n";
        cout << "3. AES Encryption\n";
        cout << "4. Exit\n";
        cout << "Enter your choice (1-4): ";
        cin >> choice;

        if(choice == 4) break;

        switch(choice) {
            case 1:
            case 2: {
                cout << "Enter input (8 bits binary or 2 digit hex): ";
                cin >> input;
                cout << "Enter key (10 bits binary or 3 digit hex): ";
                cin >> key;

                // Convert hex to binary if needed
                if(input.length() == 2) {
                    input = toBinary(input);
                }
                if(key.length() == 3) {
                    key = toBinary(key);
                }

                // Validate input
                if(input.length() != 8 || key.length() != 10) {
                    cout << "Invalid input length!\n";
                    break;
                }

                SDES sdes(key);
                string result = (choice == 1) ? sdes.encrypt(input) : sdes.decrypt(input);
                cout << "\nResult in binary: " << result << endl;
                cout << "Result in hex: " << toHex(result) << endl;
                break;
            }
            case 3: {
                // AES implementation would go here
                cout << "Enter 128-bit input in hex: ";
                cin >> input;
                // Similar validation and processing for AES
                break;
            }
            default:
                cout << "Invalid choice!\n";
        }
    }

    return 0;
}