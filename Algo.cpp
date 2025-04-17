#include <iostream>
#include <string>
#include <vector>
using namespace std;

// Utility functions for conversion and validation
string hexToBinary(string hex) {
    string binary = "";
    for (char c : hex) {
        switch(toupper(c)) {
            case '0': binary += "0000"; break;
            case '1': binary += "0001"; break;
            case '2': binary += "0010"; break;
            case '3': binary += "0011"; break;
            case '4': binary += "0100"; break;
            case '5': binary += "0101"; break;
            case '6': binary += "0110"; break;
            case '7': binary += "0111"; break;
            case '8': binary += "1000"; break;
            case '9': binary += "1001"; break;
            case 'A': binary += "1010"; break;
            case 'B': binary += "1011"; break;
            case 'C': binary += "1100"; break;
            case 'D': binary += "1101"; break;
            case 'E': binary += "1110"; break;
            case 'F': binary += "1111"; break;
            default: throw invalid_argument("Invalid hexadecimal digit");
        }
    }
    return binary;
}

string binaryToHex(string binary) {
    string hex = "";
    for (int i = 0; i < binary.length(); i += 4) {
        string chunk = binary.substr(i, 4);
        if (chunk == "0000") hex += "0";
        else if (chunk == "0001") hex += "1";
        else if (chunk == "0010") hex += "2";
        else if (chunk == "0011") hex += "3";
        else if (chunk == "0100") hex += "4";
        else if (chunk == "0101") hex += "5";
        else if (chunk == "0110") hex += "6";
        else if (chunk == "0111") hex += "7";
        else if (chunk == "1000") hex += "8";
        else if (chunk == "1001") hex += "9";
        else if (chunk == "1010") hex += "A";
        else if (chunk == "1011") hex += "B";
        else if (chunk == "1100") hex += "C";
        else if (chunk == "1101") hex += "D";
        else if (chunk == "1110") hex += "E";
        else if (chunk == "1111") hex += "F";
    }
    return hex;
}

// S-DES Implementation
class SDES {
private:
    // S-DES Constants
    const vector<int> P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
    const vector<int> P8 = {6, 3, 7, 4, 8, 5, 10, 9};
    const vector<int> IP = {2, 6, 3, 1, 4, 8, 5, 7};
    const vector<int> EP = {4, 1, 2, 3, 2, 3, 4, 1};
    const vector<int> P4 = {2, 4, 3, 1};
    const vector<vector<vector<int>>> S1 = {
        {{1,0},{0,1},{1,1},{0,0}},
        {{0,0},{1,0},{0,1},{1,1}}
    };
    const vector<vector<vector<int>>> S2 = {
        {{0,0},{1,0},{1,1},{1,0}},
        {{1,1},{0,1},{0,0},{0,1}}
    };
    
    vector<string> subkeys;

    string permute(string input, const vector<int>& pattern) {
        string output = "";
        for (int pos : pattern) {
            output += input[pos - 1];
        }
        return output;
    }

    string leftShift(string s, int n) {
        return s.substr(n) + s.substr(0, n);
    }

    void generateSubkeys(string key) {
        // Step 1: Apply P10
        string p10_result = permute(key, P10);
        cout << "After P10: " << p10_result << endl;

        // Step 2: Split and left shift
        string left = p10_result.substr(0, 5);
        string right = p10_result.substr(5, 5);
        
        // Generate K1
        left = leftShift(left, 1);
        right = leftShift(right, 1);
        string shifted = left + right;
        string k1 = permute(shifted, P8);
        cout << "Subkey K1: " << k1 << endl;
        
        // Generate K2
        left = leftShift(left, 1);
        right = leftShift(right, 1);
        shifted = left + right;
        string k2 = permute(shifted, P8);
        cout << "Subkey K2: " << k2 << endl;

        subkeys = {k1, k2};
    }

    string sBoxSubstitution(string input, const vector<vector<vector<int>>>& sbox) {
        int row = (input[0] - '0') * 2 + (input[3] - '0');
        int col = (input[1] - '0') * 2 + (input[2] - '0');
        return to_string(sbox[row][col][0]) + to_string(sbox[row][col][1]);
    }

    string fFunction(string right, string subkey) {
        // Expansion/Permutation
        string expanded = permute(right, EP);
        cout << "After expansion: " << expanded << endl;
        
        // XOR with subkey
        string xored = "";
        for (int i = 0; i < 8; i++) {
            xored += (expanded[i] == subkey[i]) ? '0' : '1';
        }
        cout << "After XOR with subkey: " << xored << endl;
        
        // S-Box substitution
        string s1_input = xored.substr(0, 4);
        string s2_input = xored.substr(4, 4);
        string s1_output = sBoxSubstitution(s1_input, S1);
        string s2_output = sBoxSubstitution(s2_input, S2);
        string s_output = s1_output + s2_output;
        cout << "After S-box substitution: " << s_output << endl;
        
        // P4 permutation
        return permute(s_output, P4);
    }

public:
    string encrypt(string plaintext, string key) {
        generateSubkeys(key);
        
        // Initial Permutation
        string ip_output = permute(plaintext, IP);
        cout << "After initial permutation: " << ip_output << endl;
        
        // Split into left and right halves
        string left = ip_output.substr(0, 4);
        string right = ip_output.substr(4, 4);
        
        // First round
        string f_output = fFunction(right, subkeys[0]);
        string new_right = "";
        for (int i = 0; i < 4; i++) {
            new_right += (left[i] == f_output[i]) ? '0' : '1';
        }
        
        // Swap
        left = right;
        right = new_right;
        cout << "After first round: " << left + right << endl;
        
        // Second round
        f_output = fFunction(right, subkeys[1]);
        new_right = "";
        for (int i = 0; i < 4; i++) {
            new_right += (left[i] == f_output[i]) ? '0' : '1';
        }
        left = right;
        right = new_right;
        
        // Final permutation
        vector<int> FP = {4, 1, 3, 5, 7, 2, 8, 6};
        return permute(left + right, FP);
    }

    string decrypt(string ciphertext, string key) {
        generateSubkeys(key);
        // Decryption is the same as encryption but with subkeys reversed
        swap(subkeys[0], subkeys[1]);
        return encrypt(ciphertext, key);
    }
};

// AES Implementation (simplified 128-bit version)
class AES {
private:
    // AES S-box (partial implementation for demonstration)
    const vector<vector<int>> sbox = {
        {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5},
        {0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0},
        {0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}
        // ... (full S-box would be 16x16)
    };

    vector<vector<unsigned char>> state;
    vector<vector<unsigned char>> roundKeys;

    void addRoundKey(int round) {
        // Implementation of AddRoundKey transformation
        cout << "Performing AddRoundKey for round " << round << endl;
        // Add actual implementation here
    }

    void subBytes() {
        // Implementation of SubBytes transformation
        cout << "Performing SubBytes transformation" << endl;
        // Add actual implementation here
    }

    void shiftRows() {
        // Implementation of ShiftRows transformation
        cout << "Performing ShiftRows transformation" << endl;
        // Add actual implementation here
    }

    void mixColumns() {
        // Implementation of MixColumns transformation
        cout << "Performing MixColumns transformation" << endl;
        // Add actual implementation here
    }

public:
    string encrypt(string plaintext, string key) {
        cout << "AES Encryption Process:" << endl;
        cout << "Initial state: " << plaintext << endl;
        
        // Initial round
        addRoundKey(0);
        
        // Main rounds
        for (int round = 1; round < 10; round++) {
            cout << "\nRound " << round << ":" << endl;
            subBytes();
            shiftRows();
            mixColumns();
            addRoundKey(round);
        }
        
        // Final round
        cout << "\nFinal Round:" << endl;
        subBytes();
        shiftRows();
        addRoundKey(10);
        
        return "encrypted_text"; // Placeholder for actual implementation
    }

    string decrypt(string ciphertext, string key) {
        // Similar structure to encrypt but with inverse operations
        return "decrypted_text"; // Placeholder for actual implementation
    }
};

int main() {
    string input, key;
    int choice;
    
    while (true) {
        cout << "\n=== Symmetric Encryption Menu ===" << endl;
        cout << "1. S-DES Encryption" << endl;
        cout << "2. S-DES Decryption" << endl;
        cout << "3. AES Encryption" << endl;
        cout << "4. AES Decryption" << endl;
        cout << "5. Exit" << endl;
        cout << "Enter your choice (1-5): ";
        cin >> choice;
        
        if (choice == 5) break;
        
        try {
            if (choice == 1 || choice == 2) {  // S-DES
                cout << "Enter input (8 bits binary or 2 digit hex): ";
                cin >> input;
                cout << "Enter key (10 bits binary or 3 digit hex): ";
                cin >> key;
                
                // Convert hex to binary if needed
                if (input.length() == 2) {
                    input = hexToBinary(input);
                }
                if (key.length() == 3) {
                    key = hexToBinary(key);
                }
                
                // Validate input
                if (input.length() != 8) {
                    throw invalid_argument("Input must be 8 bits");
                }
                if (key.length() != 10) {
                    throw invalid_argument("Key must be 10 bits");
                }
                
                SDES sdes;
                string result;
                if (choice == 1) {
                    cout << "\nS-DES Encryption Process:" << endl;
                    result = sdes.encrypt(input, key);
                    cout << "\nEncrypted result (binary): " << result << endl;
                    cout << "Encrypted result (hex): " << binaryToHex(result) << endl;
                } else {
                    cout << "\nS-DES Decryption Process:" << endl;
                    result = sdes.decrypt(input, key);
                    cout << "\nDecrypted result (binary): " << result << endl;
                    cout << "Decrypted result (hex): " << binaryToHex(result) << endl;
                }
            }
            else if (choice == 3 || choice == 4) {  // AES
                cout << "Enter input (128 bits in hex): ";
                cin >> input;
                cout << "Enter key (128 bits in hex): ";
                cin >> key;
                
                // Validate input
                if (input.length() != 32) {
                    throw invalid_argument("Input must be 32 hex digits (128 bits)");
                }
                if (key.length() != 32) {
                    throw invalid_argument("Key must be 32 hex digits (128 bits)");
                }
                
                AES aes;
                if (choice == 3) {
                    string result = aes.encrypt(input, key);
                    cout << "Encrypted result: " << result << endl;
                } else {
                    string result = aes.decrypt(input, key);
                    cout << "Decrypted result: " << result << endl;
                }
            }
        }
        catch (const exception& e) {
            cout << "Error: " << e.what() << endl;
        }
    }
    
    return 0;
}