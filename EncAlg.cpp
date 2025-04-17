#include <iostream>
#include <string>
#include <bitset>
#include <vector>
#include<bits/stdc++.h>

using namespace std;

// Function prototypes for S-DES
void generateKeys_SDES(const string& key, string& K1, string& K2);
string permute(const string& input, const vector<int>& table);
string leftShift(const string& input, int shifts);
string fk(const string& half, const string& key);
string encrypt_SDES(const string& plaintext, const string& K1, const string& K2);
string decrypt_SDES(const string& ciphertext, const string& K1, const string& K2);
bool validateInput(const string& input, int length);

// Function prototypes for AES (Simplified Example)
string encrypt_AES(const string& plaintext, const string& key);
string decrypt_AES(const string& ciphertext, const string& key);

// Permutation tables for S-DES
const vector<int> P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
const vector<int> P8 = {6, 3, 7, 4, 8, 5, 10, 9};
const vector<int> IP = {2, 6, 3, 1, 4, 8, 5, 7};
const vector<int> IP_INV = {4, 1, 3, 5, 7, 2, 8, 6};
const vector<int> EP = {4, 1, 2, 3, 2, 3, 4, 1};
const vector<int> P4 = {2, 4, 3, 1};

// S-boxes for S-DES
const int S0[4][4] = {{1, 0, 3, 2}, {3, 2, 1, 0}, {0, 2, 1, 3}, {3, 1, 3, 2}};
const int S1[4][4] = {{0, 1, 2, 3}, {2, 0, 1, 3}, {3, 0, 1, 0}, {2, 1, 0, 3}};

bool validateInput(const string& input, int length) {
    if (input.length() != length) return false;
    for (char c : input) {
        if (c != '0' && c != '1') return false;
    }
    return true;
}

string permute(const string& input, const vector<int>& table) {
    string output = "";
    for (int pos : table) {
        output += input[pos - 1];
    }
    return output;
}

string leftShift(const string& input, int shifts) {
    return input.substr(shifts) + input.substr(0, shifts);
}

void generateKeys_SDES(const string& key, string& K1, string& K2) {
    string permutedKey = permute(key, P10);
    string left = permutedKey.substr(0, 5);
    string right = permutedKey.substr(5, 5);

    left = leftShift(left, 1);
    right = leftShift(right, 1);
    K1 = permute(left + right, P8);

    left = leftShift(left, 2);
    right = leftShift(right, 2);
    K2 = permute(left + right, P8);
}

string fk(const string& half, const string& key) {
    string expanded = permute(half, EP);
    string xorResult = "";
    for (int i = 0; i < 8; i++) {
        xorResult += (expanded[i] == key[i] ? '0' : '1');
    }

    string left = xorResult.substr(0, 4);
    string right = xorResult.substr(4, 4);

    int row = stoi(string(1, left[0]) + left[3], nullptr, 2);
    int col = stoi(left.substr(1, 2), nullptr, 2);
    string s0Result = bitset<2>(S0[row][col]).to_string();

    row = stoi(string(1, right[0]) + right[3], nullptr, 2);
    col = stoi(right.substr(1, 2), nullptr, 2);
    string s1Result = bitset<2>(S1[row][col]).to_string();

    string combined = s0Result + s1Result;
    return permute(combined, P4);
}

string encrypt_SDES(const string& plaintext, const string& K1, const string& K2) {
    string permuted = permute(plaintext, IP);
    string left = permuted.substr(0, 4);
    string right = permuted.substr(4, 4);

    string temp = fk(right, K1);
    string newLeft = "";
    for (int i = 0; i < 4; i++) {
        newLeft += (left[i] == temp[i] ? '0' : '1');
    }

    string swapped = right + newLeft;
    left = swapped.substr(0, 4);
    right = swapped.substr(4, 4);

    temp = fk(right, K2);
    newLeft = "";
    for (int i = 0; i < 4; i++) {
        newLeft += (left[i] == temp[i] ? '0' : '1');
    }

    string preOutput = newLeft + right;
    return permute(preOutput, IP_INV);
}

string decrypt_SDES(const string& ciphertext, const string& K1, const string& K2) {
    return encrypt_SDES(ciphertext, K2, K1);
}

// Simplified AES (Substitution and Shift Rows only for demonstration)
string substitute(const string& input) {
    const string S_BOX[16] = {"6", "4", "C", "5", "8", "6", "7", "0", "2", "3", "1", "D", "B", "A", "F", "E"};
    string output = "";
    for (char c : input) {
        int value = c - '0';
        output += S_BOX[value];
    }
    return output;
}

string shiftRows(const string& input) {
    return input.substr(4) + input.substr(0, 4); // Example shift
}

string encrypt_AES(const string& plaintext, const string& key) {
    string substituted = substitute(plaintext);
    return shiftRows(substituted);
}

string decrypt_AES(const string& ciphertext, const string& key) {
    string shiftedBack = shiftRows(ciphertext); // Reverse shift rows
    return substitute(shiftedBack); // Reverse substitution
}

int main() {
    int choice;
    string key, input, K1, K2;

    cout << "Symmetric Algorithm Simulation\n";
    cout << "1. Encrypt (S-DES)\n2. Decrypt (S-DES)\n3. Encrypt (AES)\n4. Decrypt (AES)\n5. Exit\n";

    while (true) {
        cout << "Enter your choice: ";
        cin >> choice;

        if (choice == 5) {
            cout << "Exiting program.\n";
            break;
        }

        if (choice == 1 || choice == 2) {
            cout << "Enter a 10-bit key: ";
            cin >> key;

            if (!validateInput(key, 10)) {
                cout << "Invalid key. Please enter a binary string of length 10.\n";
                continue;
            }

            generateKeys_SDES(key, K1, K2);

            cout << "Enter 8-bit input: ";
            cin >> input;

            if (!validateInput(input, 8)) {
                cout << "Invalid input. Please enter a binary string of length 8.\n";
                continue;
            }

            if (choice == 1) {
                string ciphertext = encrypt_SDES(input, K1, K2);
                cout << "Ciphertext: " << ciphertext << "\n";
            } else {
                string plaintext = decrypt_SDES(input, K1, K2);
                cout << "Plaintext: " << plaintext << "\n";
            }
        } else if (choice == 3 || choice == 4) {
            cout << "Enter 16-bit key: ";
            cin >> key;

            cout << "Enter 16-bit input: ";
            cin >> input;

            if (choice == 3) {
                string ciphertext = encrypt_AES(input, key);
                cout << "Ciphertext: " << ciphertext << "\n";
            } else {
                string plaintext = decrypt_AES(input, key);
                cout << "Plaintext: " << plaintext << "\n";
            }
        } else {
            cout << "Invalid choice. Please select a valid option.\n";
        }
    }

    return 0;
}
