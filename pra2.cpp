#include <iostream>
#include <vector>
#include <string>

using namespace std;

// Initial Permutation (IP)
int IP[8] = {1, 5, 2, 0, 3, 7, 4, 6};
// Inverse Initial Permutation (IP^-1)
int IP_inv[8] = {3, 0, 2, 4, 6, 1, 7, 5};
// P10 and P8 key permutations
int P10[10] = {2, 4, 1, 6, 3, 9, 0, 8, 7, 5};
int P8[8] = {5, 2, 6, 3, 7, 4, 9, 8};
// Expansion/Permutation (EP)
int EP[8] = {3, 0, 1, 2, 1, 2, 3, 0};
// P4 permutation
int P4[4] = {1, 3, 2, 0};

// S-Boxes
int S0[4][4] = {
    {1, 0, 3, 2},
    {3, 2, 1, 0},
    {0, 2, 1, 3},
    {3, 1, 0, 2}
};
int S1[4][4] = {
    {0, 1, 2, 3},
    {2, 0, 1, 3},
    {3, 0, 1, 2},
    {2, 1, 0, 3}
};

// Function to apply a permutation
vector<int> permute(vector<int> input, int* perm, int size) {
    vector<int> output(size);
    for (int i = 0; i < size; i++) {
        output[i] = input[perm[i]];
    }
    return output;
}

// Left Circular Shift
vector<int> leftShift(vector<int> key, int shifts) {
    vector<int> shifted(key.size());
    for (int i = 0; i < key.size(); i++) {
        shifted[i] = key[(i + shifts) % key.size()];
    }
    return shifted;
}

// Key Generation
void generateKeys(vector<int> masterKey, vector<int>& k1, vector<int>& k2) {
    vector<int> permutedKey = permute(masterKey, P10, 10);
    vector<int> leftHalf(permutedKey.begin(), permutedKey.begin() + 5);
    vector<int> rightHalf(permutedKey.begin() + 5, permutedKey.end());

    leftHalf = leftShift(leftHalf, 1);
    rightHalf = leftShift(rightHalf, 1);
    leftHalf.insert(leftHalf.end(), rightHalf.begin(), rightHalf.end());
    k1 = permute(leftHalf, P8, 8);

    leftHalf = leftShift(leftHalf, 2);
    rightHalf = leftShift(rightHalf, 2);
    leftHalf.insert(leftHalf.end(), rightHalf.begin(), rightHalf.end());
    k2 = permute(leftHalf, P8, 8);
}

// S-Box lookup
vector<int> sBoxLookup(int row, int col, int S[4][4]) {
    int value = S[row][col];
    return { (value >> 1) & 1, value & 1 };
}

// F-function
vector<int> fFunction(vector<int> right, vector<int> subkey) {
    vector<int> expanded = permute(right, EP, 8);
    for (int i = 0; i < 8; i++) expanded[i] ^= subkey[i];

    int row1 = expanded[0] * 2 + expanded[3];
    int col1 = expanded[1] * 2 + expanded[2];
    int row2 = expanded[4] * 2 + expanded[7];
    int col2 = expanded[5] * 2 + expanded[6];

    vector<int> sboxOut = sBoxLookup(row1, col1, S0);
    vector<int> sboxOut2 = sBoxLookup(row2, col2, S1);
    sboxOut.insert(sboxOut.end(), sboxOut2.begin(), sboxOut2.end());
    return permute(sboxOut, P4, 4);
}

// Encrypt or Decrypt
vector<int> feistelNetwork(vector<int> text, vector<int> k1, vector<int> k2, bool decrypt) {
    text = permute(text, IP, 8);
    vector<int> left(text.begin(), text.begin() + 4);
    vector<int> right(text.begin() + 4, text.end());

    vector<int> sk1 = decrypt ? k2 : k1;
    vector<int> sk2 = decrypt ? k1 : k2;

    vector<int> fOut = fFunction(right, sk1);
    for (int i = 0; i < 4; i++) left[i] ^= fOut[i];
    swap(left, right);
    fOut = fFunction(right, sk2);
    for (int i = 0; i < 4; i++) left[i] ^= fOut[i];
    left.insert(left.end(), right.begin(), right.end());
    return permute(left, IP_inv, 8);
}

int main() {
    string keyInput, textInput;
    cout << "Enter 10-bit Master Key: ";
    cin >> keyInput;
    if (keyInput.length() != 10) {
        cerr << "Error: Enter exactly 10 bits." << endl;
        return 1;
    }
    
    vector<int> masterKey(10);
    for (int i = 0; i < 10; i++) masterKey[i] = keyInput[i] - '0';
    
    vector<int> k1, k2;
    generateKeys(masterKey, k1, k2);
    
    cout << "Enter 8-bit Plaintext: ";
    cin >> textInput;
    if (textInput.length() != 8) {
        cerr << "Error: Enter exactly 8 bits." << endl;
        return 1;
    }
    
    vector<int> plaintext(8);
    for (int i = 0; i < 8; i++) plaintext[i] = textInput[i] - '0';
    
    vector<int> ciphertext = feistelNetwork(plaintext, k1, k2, false);
    cout << "Ciphertext: ";
    for (int bit : ciphertext) cout << bit;
    cout << endl;
    
    vector<int> decryptedText = feistelNetwork(ciphertext, k1, k2, true);
    cout << "Decrypted Text: ";
    for (int bit : decryptedText) cout << bit;
    cout << endl;
    
    return 0;
}
