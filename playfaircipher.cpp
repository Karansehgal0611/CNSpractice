#include <iostream>
#include <vector>
#include <algorithm>

using namespace std;

class PlayfairCipher {
private:
    char keyMatrix[5][5];

    void generateKeyMatrix(string key) {
        string tempKey = "";
        vector<bool> used(26, false);

        for (char c : key) {
            if (c == 'j') c = 'i';
            if (!used[c - 'a']) {
                tempKey += c;
                used[c - 'a'] = true;
            }
        }

        for (char c = 'a'; c <= 'z'; ++c) {
            if (c == 'j') continue;
            if (!used[c - 'a']) {
                tempKey += c;
                used[c - 'a'] = true;
            }
        }

        int k = 0;
        for (int i = 0; i < 5; ++i) {
            for (int j = 0; j < 5; ++j) {
                keyMatrix[i][j] = tempKey[k++];
            }
        }
    }

    pair<int, int> findPosition(char c) {
        if (c == 'j') c = 'i';
        for (int i = 0; i < 5; ++i) {
            for (int j = 0; j < 5; ++j) {
                if (keyMatrix[i][j] == c) {
                    return {i, j};
                }
            }
        }
        return {-1, -1};
    }

    string processText(string text, bool encrypt) {
        string result = "";
        for (int i = 0; i < text.length(); i += 2) {
            if (i + 1 == text.length() || text[i] == text[i + 1]) {
                text.insert(i + 1, "x");
            }
            auto pos1 = findPosition(text[i]);
            auto pos2 = findPosition(text[i + 1]);

            if (pos1.first == pos2.first) {
                result += keyMatrix[pos1.first][(pos1.second + (encrypt ? 1 : 4)) % 5];
                result += keyMatrix[pos2.first][(pos2.second + (encrypt ? 1 : 4)) % 5];
            } else if (pos1.second == pos2.second) {
                result += keyMatrix[(pos1.first + (encrypt ? 1 : 4)) % 5][pos1.second];
                result += keyMatrix[(pos2.first + (encrypt ? 1 : 4)) % 5][pos2.second];
            } else {
                result += keyMatrix[pos1.first][pos2.second];
                result += keyMatrix[pos2.first][pos1.second];
            }
        }
        return result;
    }

public:
    PlayfairCipher(string key) {
        generateKeyMatrix(key);
    }

    string encrypt(string plaintext) {
        return processText(plaintext, true);
    }

    string decrypt(string ciphertext) {
        return processText(ciphertext, false);
    }
};

int main() {
    string key;
    cout << "Enter the key: ";
    getline(cin, key);
    PlayfairCipher cipher(key);

    string plaintext;
    cout << "Enter the plaintext: ";
    getline(cin, plaintext);

    string ciphertext = cipher.encrypt(plaintext);
    cout << "Encrypted: " << ciphertext << endl;

    string decryptedtext = cipher.decrypt(ciphertext);
    cout << "Decrypted: " << decryptedtext << endl;

    return 0;
}