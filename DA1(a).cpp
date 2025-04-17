#include <iostream>
#include <vector>
#include <string>
#include <cctype>
#include <algorithm>
using namespace std;

// Function prototypes
void caesarCipher();
void playfairCipher();
void hillCipher();

// Utility functions
void toUpperCase(string& str);

int main() {
    int choice;
    do {
        cout << "\nCipher Simulation Program\n";
        cout << "1. Caesar Cipher\n";
        cout << "2. Playfair Cipher\n";
        cout << "3. Hill Cipher\n";
        cout << "4. Exit\n";
        cout << "Enter your choice: ";
        cin >> choice;
        cin.ignore(); // Clear the input buffer

        switch (choice) {
            case 1:
                caesarCipher();
                break;
            case 2:
                playfairCipher();
                break;
            case 3:
                hillCipher();
                break;
            case 4:
                cout << "Exiting the program.\n";
                break;
            default:
                cout << "Invalid choice. Please try again.\n";
        }
    } while (choice != 4);

    return 0;
}

void caesarCipher() {
    string text, result;
    int shift;

    cout << "Enter text: ";
    getline(cin, text);

    cout << "Enter shift (key): ";
    cin >> shift;
    cin.ignore();

    toUpperCase(text);

    for (char ch : text) {
        if (isalpha(ch)) {
            result += ((ch - 'A' + shift) % 26) + 'A';
        } else {
            result += ch;
        }
    }

    cout << "Encrypted text: " << result << "\n";
}

void playfairCipher() {
    string text, key;
    char matrix[5][5];
    bool used[26] = {false};

    cout << "Enter text: ";
    getline(cin, text);

    cout << "Enter key: ";
    getline(cin, key);

    toUpperCase(text);
    toUpperCase(key);

    // Generate Playfair matrix
    int row = 0, col = 0;
    for (char ch : key) {
        if (!used[ch - 'A'] && ch != 'J') {
            matrix[row][col++] = ch;
            used[ch - 'A'] = true;
            if (col == 5) {
                col = 0;
                row++;
            }
        }
    }

    for (char c = 'A'; c <= 'Z'; c++) {
        if (!used[c - 'A'] && c != 'J') {
            matrix[row][col++] = c;
            used[c - 'A'] = true;
            if (col == 5) {
                col = 0;
                row++;
            }
        }
    }

    cout << "Playfair matrix:\n";
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            cout << matrix[i][j] << ' ';
        }
        cout << "\n";
    }

    // Encryption logic is omitted for simplicity
}

void hillCipher() {
    int n;
    cout << "Enter matrix size (n x n): ";
    cin >> n;

    vector<vector<int>> key(n, vector<int>(n));
    string text, result;

    cout << "Enter key matrix:\n";
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            cin >> key[i][j];
        }
    }
    cin.ignore();

    cout << "Enter text: ";
    getline(cin, text);

    toUpperCase(text);
    int len = text.length();
    if (len % n != 0) {
        for (int i = len; i < len + (n - len % n); i++) {
            text += 'X';
        }
    }

    len = text.length();
    for (int i = 0; i < len; i += n) {
        for (int j = 0; j < n; j++) {
            int sum = 0;
            for (int k = 0; k < n; k++) {
                sum += key[j][k] * (text[i + k] - 'A');
            }
            result += (sum % 26) + 'A';
        }
    }

    cout << "Encrypted text: " << result << "\n";
}

void toUpperCase(string& str) {
    transform(str.begin(), str.end(), str.begin(), ::toupper);
}
