#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <stdexcept>
#include <algorithm>
using namespace std;

vector<vector<int>> getKeyMatrix(int n) {
    cout << "Enter key matrix (row-wise as a single string): ";
    string key;
    cin >> key;

    if (key.length() != n * n) {
        throw invalid_argument("Key length does not match the required matrix size.");
    }

    vector<vector<int>> keyMatrix(n, vector<int>(n));
    int k = 0;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            keyMatrix[i][j] = key[k++] - 'a';
        }
    }
    return keyMatrix;
}

int determinantModulo26(vector<vector<int>>& matrix, int n) {
    if (n == 1) return matrix[0][0] % 26;

    int det = 0;
    vector<vector<int>> subMatrix(n - 1, vector<int>(n - 1));

    for (int x = 0; x < n; x++) {
        int subi = 0;
        for (int i = 1; i < n; i++) {
            int subj = 0;
            for (int j = 0; j < n; j++) {
                if (j == x) continue;
                subMatrix[subi][subj] = matrix[i][j];
                subj++;
            }
            subi++;
        }
        det = (det + (x % 2 == 0 ? 1 : -1) * matrix[0][x] * determinantModulo26(subMatrix, n - 1)) % 26;
    }
    return (det + 26) % 26;
}

vector<vector<int>> inverseKeyMatrix(vector<vector<int>>& keyMatrix, int n) {
    int det = determinantModulo26(keyMatrix, n);
    if (det == 0) {
        throw invalid_argument("Determinant is zero. Key matrix is not invertible.");
    }

    int detInverse = -1;
    for (int i = 1; i < 26; i++) {
        if ((det * i) % 26 == 1) {
            detInverse = i;
            break;
        }
    }
    if (detInverse == -1) {
        throw invalid_argument("Determinant has no modular inverse under modulo 26.");
    }

    vector<vector<int>> adjMatrix(n, vector<int>(n));
    vector<vector<int>> subMatrix(n - 1, vector<int>(n - 1));

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            int subi = 0;
            for (int x = 0; x < n; x++) {
                if (x == i) continue;
                int subj = 0;
                for (int y = 0; y < n; y++) {
                    if (y == j) continue;
                    subMatrix[subi][subj] = keyMatrix[x][y];
                    subj++;
                }
                subi++;
            }
            int cofactor = determinantModulo26(subMatrix, n - 1);
            adjMatrix[j][i] = ((i + j) % 2 == 0 ? cofactor : -cofactor + 26) % 26;
        }
    }

    vector<vector<int>> invMatrix(n, vector<int>(n));
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            invMatrix[i][j] = (adjMatrix[i][j] * detInverse) % 26;
        }
    }
    return invMatrix;
}

vector<int> stringToVector(const string& str, bool alphaZero) {
    vector<int> vec;
    int offset = alphaZero ? 0 : 1;
    for (char c : str) {
        vec.push_back(c - 'A' + offset);
    }
    return vec;
}

string vectorToString(const vector<int>& vec, bool alphaZero) {
    string str;
    int offset = alphaZero ? 0 : 1;
    for (int val : vec) {
        str.push_back((val + 26) % 26 + 'A' - offset);
    }
    return str;
}

vector<int> matrixVectorProduct(vector<vector<int>>& matrix, vector<int>& vec, int n) {
    vector<int> result(n, 0);
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            result[i] = (result[i] + matrix[i][j] * vec[j]) % 26;
        }
    }
    return result;
}

string encrypt(const string& phrase, vector<vector<int>>& keyMatrix, int n, bool alphaZero) {
    string formattedPhrase = phrase;
    formattedPhrase.erase(remove_if(formattedPhrase.begin(), formattedPhrase.end(), [](char c) { return !isalpha(c); }), formattedPhrase.end());
    transform(formattedPhrase.begin(), formattedPhrase.end(), formattedPhrase.begin(), ::toupper);

    while (formattedPhrase.length() % n != 0) {
        formattedPhrase.push_back('X');
    }

    vector<int> numericPhrase = stringToVector(formattedPhrase, alphaZero);
    string encryptedPhrase;

    for (size_t i = 0; i < numericPhrase.size(); i += n) {
        vector<int> block(n);
        for (int j = 0; j < n; j++) {
            block[j] = numericPhrase[i + j];
        }
        vector<int> encryptedBlock = matrixVectorProduct(keyMatrix, block, n);
        encryptedPhrase += vectorToString(encryptedBlock, alphaZero);
    }
    return encryptedPhrase;
}

string decrypt(const string& phrase, vector<vector<int>>& keyMatrix, int n, bool alphaZero) {
    vector<vector<int>> inverseMatrix = inverseKeyMatrix(keyMatrix, n);
    vector<int> numericPhrase = stringToVector(phrase, alphaZero);
    string decryptedPhrase;

    for (size_t i = 0; i < numericPhrase.size(); i += n) {
        vector<int> block(n);
        for (int j = 0; j < n; j++) {
            block[j] = numericPhrase[i + j];
        }
        vector<int> decryptedBlock = matrixVectorProduct(inverseMatrix, block, n);
        decryptedPhrase += vectorToString(decryptedBlock, alphaZero);
    }
    return decryptedPhrase;
}

int main() {
    while (true) {
        cout << "Hill Cipher Implementation (n x n)" << endl;
        cout << "--------------------------------" << endl;
        cout << "1. Set key matrix" << endl;
        cout << "2. Encrypt text (A=0,B=1,...Z=25)" << endl;
        cout << "3. Decrypt text (A=0,B=1,...Z=25)" << endl;
        cout << "4. Exit" << endl;
        cout << "Choose an option: ";

        int choice;
        cin >> choice;
        cin.ignore();

        static vector<vector<int>> keyMatrix;
        static int n;
        static bool keySet = false;

        if (choice == 1) {
            cout << "Enter the size of the key matrix (n): ";
            cin >> n;
            cin.ignore();
            try {
                keyMatrix = getKeyMatrix(n);
                keySet = true;
                cout << "Key matrix set successfully." << endl;
            } catch (const exception& e) {
                cout << "Error: " << e.what() << endl;
            }
        } else if (choice == 2 || choice == 3) {
            if (!keySet) {
                cout << "Key matrix not set. Please set the key matrix first." << endl;
                continue;
            }

            cout << "Enter the phrase: ";
            string phrase;
            getline(cin, phrase);

            bool alphaZero = true;

            try {
                if (choice == 2) {
                    string encrypted = encrypt(phrase, keyMatrix, n, alphaZero);
                    cout << "Encrypted text: " << encrypted << endl;
                } else if (choice == 3) {
                    string decrypted = decrypt(phrase, keyMatrix, n, alphaZero);
                    cout << "Decrypted text: " << decrypted << endl;
                }
            } catch (const exception& e) {
                cout << "Error: " << e.what() << endl;
            }
        } else if (choice == 4) {
            break;
        } else {
            cout << "Invalid option!" << endl;
        }
    }

    return 0;
}
