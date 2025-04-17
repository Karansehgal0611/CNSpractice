//22BCE3939
//Karan Sehgal
//DA1 Implementation of Caesar, Playfair and Hill Cipher in C++
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cmath>
using namespace std;

// Utility functions remain the same
string removeSpaces(string str) {
    str.erase(remove(str.begin(), str.end(), ' '), str.end());
    return str;
}

string toUpperCase(string str) {
    transform(str.begin(), str.end(), str.begin(), ::toupper);
    return str;
}

bool isValidInput(string str) {
    return all_of(str.begin(), str.end(), [](char c) { 
        return isalpha(c) || isspace(c); 
    });
}

// Caesar Cipher functions 
string caesarEncrypt(string text, int shift) {
    string result = "";
    for(char c : text) {
        if(isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            result += char(base + (c - base + shift) % 26);
        } else {
            result += c;
        }
    }
    return result;
}

string caesarDecrypt(string text, int shift) {
    return caesarEncrypt(text, 26 - shift);
}

// Enhanced Playfair Cipher functions
void generatePlayfairMatrix(string key, char matrix[5][5]) {
    bool used[26] = {false};
    used['J' - 'A'] = true;
    
    int row = 0, col = 0;
    key = toUpperCase(removeSpaces(key));
    
    for(char c : key) {
        if(!used[c - 'A']) {
            matrix[row][col] = c;
            used[c - 'A'] = true;
            col++;
            if(col == 5) {
                col = 0;
                row++;
            }
        }
    }
    
    for(char c = 'A'; c <= 'Z'; c++) {
        if(!used[c - 'A']) {
            matrix[row][col] = c;
            col++;
            if(col == 5) {
                col = 0;
                row++;
            }
        }
    }
}

void findPosition(char matrix[5][5], char c, int& row, int& col) {
    if(c == 'J') c = 'I';
    for(int i = 0; i < 5; i++)
        for(int j = 0; j < 5; j++)
            if(matrix[i][j] == c) {
                row = i;
                col = j;
                return;
            }
}

string playfairEncrypt(string text, string key) {
    char matrix[5][5];
    generatePlayfairMatrix(key, matrix);
    
    text = toUpperCase(removeSpaces(text));
    if(text.length() % 2 != 0) text += 'X';
    
    string result = "";
    for(size_t i = 0; i < text.length(); i += 2) {
        int row1, col1, row2, col2;
        findPosition(matrix, text[i], row1, col1);
        findPosition(matrix, text[i+1], row2, col2);
        
        if(row1 == row2) {
            result += matrix[row1][(col1 + 1) % 5];
            result += matrix[row2][(col2 + 1) % 5];
        }
        else if(col1 == col2) {
            result += matrix[(row1 + 1) % 5][col1];
            result += matrix[(row2 + 1) % 5][col2];
        }
        else {
            result += matrix[row1][col2];
            result += matrix[row2][col1];
        }
    }
    return result;
}

string playfairDecrypt(string text, string key) {
    char matrix[5][5];
    generatePlayfairMatrix(key, matrix);
    
    string result = "";
    for(size_t i = 0; i < text.length(); i += 2) {
        int row1, col1, row2, col2;
        findPosition(matrix, text[i], row1, col1);
        findPosition(matrix, text[i+1], row2, col2);
        
        if(row1 == row2) {
            result += matrix[row1][(col1 + 4) % 5];
            result += matrix[row2][(col2 + 4) % 5];
        }
        else if(col1 == col2) {
            result += matrix[(row1 + 4) % 5][col1];
            result += matrix[(row2 + 4) % 5][col2];
        }
        else {
            result += matrix[row1][col2];
            result += matrix[row2][col1];
        }
    }
    return result;
}

// Enhanced Hill Cipher functions
int modInverse(int a) {
    for(int i = 1; i < 26; i++)
        if(((a % 26) * (i % 26)) % 26 == 1)
            return i;
    return -1;
}

void getCofactor(vector<vector<int>>& matrix, vector<vector<int>>& temp, int p, int q, int n) {
    int i = 0, j = 0;
    for(int row = 0; row < n; row++) {
        for(int col = 0; col < n; col++) {
            if(row != p && col != q) {
                temp[i][j++] = matrix[row][col];
                if(j == n - 1) {
                    j = 0;
                    i++;
                }
            }
        }
    }
}

int determinant(vector<vector<int>>& matrix, int n) {
    if(n == 1) return matrix[0][0];
    int D = 0;
    vector<vector<int>> temp(n, vector<int>(n));
    int sign = 1;
    for(int f = 0; f < n; f++) {
        getCofactor(matrix, temp, 0, f, n);
        D += sign * matrix[0][f] * determinant(temp, n-1);
        sign = -sign;
    }
    return D;
}

void adjoint(vector<vector<int>>& matrix, vector<vector<int>>& adj) {
    int N = matrix.size();
    if(N == 1) {
        adj[0][0] = 1;
        return;
    }
    int sign = 1;
    vector<vector<int>> temp(N, vector<int>(N));
    
    for(int i = 0; i < N; i++) {
        for(int j = 0; j < N; j++) {
            getCofactor(matrix, temp, i, j, N);
            sign = ((i+j) % 2 == 0)? 1: -1;
            adj[j][i] = (sign) * (determinant(temp, N-1));
            adj[j][i] = ((adj[j][i] % 26) + 26) % 26;
        }
    }
}

void getKeyMatrix(string key, vector<vector<int>>& keyMatrix, int size) {
    if (key.length() != size * size) {
        throw runtime_error("Key length must be " + to_string(size * size));
    }
    int k = 0;
    for(int i = 0; i < size; i++)
        for(int j = 0; j < size; j++)
            keyMatrix[i][j] = (key[k++] - 'A') % 26;
}

string hillEncrypt(string text, string key, int size) {
    vector<vector<int>> keyMatrix(size, vector<int>(size));
    getKeyMatrix(key, keyMatrix, size);
    
    while(text.length() % size != 0)
        text += 'X';
    
    string result = "";
    for(size_t i = 0; i < text.length(); i += size) {
        for(int j = 0; j < size; j++) {
            int sum = 0;
            for(int k = 0; k < size; k++) {
                sum += keyMatrix[j][k] * (text[i + k] - 'A');
            }
            result += char((sum % 26) + 'A');
        }
    }
    return result;
}

string hillDecrypt(string text, string key, int size) {
    vector<vector<int>> keyMatrix(size, vector<int>(size));
    getKeyMatrix(key, keyMatrix, size);
    
    int det = determinant(keyMatrix, size);
    det = ((det % 26) + 26) % 26;
    int detInv = modInverse(det);
    
    if(detInv == -1) {
        return "Invalid key: inverse doesn't exist!";
    }
    
    vector<vector<int>> adj(size, vector<int>(size));
    adjoint(keyMatrix, adj);
    
    for(int i = 0; i < size; i++)
        for(int j = 0; j < size; j++)
            keyMatrix[i][j] = (detInv * adj[i][j]) % 26;
    
    string result = "";
    for(size_t i = 0; i < text.length(); i += size) {
        for(int j = 0; j < size; j++) {
            int sum = 0;
            for(int k = 0; k < size; k++) {
                sum += keyMatrix[j][k] * (text[i + k] - 'A');
            }
            result += char(((sum % 26) + 26) % 26 + 'A');
        }
    }
    return result;
}


int main() {
    int choice;
    string text, key;
    
    do {
        cout << "\nCipher Menu:\n";
        cout << "1. Caesar Cipher Encrypt\n";
        cout << "2. Caesar Cipher Decrypt\n";
        cout << "3. Playfair Cipher Encrypt\n";
        cout << "4. Playfair Cipher Decrypt\n";
        cout << "5. Hill Cipher Encrypt\n";
        cout << "6. Hill Cipher Decrypt\n";
        cout << "7. Exit\n";
        cout << "Enter choice (1-7): ";
        cin >> choice;
        cin.ignore();
        
        if(choice >= 1 && choice <= 6) {
            cout << "Enter text: ";
            getline(cin, text);
            
            if(!isValidInput(text)) {
                cout << "Invalid input! Use only alphabets and spaces.\n";
                continue;
            }

            
            switch(choice) {
                case 1: {
                    int shift;
                    cout << "Enter shift value (1-25): ";
                    cin >> shift;
                    if(shift < 1 || shift > 25) {
                        cout << "Invalid shift value!\n";
                        break;
                    }
                    cout << "Encrypted: " << caesarEncrypt(text, shift) << endl;
                    break;
                }
                case 2: {
                    int shift;
                    cout << "Enter shift value (1-25): ";
                    cin >> shift;
                    if(shift < 1 || shift > 25) {
                        cout << "Invalid shift value!\n";
                        break;
                    }
                    cout << "Decrypted: " << caesarDecrypt(text, shift) << endl;
                    break;
                }
                case 3: {
                    cout << "Enter key: ";
                    cin >> key;
                    if(!isValidInput(key)) {
                        cout << "Invalid key! Use only alphabets.\n";
                        break;
                    }
                    cout << "Encrypted: " << playfairEncrypt(text, key) << endl;
                    break;
                }
                case 4: {
                    cout << "Enter key: ";
                    cin >> key;
                    if(!isValidInput(key)) {
                        cout << "Invalid key! Use only alphabets.\n";
                        break;
                    }
                    cout << "Decrypted: " << playfairDecrypt(text, key) << endl;
                    break;
                }
                case 5: {
                        int size;
                        cout << "Enter matrix size (n): ";
                        cin >> size;
                        cout << "Enter key (" << size * size << " letters): ";
                        cin >> key;
                        if(!isValidInput(key)) {
                            cout << "Invalid key! Use only alphabets.\n";
                            break;
                        }
                        key = toUpperCase(key);
                        cout << "Encrypted: " << hillEncrypt(toUpperCase(removeSpaces(text)), toUpperCase(key), size) << endl;
                        break;
                    }
                case 6: {
                        int size;
                        cout << "Enter matrix size (n): ";
                        cin >> size;
                        cout << "Enter key (" << size * size << " letters): ";
                        cin >> key;
                        if(!isValidInput(key)) {
                            cout << "Invalid key! Use only alphabets.\n";
                            break;
                        }
                        key = toUpperCase(key);
                        cout << "Decrypted: " << hillDecrypt(toUpperCase(removeSpaces(text)),toUpperCase(key), size) << endl;
                        break;
                    }
            }
        }
    } while(choice != 7);
    
    return 0;
}