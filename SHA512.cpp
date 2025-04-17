
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <string>
#include <sstream>

using namespace std;

// Rotate right functions
static uint64_t rotr64(uint64_t x, int shift) {
    return (x >> shift) | (x << (64 - shift));
}

static uint32_t rotr32(uint32_t x, int shift) {
    return (x >> shift) | (x << (32 - shift));
}

// Bitwise choice function
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

// Majority function
static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// SHA-256 sigma functions
static uint32_t sigma0_32(uint32_t x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static uint32_t sigma1_32(uint32_t x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

// SHA-512 sigma functions
static uint64_t sigma0_64(uint64_t x) {
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

static uint64_t sigma1_64(uint64_t x) {
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

// Function to get numeric input from user
template<typename T>
T getInput(const string& prompt) {
    T value;
    while (true) {
        cout << prompt;
        string input;
        getline(cin, input);

        stringstream ss(input);
        if (ss >> value) {
            // Check if there's remaining input
            string remaining;
            if (ss >> remaining) {
                cout << "Invalid input. Please enter a single number.\n";
            } else {
                break;
            }
        } else {
            cout << "Invalid input. Please enter a valid number.\n";
        }
    }
    return value;
}

// Function to print binary representation
void printBinary(uint64_t value, int bits = 64) {
    cout << "Binary: ";
    for (int i = bits-1; i >= 0; i--) {
        cout << ((value >> i) & 1);
        if (i % 8 == 0 && i != 0) cout << " ";
    }
    cout << endl;
}

// Function to print hexadecimal representation
void printHex(uint64_t value, int bits = 64) {
    int digits = bits / 4;
    cout << "Hex: 0x" << hex << setw(digits) << setfill('0') << value << dec << endl;
}

// Main menu
void showMenu() {
    cout << "\nSHA-512 Helper Functions Simulator\n";
    cout << "--------------------------------\n";
    cout << "1. Rotate Right (64-bit)\n";
    cout << "2. Rotate Right (32-bit)\n";
    cout << "3. Choice Function (ch)\n";
    cout << "4. Majority Function (maj)\n";
    cout << "5. SHA-256 Sigma0 (σ0)\n";
    cout << "6. SHA-256 Sigma1 (σ1)\n";
    cout << "7. SHA-512 Sigma0 (Σ0)\n";
    cout << "8. SHA-512 Sigma1 (Σ1)\n";
    cout << "9. Exit\n";
    cout << "--------------------------------\n";
    cout << "Enter your choice: ";
}

int main() {
    while (true) {
        showMenu();
        int choice = getInput<int>("");

        if (choice == 9) break;

        switch (choice) {
            case 1: {
                uint64_t x = getInput<uint64_t>("Enter 64-bit value (decimal): ");
                int shift = getInput<int>("Enter shift amount: ");
                uint64_t result = rotr64(x, shift);

                cout << "\nRotate Right 64-bit:\n";
                cout << "Input:    " << x << endl;
                printBinary(x);
                cout << "Shift:    " << shift << endl;
                cout << "Result:   " << result << endl;
                printBinary(result);
                printHex(result);
                break;
            }

            case 2: {
                uint32_t x = getInput<uint32_t>("Enter 32-bit value (decimal): ");
                int shift = getInput<int>("Enter shift amount: ");
                uint32_t result = rotr32(x, shift);

                cout << "\nRotate Right 32-bit:\n";
                cout << "Input:    " << x << endl;
                printBinary(x, 32);
                cout << "Shift:    " << shift << endl;
                cout << "Result:   " << result << endl;
                printBinary(result, 32);
                printHex(result, 32);
                break;
            }

            case 3: {
                uint32_t x = getInput<uint32_t>("Enter x (32-bit): ");
                uint32_t y = getInput<uint32_t>("Enter y (32-bit): ");
                uint32_t z = getInput<uint32_t>("Enter z (32-bit): ");
                uint32_t result = ch(x, y, z);

                cout << "\nChoice Function (ch):\n";
                cout << "x:        " << x << endl;
                printBinary(x, 32);
                cout << "y:        " << y << endl;
                printBinary(y, 32);
                cout << "z:        " << z << endl;
                printBinary(z, 32);
                cout << "Result:   " << result << endl;
                printBinary(result, 32);
                printHex(result, 32);
                break;
            }

            case 4: {
                uint32_t x = getInput<uint32_t>("Enter x (32-bit): ");
                uint32_t y = getInput<uint32_t>("Enter y (32-bit): ");
                uint32_t z = getInput<uint32_t>("Enter z (32-bit): ");
                uint32_t result = maj(x, y, z);

                cout << "\nMajority Function (maj):\n";
                cout << "x:        " << x << endl;
                printBinary(x, 32);
                cout << "y:        " << y << endl;
                printBinary(y, 32);
                cout << "z:        " << z << endl;
                printBinary(z, 32);
                cout << "Result:   " << result << endl;
                printBinary(result, 32);
                printHex(result, 32);
                break;
            }

            case 5: {
                uint32_t x = getInput<uint32_t>("Enter 32-bit value: ");
                uint32_t result = sigma0_32(x);

                cout << "\nSHA-256 Sigma0 (σ0):\n";
                cout << "Input:    " << x << endl;
                printBinary(x, 32);
                cout << "Result:   " << result << endl;
                printBinary(result, 32);
                printHex(result, 32);
                break;
            }

            case 6: {
                uint32_t x = getInput<uint32_t>("Enter 32-bit value: ");
                uint32_t result = sigma1_32(x);

                cout << "\nSHA-256 Sigma1 (σ1):\n";
                cout << "Input:    " << x << endl;
                printBinary(x, 32);
                cout << "Result:   " << result << endl;
                printBinary(result, 32);
                printHex(result, 32);
                break;
            }

            case 7: {
                uint64_t x = getInput<uint64_t>("Enter 64-bit value: ");
                uint64_t result = sigma0_64(x);

                cout << "\nSHA-512 Sigma0 (Σ0):\n";
                cout << "Input:    " << x << endl;
                printBinary(x);
                cout << "Result:   " << result << endl;
                printBinary(result);
                printHex(result);
                break;
            }

            case 8: {
                uint64_t x = getInput<uint64_t>("Enter 64-bit value: ");
                uint64_t result = sigma1_64(x);

                cout << "\nSHA-512 Sigma1 (Σ1):\n";
                cout << "Input:    " << x << endl;
                printBinary(x);
                cout << "Result:   " << result << endl;
                printBinary(result);
                printHex(result);
                break;
            }

            default:
                cout << "Invalid choice. Please try again.\n";
        }
    }

    cout << "Exiting SHA-512 Helper Functions Simulator.\n";
    return 0;
}
