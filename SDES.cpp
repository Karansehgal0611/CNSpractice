#include <iostream>
#include <vector>
#include <bitset>
#include <algorithm>
#include <iomanip>


using namespace std;

// Permutation tables for SDES key generation
const vector<int> P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
const vector<int> P8 = {6, 3, 7, 4, 8, 5, 10, 9};

// Function to apply permutation
bitset<8> permute(const bitset<10>& input, const vector<int>& perm_table) {
    bitset<8> output;
    for (size_t i = 0; i < perm_table.size(); i++) {
        output[i] = input[perm_table[i] - 1]; // -1 because tables are 1-based
    }
    return output;
}

// Circular left shift function
bitset<5> leftShift(const bitset<5>& input, int shift) {
    bitset<5> output;
    for (int i = 0; i < 5; i++) {
        output[i] = input[(i + shift) % 5];
    }
    return output;
}

// Generate SDES subkeys K1 and K2 from a 10-bit key
pair<bitset<8>, bitset<8>> generateSDESKeys(const bitset<10>& original_key) {
    // Apply P10 permutation
    bitset<10> after_p10;
    for (size_t i = 0; i < P10.size(); i++) {
        after_p10[i] = original_key[P10[i] - 1];
    }

    // Split into left and right 5-bit halves
    bitset<5> left, right;
    for (int i = 0; i < 5; i++) {
        left[i] = after_p10[i];
        right[i] = after_p10[i + 5];
    }

    // Left shift both halves by 1
    left = leftShift(left, 1);
    right = leftShift(right, 1);

    // Combine for LS-1
    bitset<10> ls1;
    for (int i = 0; i < 5; i++) {
        ls1[i] = left[i];
        ls1[i + 5] = right[i];
    }

    // Generate K1 by applying P8
    bitset<8> k1 = permute(ls1, P8);

    // Left shift both halves by 2 (total shift of 3 from original)
    left = leftShift(left, 2);
    right = leftShift(right, 2);

    // Combine for LS-2
    bitset<10> ls2;
    for (int i = 0; i < 5; i++) {
        ls2[i] = left[i];
        ls2[i + 5] = right[i];
    }

    // Generate K2 by applying P8
    bitset<8> k2 = permute(ls2, P8);

    return make_pair(k1, k2);
}

int main() {
    string input;
    bitset<10> key;
    bool valid_input = false;

    while (!valid_input) {
        cout << "Enter a 10-bit key in either:\n"
             << "1. Binary format (e.g., 1010000010)\n"
             << "2. Hexadecimal format (e.g., 0x282 or 282)\n"
             << "Your input: ";
        cin >> input;

        try {
            // Check for hexadecimal input (starts with 0x or contains letters)
            if (input.find("0x") == 0 || input.find_first_of("abcdefABCDEF") != string::npos) {
                // Remove 0x prefix if present
                if (input.find("0x") == 0) {
                    input = input.substr(2);
                }

                // Convert hex string to unsigned long
                unsigned long hex_value = stoul(input, nullptr, 16);

                // Check if value fits in 10 bits
                if (hex_value > 0x3FF) {
                    throw out_of_range("Hexadecimal value too large for 10-bit key");
                }

                key = bitset<10>(hex_value);
                valid_input = true;
            }
            // Binary input
            else {
                // Check length
                if (input.length() != 10) {
                    throw invalid_argument("Binary input must be exactly 10 bits long");
                }

                // Check for invalid characters
                if (input.find_first_not_of("01") != string::npos) {
                    throw invalid_argument("Binary input can only contain 0s and 1s");
                }

                key = bitset<10>(input);
                valid_input = true;
            }
        } catch (const exception& e) {
            cout << "Invalid input: " << e.what() << "\nPlease try again.\n\n";
            cin.clear();
        }
    }

    // Generate subkeys
    auto [k1, k2] = generateSDESKeys(key);

    // Output results in multiple formats
    cout << "\nKey Generation Results:\n";
    cout << "----------------------\n";
    cout << "Original key (bin): " << key << endl;
    cout << "Original key (hex): 0x" << hex << setw(3) << setfill('0')
         << key.to_ulong() << dec << endl << endl;

    cout << "Subkey K1 (bin): " << k1 << endl;
    cout << "Subkey K1 (hex): 0x" << hex << setw(2) << setfill('0')
         << k1.to_ulong() << dec << endl << endl;

    cout << "Subkey K2 (bin): " << k2 << endl;
    cout << "Subkey K2 (hex): 0x" << hex << setw(2) << setfill('0')
         << k2.to_ulong() << dec << endl;

    return 0;
}

