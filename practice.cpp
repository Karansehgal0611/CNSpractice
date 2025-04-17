#include <iostream>
#include <bitset>
#include <regex>

using namespace std;

bitset<8> getValidInput() {
    string input;
    regex binaryPattern("^[01]{8}$");
    
    while (true) {
        cin >> input;
        if (regex_match(input, binaryPattern)) {
            return bitset<8>(input);
        } else {
            cout << "Invalid input. Please enter an 8-bit binary number: ";
        }
    }
}

// Majority function (SHA Maj function): 
bitset<8> Maj(bitset<8> x, bitset<8> y, bitset<8> z) {
    cout<<"\n";
    cout << "Step 1: (x & y) = " << (x & y) << endl;
    cout << "Step 2: (x & z) = " << (x & z) << endl;
    cout << "Step 3: (y & z) = " << (y & z) << endl;
    return (x & y) ^ (x & z) ^ (y & z);
}

// Conditional function (SHA Ch function): 
bitset<8> Ch(bitset<8> x, bitset<8> y, bitset<8> z) {
    cout<<"\n";
    cout << "Step 1: (x & y) = " << (x & y) << endl;
    cout << "Step 2: (~x & z) = " << (~x & z) << endl;
    return (x & y) ^ (~x & z);
}

void performBitwiseOperations(bitset<8> a, bitset<8> b) {
    //  Bitwise operations
    bitset<8> andResult = a & b;
    bitset<8> xorResult = a ^ b;
    bitset<8> negA = ~a;
    bitset<8> negB = ~b;
    
    cout << "Input A:       " << a << endl;
    cout << "Input B:       " << b << endl;
    cout << "Bitwise AND:   " << andResult << endl;
    cout << "Bitwise XOR:   " << xorResult << endl;
    cout << "Negation A:    " << negA << endl;
    cout << "Negation B:    " << negB << endl;
    cout << "-------------------------------\n";
}

int main() {
    int choice;
    bitset<8> a, b, c;
    
    do {
        cout << "\nMenu:" << endl;
        cout << "1. Perform Bitwise Operations (AND, XOR, Negation)" << endl;
        cout << "2. Compute Majority Function (SHA Maj)" << endl;
        cout << "3. Compute Conditional Function (SHA Ch)" << endl;
        cout << "4. Exit" << endl;
        cout << "Enter your choice: ";
        cin >> choice;
        
        switch (choice) {
            case 1:
                cout << "Enter first 8-bit binary number: ";
                a = getValidInput();
                cout << "Enter second 8-bit binary number: ";
                b = getValidInput();
                performBitwiseOperations(a, b);
                break;
            
            case 2:
                cout << "Enter first 8-bit binary number: ";
                a = getValidInput();
                cout << "Enter second 8-bit binary number: ";
                b = getValidInput();
                cout << "Enter third 8-bit binary number: ";
                c = getValidInput();
                cout << "Maj(" << a << ", " << b << ", " << c << ") = " << Maj(a, b, c) << endl;
                break;
            
            case 3:
                cout << "Enter first 8-bit binary number: ";
                a = getValidInput();
                cout << "Enter second 8-bit binary number: ";
                b = getValidInput();
                cout << "Enter third 8-bit binary number: ";
                c = getValidInput();
                cout << "Ch(" << a << ", " << b << ", " << c << ") = " << Ch(a, b, c) << endl;
                break;
            
            case 4:
                cout << "Exiting program..." << endl;
                break;
            
            default:
                cout << "Invalid choice. Please try again." << endl;
        }
    } while (choice != 4);
    
    return 0;
}
