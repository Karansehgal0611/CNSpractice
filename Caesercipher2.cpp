#include <bits/stdc++.h>
#include <vector>
#include <algorithm>
using namespace std;

void addition_cipher()
{
    string s;
    cout << "Enter a string to be encrypted: ";
    cin.ignore();
    getline(cin, s);

    cout << "Enter the key value: ";
    int key;
    cin >> key;

    string encrypted_string = "";
    for (char c : s)
    {
        if (isalpha(c))
        {
            if (isupper(c))
                encrypted_string += (c - 'A' + key) % 26 + 'A';
            else
                encrypted_string += (c - 'a' + key) % 26 + 'a';
        }
        else
        {
            encrypted_string += c;
        }
    }

    cout << "Encrypted: " << encrypted_string << endl;

    string decrypted_string = "";
    for (char c : encrypted_string)
    {
        if (isalpha(c))
        {
            if (isupper(c))
                decrypted_string += (c - 'A' - key + 26) % 26 + 'A';
            else
                decrypted_string += (c - 'a' - key + 26) % 26 + 'a';
        }
        else
        {
            decrypted_string += c;
        }
    }

    cout << "Decrypted: " << decrypted_string << endl;
}

int modInverse(int a, int m)
{
    a = a % m;
    for (int x = 1; x < m; x++)
        if ((a * x) % m == 0)
            return x;
    return 1;
}

void multiplication_cipher()
{
    // modInverse function is already defined globally
    string s;
    cout << "Enter a string to be encrypted: ";
    cin.ignore();
    getline(cin, s);

    cout << "Enter the key value: ";
    int key;
    cin >> key;

    string encrypted_string = "";
    for (char c : s)
    {
        if (isalpha(c))
        {
            if (isupper(c))
                encrypted_string += ((c - 'A') * key) % 26 + 'A';
            else
                encrypted_string += ((c - 'a') * key) % 26 + 'a';
        }
        else
        {
            encrypted_string += c;
        }
    }

    cout << "Encrypted: " << encrypted_string << endl;

    string decrypted_string = "";
    for (char c : encrypted_string)
    {
        if (isalpha(c))
        {
            if (isupper(c))
                decrypted_string += ((c - 'A') * modInverse(key, 26)) % 26 + 'A';
            else
                decrypted_string += ((c - 'a') * modInverse(key, 26)) % 26 + 'a';
        }
        else
        {
            decrypted_string += c;
        }
    }

    cout << "Decrypted: " << decrypted_string << endl;
}


void menu()
{
    int choice;
    do
    {
        cout << "Menu:\n";
        cout << "1. Encrypt/Decrypt using addition/subtraction based Caesar cipher\n";
        cout << "2. Encrypt/Decrypt using multiplication/division based Caesar cipher\n";
        cout << "3. Exit\n";
        cout << "Enter your choice: ";
        cin >> choice;

        switch (choice)
        {
        case 1:
            addition_cipher();
            break;
        case 2:
            multiplication_cipher();
            break;
        case 3:
            cout << "Exiting...\n";
            break;
        default:
            cout << "Invalid choice. Please try again.\n";
        }
    } while (choice != 3);
}