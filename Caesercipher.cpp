#include <bits/stdc++.h>
#include <vector>
#include <algorithm>
using namespace std;

char shift(char character, int k)
{
    if(isupper(character))
        {
        return (character-'A'+k)%26 + 'A';
        }
    else if(islower(character))
       {
         return (character-'a'+k)%26 + 'a';
       }
    else
    {
        return character; // return the character unchanged if it's not a letter
    }
}

char shift_back(char character, int k)
{
    if(isupper(character))
        {
        return (character-'A'-k)%26 + 'A';
        }
    else if(islower(character))
       {
         return (character-'a'-k)%26 + 'a';
       }
}

string encrypt(string text, int k)
{
    string cipher="";
    for(int i =0;i<text.length();i++)
    {
        if(text[i]==' ')
        {
            cipher += ' ';
            continue;
        }
        else if(isalpha(text[i]))
        {
            char j = shift(text[i],k);
            cipher += j;
        }
        else
        {
            return "Enter plain text";
        }
    }
    return cipher;
}

string decrypt(string cipher,int k)
{
    string text="";
    for(int i =0;i<cipher.length();i++)
    {
        if(cipher[i]==' ')
        {
            text += ' ';
            continue;
        }
        else if(isalpha(cipher[i]))
        {
            char j = shift_back(cipher[i],k);
            text += j;
        }
        else
        {
            return "Plain text";
        }
    }
    return text;
}


int main()
{
    string s = "";
    cout<<"Enter a string to be encrypted: ";
    getline(cin,s);

    cout<<"Enter the key value";
    int key;
    cin>> key;

    string encrypted_string = encrypt(s,key);
    string decrypted_string = "";
    if(encrypted_string!="Enter plain text")
    {
        decrypted_string = decrypt(encrypted_string,key);
    }
    cout<<"Encrypted: "<<encrypted_string<<endl;
    cout<<"Decrypted: "<<decrypted_string<<endl;

    return 0;
}