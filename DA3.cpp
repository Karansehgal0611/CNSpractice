#include <iostream>
#include <cmath>
#include <vector>
#include <random>
#include <ctime>
#include <limits>

using namespace std;
// Utility functions
long long mod_pow(long long base, long long exponent, long long modulus) {
    long long result = 1;
    while (exponent > 0) {
        if (exponent & 1)
            result = (result * base) % modulus;
        base = (base * base) % modulus;
        exponent >>= 1;
    }
    return result;
}

long long mod_inverse(long long a, long long m) {
    long long m0 = m, t, q;
    long long x0 = 0, x1 = 1;
    if (m == 1)
        return 0;
    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0)
        x1 += m0;
    return x1;
}

bool is_prime(long long n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (long long i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0)
            return false;
    }
    return true;
}

long long generate_prime(long long min, long long max) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<long long> dis(min, max);
    long long prime;
    do {
        prime = dis(gen);
    } while (!is_prime(prime));
    return prime;
}

// Point structure for ECC
struct Point {
    long long x, y;
    Point(long long x = 0, long long y = 0) : x(x), y(y) {}
};

// Function to get a valid long long input from the user
long long get_long_long_input(const string& prompt) {
    long long value;
    while (true) {
        cout << prompt;
        if (cin >> value) {
            return value;
        } else {
            cout << "Invalid input. Please enter a valid number.\n";
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
    }
}

// RSA implementation
void rsa() {
    cout << "\n--- RSA Algorithm ---\n";
    
    long long p = generate_prime(100, 1000);
    long long q = generate_prime(100, 1000);
    long long n = p * q;
    long long phi = (p - 1) * (q - 1);
    
    cout << "Generated primes p = " << p << ", q = " << q << endl;
    cout << "n = p * q = " << n << endl;
    cout << "φ(n) = " << phi << endl;
    
    long long e = 65537; // Commonly used public exponent
    long long d = mod_inverse(e, phi);
    
    cout << "Public key (e, n): (" << e << ", " << n << ")" << endl;
    cout << "Private key (d, n): (" << d << ", " << n << ")" << endl;
    
    long long message = get_long_long_input("Enter a message to encrypt (a number smaller than " + to_string(n) + "): ");
    
    long long encrypted = mod_pow(message, e, n);
    cout << "Encrypted message: " << encrypted << endl;
    
    long long decrypted = mod_pow(encrypted, d, n);
    cout << "Decrypted message: " << decrypted << endl;
}

// ElGamal implementation
void elgamal() {
    cout << "\n--- ElGamal Algorithm ---\n";
    
    long long p = generate_prime(100, 1000);
    long long g = 2; // Generator
    
    cout << "Generated prime p = " << p << endl;
    cout << "Generator g = " << g << endl;
    
    long long x = rand() % (p - 2) + 1; // Private key
    long long y = mod_pow(g, x, p); // Public key
    
    cout << "Private key x = " << x << endl;
    cout << "Public key y = " << y << endl;     
    
    long long message = get_long_long_input("Enter a message to encrypt (a number smaller than " + to_string(p) + "): ");
    
    long long k = rand() % (p - 2) + 1; // Ephemeral key
    long long a = mod_pow(g, k, p);
    long long b = (message * mod_pow(y, k, p)) % p;
    
    cout << "Encrypted message (a, b): (" << a << ", " << b << ")" << endl;
    
    long long decrypted = (b * mod_inverse(mod_pow(a, x, p), p)) % p;
    cout << "Decrypted message: " << decrypted << endl;
}

// Diffie-Hellman key exchange implementation
void diffie_hellman() {
    cout << "\n--- Diffie-Hellman Key Exchange ---\n";
    
    long long p = generate_prime(100, 1000);
    long long g = 2; // Generator
    
    cout << "Shared prime p = " << p << endl;
    cout << "Shared base g = " << g << endl;
    
    long long a = get_long_long_input("Enter Alice's private key (1 < a < " + to_string(p-1) + "): ");
    long long b = get_long_long_input("Enter Bob's private key (1 < b < " + to_string(p-1) + "): ");
    
    long long A = mod_pow(g, a, p); // Alice's public key
    long long B = mod_pow(g, b, p); // Bob's public key
    
    cout << "Alice's public key: " << A << endl;
    cout << "Bob's public key: " << B << endl;
    
    long long s_alice = mod_pow(B, a, p); // Alice's shared secret
    long long s_bob = mod_pow(A, b, p); // Bob's shared secret
    
    cout << "Alice's computed shared secret: " << s_alice << endl;
    cout << "Bob's computed shared secret: " << s_bob << endl;
}

// ECC Point operations
Point point_addition(Point P, Point Q, long long a, long long p) {
    if (P.x == 0 && P.y == 0) return Q;
    if (Q.x == 0 && Q.y == 0) return P;
    
    long long m;
    if (P.x == Q.x && P.y == Q.y) {
        m = (3 * P.x * P.x + a) * mod_inverse(2 * P.y, p) % p;
    } else {
        m = (Q.y - P.y) * mod_inverse(Q.x - P.x + p, p) % p;
    }
    
    long long x = (m * m - P.x - Q.x + p) % p;
    long long y = (m * (P.x - x) - P.y + p) % p;
    
    return Point(x, y);
}


Point point_doubling(Point P, long long a, long long p) {
    return point_addition(P, P, a, p);
}

void ecc_operations() {
    cout << "\n--- ECC Point Operations ---\n";
    
    long long a = get_long_long_input("Enter parameter a: ");
    long long b = get_long_long_input("Enter parameter b: ");
    long long p = get_long_long_input("Enter prime p: ");
    
    long long x = get_long_long_input("Enter x-coordinate of point P: ");
    long long y = get_long_long_input("Enter y-coordinate of point P: ");
    Point P(x, y);
    
    cout << "Curve parameters: y^2 = x^3 + " << a << "x + " << b << " (mod " << p << ")" << endl;
    cout << "Point P: (" << P.x << ", " << P.y << ")" << endl;
    
    Point Q = point_doubling(P, a, p);
    cout << "2P: (" << Q.x << ", " << Q.y << ")" << endl;
    
    Point R = point_addition(P, Q, a, p);
    cout << "P + 2P: (" << R.x << ", " << R.y << ")" << endl;
}

// Key generation for ECC
void ecc_key_generation() {
    cout << "\n--- ECC Key Generation ---\n";
    
    long long a = get_long_long_input("Enter parameter a: ");
    long long b = get_long_long_input("Enter parameter b: ");
    long long p = get_long_long_input("Enter prime p: ");
    
    long long gx = get_long_long_input("Enter x-coordinate of generator point G: ");
    long long gy = get_long_long_input("Enter y-coordinate of generator point G: ");
    Point G(gx, gy);
    
    cout << "Curve parameters: y^2 = x^3 + " << a << "x + " << b << " (mod " << p << ")" << endl;
    cout << "Generator point G: (" << G.x << ", " << G.y << ")" << endl;
    
    long long private_key = get_long_long_input("Enter private key (1 < key < " + to_string(p-1) + "): ");
    Point public_key = G;
    for (int i = 0; i < private_key; i++) {
        public_key = point_addition(public_key, G, a, p);
    }
    
    cout << "Private key: " << private_key << endl;
    cout << "Public key: (" << public_key.x << ", " << public_key.y << ")" << endl;
}

int main() {
    srand(time(0));
    int choice;
    
    do {
        cout << "\nAsymmetric Algorithms Simulation\n";
        cout << "1. RSA\n";
        cout << "2. ElGamal\n";
        cout << "3. Diffie-Hellman Key Exchange\n";
        cout << "4. ECC - Point Doubling and Addition\n";
        cout << "5. ECC - Key Generation\n";
        cout << "6. Exit\n";
        cout << "Enter your choice: ";
        cin >> choice;
        
        switch (choice) {
            case 1: rsa(); break;
            case 2: elgamal(); break;
            case 3: diffie_hellman(); break;
            case 4: ecc_operations(); break;
            case 5: ecc_key_generation(); break;
            case 0: cout << "Exiting program.\n"; break;
            default: cout << "Invalid choice. Please try again.\n";
        }
    } while (choice != 6);
    
    return 0;
}
