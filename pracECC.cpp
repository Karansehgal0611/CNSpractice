#include <iostream>
#include <vector>
#include <stdexcept>
#include <cmath>
#include <numeric>
#include<utility>

// Point class to represent a point on the elliptic curve
class Point {
public:
    int x, y;
    bool isInfinity; // Flag for point at infinity (identity element)

    // Constructor for regular points
    Point(int x, int y) : x(x), y(y), isInfinity(false) {}

    // Constructor for point at infinity
    Point() : x(0), y(0), isInfinity(true) {}

    // Equality operator
    bool operator==(const Point& other) const {
        if (isInfinity && other.isInfinity) return true;
        if (isInfinity || other.isInfinity) return false;
        return x == other.x && y == other.y;
    }

    // Inequality operator
    bool operator!=(const Point& other) const {
        return !(*this == other);
    }

    // Print point
    void print() const {
        if (isInfinity) {
            std::cout << "Point at Infinity" << std::endl;
        } else {
            std::cout << "(" << x << ", " << y << ")" << std::endl;
        }
    }
};

// Elliptic Curve class
class EllipticCurve {
private:
    int a, b, p; // Curve parameters: y² ≡ x³ + ax + b (mod p)

    // Helper function for modular inverse using extended Euclidean algorithm
    int modInverse(int value, int mod) const {
        value = value % mod;
        for (int x = 1; x < mod; x++) {
            if ((value * x) % mod == 1) {
                return x;
            }
        }
        throw std::runtime_error("Modular inverse does not exist");
    }

public:
    // Constructor
    EllipticCurve(int a, int b, int p) : a(a), b(b), p(p) {
        // Check that the curve is non-singular
        if ((4 * a * a * a + 27 * b * b) % p == 0) {
            throw std::invalid_argument("Curve is singular");
        }
    }

    // Check if a point is on the curve
    bool isPointOnCurve(const Point& point) const {
        if (point.isInfinity) return true;

        int lhs = (point.y * point.y) % p;
        int rhs = (point.x * point.x * point.x + a * point.x + b) % p;
        return lhs == rhs;
    }

    // Point addition
    Point add(const Point& p1, const Point& p2) const {
        // Handle identity element (point at infinity)
        if (p1.isInfinity) return p2;
        if (p2.isInfinity) return p1;

        // Check if points are on the curve
        if (!isPointOnCurve(p1) || !isPointOnCurve(p2)) {
            throw std::invalid_argument("Points not on the curve");
        }

        // Handle point doubling
        if (p1 == p2) {
            return doublePoint(p1);
        }

        // Handle vertical line (result is point at infinity)
        if (p1.x == p2.x) {
            return Point(); // point at infinity
        }

        // Calculate slope
        int numerator = (p2.y - p1.y) % p;
        int denominator = (p2.x - p1.x) % p;
        if (numerator < 0) numerator += p;
        if (denominator < 0) denominator += p;
        int slope = (numerator * modInverse(denominator, p)) % p;

        // Calculate resulting point
        int x3 = (slope * slope - p1.x - p2.x) % p;
        int y3 = (slope * (p1.x - x3) - p1.y) % p;
        if (x3 < 0) x3 += p;
        if (y3 < 0) y3 += p;

        return Point(x3, y3);
    }

    // Point doubling
    Point doublePoint(const Point& point) const {
        if (point.isInfinity) return point;
        if (point.y == 0) return Point(); // vertical tangent

        // Calculate slope
        int numerator = (3 * point.x * point.x + a) % p;
        int denominator = (2 * point.y) % p;
        if (numerator < 0) numerator += p;
        if (denominator < 0) denominator += p;
        int slope = (numerator * modInverse(denominator, p)) % p;

        // Calculate resulting point
        int x3 = (slope * slope - 2 * point.x) % p;
        int y3 = (slope * (point.x - x3) - point.y) % p;
        if (x3 < 0) x3 += p;
        if (y3 < 0) y3 += p;

        return Point(x3, y3);
    }

    // Scalar multiplication using double-and-add algorithm
    Point multiply(const Point& point, int scalar) const {
        if (scalar < 0) {
            throw std::invalid_argument("Scalar must be non-negative");
        }

        Point result; // point at infinity
        Point temp = point;

        while (scalar > 0) {
            if (scalar & 1) {
                result = add(result, temp);
            }
            temp = doublePoint(temp);
            scalar >>= 1;
        }

        return result;
    }

    pair<Point,Point> ECCencrypt(const Point& G, const Point& M, int n){
        if(!isPointOnCurve(M) || !isPointOnCurve(G)){
            throw std::invalid_argument("Invalid  points");
        }
        Point Pu = multiply(G,n);

        int k;
        cout << "Enter ephemeral key" <<endl;
        cin >> k >> endl;
        Point C1 = multiply(G,k);
        Point C2 = add(M,multiply(Pu,k));

        return {C1,C2};
    }

     Point decrypt(const pair<Point, Point>& ciphertext, int n) const {
        auto [C1, C2] = ciphertext;
        if(!isPointOnCurve(C1) || !isPointOnCurve(C2)) {
            throw std::invalid_argument("Invalid ciphertext points");
        }

        Point S = multiply(C1, n);  // Shared secret
        return add(C2, negate(S));          // Unmask the message
    }

    // Helper to negate a point
    Point negate(const Point& p) const {
        if(p.isInfinity) return p;
        return Point(p.x, (-p.y) % p);
    }

    // Get curve parameters
    void getParameters(int& a_out, int& b_out, int& p_out) const {
        a_out = a;
        b_out = b;
        p_out = p;
    }
};

int main() {
    try {
    Point G(1,5); // Example generator point
    int n = 2;        // Order of base point
    EllipticCurve curve(1, 1, 11); // y² = x³ + x + 1 mod 11

    // Key generation
    int privateKey = 2; // Normally would be randomly generated
    Point publicKey = curve.multiply(G, privateKey);

    // Encrypt a message point
    Point message(4, 6); // Must be on curve
    auto ciphertext = curve.ECCencrypt(G,message,n);

    // Decrypt
    Point decrypted = curve.decrypt(ciphertext, privateKey);

    std::cout << "Original: "; message.print();
    std::cout << "Decrypted: "; decrypted.print();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

