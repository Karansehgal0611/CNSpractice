#include <iostream>
#include <vector>
#include <cstdint>
#include <random>
#include <stdexcept>
#include <cassert>

class EllipticCurve {
private:
    uint64_t a, b, p, n;

public:
    struct Point {
        uint64_t x;
        uint64_t y;
        bool infinity;

        Point() : x(0), y(0), infinity(true) {}
        Point(uint64_t x_coord, uint64_t y_coord) : x(x_coord), y(y_coord), infinity(false) {}

        bool operator==(const Point& other) const {
            if (infinity && other.infinity) return true;
            if (infinity || other.infinity) return false;
            return x == other.x && y == other.y;
        }

        Point operator-() const {
            if (infinity) return Point();
            return Point(x, -(p.y));  // p is captured from the outer scope
        }
    };

    Point G;

    EllipticCurve(uint64_t a_param, uint64_t b_param, uint64_t p_param, uint64_t n_param,
                  uint64_t gx, uint64_t gy)
        : a(a_param), b(b_param), p(p_param), n(n_param), G(gx, gy) {
        ::p = p_param;  // To allow mod operations in static context like operator-
        assert(isOnCurve(G));
        assert(scalarMultiply(n, G).infinity);
    }

    bool isOnCurve(const Point& point) const {
        if (point.infinity) return true;
        uint64_t left = modMul(point.y, point.y);
        uint64_t right = modAdd(modAdd(modPow(point.x, 3), modMul(a, point.x)), b);
        return left == (right % p);
    }

    Point addPoints(const Point& P, const Point& Q) const {
        if (P.infinity) return Q;
        if (Q.infinity) return P;

        if (P.x == Q.x && (P.y != Q.y || P.y == 0)) return Point();

        uint64_t m;
        if (P == Q) {
            uint64_t numerator = modAdd(modMul(3, modPow(P.x, 2)), a);
            uint64_t denominator = modMul(2, P.y);
            if (denominator == 0) return Point();
            m = modMul(numerator, modInverse(denominator, p));
        } else {
            uint64_t dx = modSub(Q.x, P.x);
            if (dx == 0) return Point();
            uint64_t dy = modSub(Q.y, P.y);
            m = modMul(dy, modInverse(dx, p));
        }

        uint64_t x3 = modSub(modSub(modPow(m, 2), P.x), Q.x);
        uint64_t y3 = modSub(modMul(m, modSub(P.x, x3)), P.y);
        return Point(x3, y3);
    }

    Point scalarMultiply(uint64_t k, const Point& P) const {
        Point result;
        Point addend = P;

        while (k > 0) {
            if (k & 1)
                result = addPoints(result, addend);
            addend = addPoints(addend, addend);
            k >>= 1;
        }

        return result;
    }

    uint64_t generatePrivateKey() const {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dis(1, n - 1);
        return dis(gen);
    }

    Point generatePublicKey(uint64_t privateKey) const {
        return scalarMultiply(privateKey, G);
    }

    Point computeSharedSecret(uint64_t privateKey, const Point& otherPublicKey) const {
        return scalarMultiply(privateKey, otherPublicKey);
    }

private:
    uint64_t modAdd(uint64_t a, uint64_t b) const {
        return (a + b) % p;
    }

    uint64_t modSub(uint64_t a, uint64_t b) const {
        return (a + p - (b % p)) % p;
    }

    uint64_t modMul(uint64_t a, uint64_t b) const {
        return (a % p * b % p) % p;
    }

    uint64_t modPow(uint64_t base, uint64_t exponent) const {
        uint64_t result = 1;
        base %= p;
        while (exponent > 0) {
            if (exponent & 1)
                result = modMul(result, base);
            exponent >>= 1;
            base = modMul(base, base);
        }
        return result;
    }

    uint64_t modInverse(uint64_t a, uint64_t m) const {
        int64_t m0 = m, x = 1, y = 0;
        if (m == 1) return 0;
        while (a > 1) {
            int64_t q = a / m;
            int64_t t = m;
            m = a % m;
            a = t;
            t = y;
            y = x - q * y;
            x = t;
        }
        if (x < 0) x += m0;
        return x;
    }
};

// Static global needed for Point operator- (so p can be captured safely)
static uint64_t p = 0;

int main() {
    uint64_t a = 0, b = 7, p_ = 17, n = 18;
    uint64_t gx = 5, gy = 1;

    try {
        EllipticCurve curve(a, b, p_, n, gx, gy);

        uint64_t alicePrivate = 3;
        auto alicePublic = curve.generatePublicKey(alicePrivate);

        uint64_t bobPrivate = 7;
        auto bobPublic = curve.generatePublicKey(bobPrivate);

        auto aliceShared = curve.computeSharedSecret(alicePrivate, bobPublic);
        auto bobShared = curve.computeSharedSecret(bobPrivate, alicePublic);

        std::cout << "Alice's private key: " << alicePrivate << "\n";
        std::cout << "Alice's public key: (" << alicePublic.x << ", " << alicePublic.y << ")\n";

        std::cout << "Bob's private key: " << bobPrivate << "\n";
        std::cout << "Bob's public key: (" << bobPublic.x << ", " << bobPublic.y << ")\n";

        std::cout << "Alice's shared secret: (" << aliceShared.x << ", " << aliceShared.y << ")\n";
        std::cout << "Bob's shared secret: (" << bobShared.x << ", " << bobShared.y << ")\n";

        if (aliceShared == bobShared)
            std::cout << "ECDH key exchange successful!\n";
        else
            std::cout << "ECDH key exchange failed!\n";

        auto P = EllipticCurve::Point(5, 1);
        auto Q = curve.scalarMultiply(2, P);
        auto R = curve.addPoints(P, Q);

        std::cout << "\nPoint operations:\n";
        std::cout << "P = (" << P.x << ", " << P.y << ")\n";
        std::cout << "2P = (" << Q.x << ", " << Q.y << ")\n";
        std::cout << "P + 2P = (" << R.x << ", " << R.y << ")\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
