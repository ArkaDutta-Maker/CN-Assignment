#pragma once
#include <bits/stdc++.h>
using namespace std;

enum class ErrorType
{
    SINGLE_BIT = 0,
    TWO_ISOLATED = 1,
    ODD_ERRORS = 2,
    BURST = 3
};

inline const char *errorTypeName(ErrorType t)
{
    switch (t)
    {
    case ErrorType::SINGLE_BIT:
        return "single_bit";
    case ErrorType::TWO_ISOLATED:
        return "two_isolated_single_bits";
    case ErrorType::ODD_ERRORS:
        return "odd_number_of_errors";
    case ErrorType::BURST:
        return "burst";
    }
    return "unknown";
}

class ErrorInjector
{
    int lenf;

public:
    ErrorInjector(int len = -1) : lenf(len)
    {
        srand((unsigned)time(nullptr));
    }

    string inject(const string &in, ErrorType type)
    {
        if (in.empty())
            return in;
        string s = in;
        int n = (int)s.size();

        auto flip = [&](int pos)
        {
            s[pos] = (s[pos] == '0') ? '1' : '0';
        };

        switch (type)
        {
        case ErrorType::SINGLE_BIT:
        {
            int p = rand() % n;
            flip(p);
            cerr << "[Injector] SINGLE_BIT at " << p << "\n";
            break;
        }
        case ErrorType::TWO_ISOLATED:
        {
            if (n < 2)
            {
                flip(0);
                break;
            }
            int p1 = rand() % n;
            int p2 = rand() % n;
            while (p2 == p1 || abs(p2 - p1) < 2)
                p2 = rand() % n;
            flip(p1);
            flip(p2);
            cerr << "[Injector] TWO_ISOLATED at " << p1 << "," << p2 << "\n";
            break;
        }
        case ErrorType::ODD_ERRORS:
        {
            int candidates[3] = {1, 3, 5};
            int flips = candidates[rand() % 3];
            cerr << "[Injector] ODD_ERRORS flips=" << flips << "\n";
            for (int i = 0; i < flips; ++i)
                flip(rand() % n);
            break;
        }
        case ErrorType::BURST:
        {
            if (n <= 3)
            {
                for (int i = 0; i < n; ++i)
                    flip(i);
                break;
            }

            int start = rand() % (n - 3);
            int len = -1;
            if (this->lenf == -1)
                len = 3 + rand() % 32;
            else
                len = this->lenf;

            int end = min(start + len, n);

            cerr << "[Injector] BURST window start=" << start
                 << " len=" << (end - start) << "\n";

            int flips = 3 + rand() % (end - start);
            cerr << "[Injector] No of flips: " << flips;
            cerr << "[Injector] Flips Pos:- ";

            for (int i = 0; i < flips; ++i)
            {
                int pos = start + rand() % (end - start);
                flip(pos);
                cerr << pos << " ";
            }
            break;
        }
        }
        return s;
    }

    ErrorType randomType() const
    {
        int v = rand() % 4;
        return static_cast<ErrorType>(v);
    }

    ErrorType chooseType(int a) const
    {
        return static_cast<ErrorType>(a);
    }
};
