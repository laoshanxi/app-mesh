// src/common/Password.cpp
#include <stdexcept>
#include <string>
#include <time.h>
#include <vector>

#define TYPE_LOWERLETTERS 0
#define TYPE_UPPERLETTERS 3
#define TYPE_NUMBERS 1
#define TYPE_SPECIAL_CHARS 2

std::string generatePassword(int length, bool lowerLettersEnabled, bool upperLettersEnabled, bool numbersEnabled, bool specialsEnabled)
{

    if (length == 0)
    {
        throw std::invalid_argument("password length should not be zero");
    }

    std::srand((unsigned int)time(NULL));

    std::vector<char> symbols{};

    if (lowerLettersEnabled)
    {
        char lowerLetters[26] = {'a', 'z', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', 'q', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'w', 'x', 'c', 'v', 'b', 'n'};
        symbols.insert(symbols.end(), std::begin(lowerLetters), std::end(lowerLetters));
    }

    if (upperLettersEnabled)
    {
        char upperLetters[26] = {'A', 'Z', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', 'Q', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'W', 'X', 'C', 'V', 'B', 'N'};
        symbols.insert(symbols.end(), std::begin(upperLetters), std::end(upperLetters));
    }

    if (numbersEnabled)
    {
        char numbers[10] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};
        symbols.insert(symbols.end(), std::begin(numbers), std::end(numbers));
    }

    if (specialsEnabled)
    {
        char specials[24] = {'[', ']', '(', ')', '{', '}', '.', '?', '!', ',', ':', ';', '/', '\\', '|', '-', '~', '#', '&', '=', '^', '$', '%', '*'};
        symbols.insert(symbols.end(), std::begin(specials), std::end(specials));
    }

    if (symbols.size() == 0)
    {
        throw std::invalid_argument("no charactor type selected");
    }

    std::string result = "";
    for (int i = 0; i < length; i++)
    {
        result.push_back(symbols[std::rand() % symbols.size()]);
    }
    return result;
}