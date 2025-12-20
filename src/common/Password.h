// src/common/Password.h
#include <string>

//////////////////////////////////////////////////////////////////////////
// Generate random password with different options
//////////////////////////////////////////////////////////////////////////
std::string generatePassword(int length, bool lowerLettersEnabled, bool upperLettersEnabled, bool numbersEnabled, bool specialsEnabled);
