#pragma once

#include <cstdio>
#include <stdexcept>
#include <string>

// RAII wrapper for FILE*
class FileWrapper
{
public:
    // Constructor that opens the file
    FileWrapper(const std::string &filename, const char *mode = "wb")
    {
        file = fopen(filename.c_str(), mode);
        if (file == nullptr)
        {
            throw std::runtime_error(std::string("Failed to open file: ") + filename);
        }
    }

    // Move constructor
    FileWrapper(FileWrapper &&other) noexcept : file(other.file)
    {
        other.file = nullptr;
    }

    // Move assignment operator
    FileWrapper &operator=(FileWrapper &&other) noexcept
    {
        if (this != &other)
        {
            if (file != nullptr)
            {
                fclose(file);
            }
            file = other.file;
            other.file = nullptr;
        }
        return *this;
    }

    // Destructor that closes the file if it's open
    ~FileWrapper()
    {
        if (file != nullptr)
        {
            fclose(file);
        }
    }

    // Delete copy constructor and copy assignment operator
    FileWrapper(const FileWrapper &) = delete;
    FileWrapper &operator=(const FileWrapper &) = delete;

    // Accessor for the raw FILE* pointer
    FILE *get() const { return file; }

    // Check if file is open
    bool is_open() const { return file != nullptr; }

private:
    FILE *file; // Raw FILE* pointer
};
