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

    // Destructor that closes the file if it's open
    ~FileWrapper()
    {
        if (file != nullptr)
        {
            fclose(file);
        }
    }

    // Accessor for the raw FILE* pointer
    FILE *get() const { return file; }

private:
    FILE *file; // Raw FILE* pointer
};
