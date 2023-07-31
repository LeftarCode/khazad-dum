#include <iostream>

class AESException : public std::exception {
 private:
  std::string message = "AES Exception: ";

 public:
  AESException(std::string msg) { message += msg; }
  const char* what() { return message.c_str(); }
};
