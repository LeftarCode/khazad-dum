#include <iostream>

class TPM2Exception : public std::exception {
 private:
  std::string message = "TPM2 Exception: ";

 public:
  TPM2Exception(std::string msg) { message += msg; }
  const char* what() { return message.c_str(); }
};
