#include "crypto/symmetric/aes_processor.h"

#include <openssl/rand.h>

#include <iomanip>
#include <iostream>
#include <sstream>

#include "utils/aes_exception.h"

namespace Moria {
AESProcessor::AESProcessor(SymmetricEncryptionType type, ECPointCoord key)
    : type(type), key(key) {
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    throw new AESException("Could not initialize OpenSSL context");
  }
}

std::array<std::byte, 12> AESProcessor::generateInitialVector() {
  std::array<std::byte, 12> iv;
  RAND_bytes((unsigned char*)std::begin(iv), 12);
  return iv;
}

std::string AESProcessor::encrypt(std::string cleartext,
                                  std::array<std::byte, 12> iv) {
  std::array<std::byte, 1024> ciphertext;
  std::size_t ciphertextLen = 0;
  int len = 0;

  if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
    throw new AESException(
        "Could not initialize AES256_GCM encryption operation");
  }

  if (!EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char*)std::begin(key),
                          (unsigned char*)std::begin(iv))) {
    throw new AESException("Could not initialize key and IV ");
  }

  if (!EVP_EncryptUpdate(ctx, (unsigned char*)std::begin(ciphertext), &len,
                         (const unsigned char*)cleartext.c_str(),
                         cleartext.size())) {
    throw new AESException("Could not encrypt provided data");
  }
  ciphertextLen = len;

  if (!EVP_EncryptFinal_ex(ctx, (unsigned char*)std::begin(ciphertext), &len)) {
    throw new AESException(
        "Could not finalize AES256_GCM encryption operation");
  }
  ciphertextLen += len;

  std::ostringstream outputStringStream;
  for (int i = 0; i < ciphertextLen; i++) {
    outputStringStream << std::setw(2) << std::setfill('0') << std::hex
                       << +static_cast<unsigned char>(ciphertext[i]);
  }

  return outputStringStream.str();
}
AESProcessor::~AESProcessor() { EVP_CIPHER_CTX_free(ctx); }
}  // namespace Moria