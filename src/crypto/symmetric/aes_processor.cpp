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

EncryptedSecret AESProcessor::encryptSecret(const Secret& secret) {
  std::array<std::byte, 12> iv = generateInitialVector();
  std::array<std::byte, 16> tag;
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
                         (const unsigned char*)secret.value.data(),
                         secret.value.size())) {
    throw new AESException("Could not encrypt provided data");
  }
  ciphertextLen = len;

  if (!EVP_EncryptFinal_ex(ctx, (unsigned char*)std::begin(ciphertext) + len,
                           &len)) {
    throw new AESException(
        "Could not finalize AES256_GCM encryption operation");
  }
  ciphertextLen += len;

  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                           (unsigned char*)std::begin(tag))) {
    throw new AESException("Could not retrieve tag value");
  }

  EncryptedSecret encryptedSecret;
  encryptedSecret.name = secret.name;
  encryptedSecret.iv = iv;
  encryptedSecret.tag = tag;
  encryptedSecret.value = std::vector<std::byte>(
      std::begin(ciphertext), std::begin(ciphertext) + ciphertextLen);

  std::ostringstream tagStringStream;
  for (int i = 0; i < 16; i++) {
    tagStringStream << std::setw(2) << std::setfill('0') << std::hex
                    << +static_cast<unsigned char>(tag[i]);
  }

  std::ostringstream outputStringStream;
  for (int i = 0; i < ciphertextLen; i++) {
    outputStringStream << std::setw(2) << std::setfill('0') << std::hex
                       << +static_cast<unsigned char>(ciphertext[i]);
  }

  return encryptedSecret;
}

Secret AESProcessor::decryptSecret(const EncryptedSecret& encryptedSecret) {
  unsigned char tag[16] = {0};
  std::array<std::byte, 1024> cleartext;
  std::size_t cleartextLen = 0;
  int len = 0;

  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
    throw new AESException(
        "Could not initialize AES256_GCM encryption operation");
  }

  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, (unsigned char*)std::begin(key),
                          (unsigned char*)std::begin(encryptedSecret.iv))) {
    throw new AESException("Could not initialize key and IV");
  }

  if (!EVP_DecryptUpdate(ctx, (unsigned char*)std::begin(cleartext), &len,
                         (const unsigned char*)encryptedSecret.value.data(),
                         encryptedSecret.value.size())) {
    throw new AESException("Could not decrypt provided data");
  }
  cleartextLen = len;

  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                           (unsigned char*)std::begin(encryptedSecret.tag))) {
    throw new AESException("Could not decrypt provided data");
  }

  if (!EVP_DecryptFinal_ex(ctx, (unsigned char*)std::begin(cleartext), &len)) {
    std::cout << "ERROR4" << std::endl;
    throw new AESException(
        "Could not finalize AES256_GCM encryption operation");
  }
  cleartextLen += len;

  std::ostringstream cleartextStringStream;
  for (int i = 0; i < cleartextLen; i++) {
    cleartextStringStream << (unsigned char)(cleartext[i]);
  }

  Secret secret;
  secret.name = encryptedSecret.name;
  secret.value = cleartextStringStream.str();

  return secret;
}
AESProcessor::~AESProcessor() { EVP_CIPHER_CTX_free(ctx); }
}  // namespace Moria