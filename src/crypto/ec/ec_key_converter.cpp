#include "crypto/ec/ec_key_converter.h"

#include <openssl/bio.h>
#include <openssl/pem.h>

#include <iostream>

namespace Moria {
ECPublicKeyPoint ECKeyConverter::convertPEMToPoint(const std::string& pem) {
  std::array<std::byte, 32> x;
  std::array<std::byte, 32> y;

  BIO* bio = BIO_new_mem_buf(pem.c_str(), pem.size());

  EVP_PKEY* privateKey = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
  if (privateKey == NULL) {
    std::cout << "Reading PEM private key failed" << std::endl;
    exit(1);
  }

  EC_KEY* ecPrivateKey = EVP_PKEY_get1_EC_KEY(privateKey);
  EC_GROUP* ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

  const EC_POINT* ecPoint = EC_KEY_get0_public_key(ecPrivateKey);

  BIGNUM* bnX = BN_new();
  BIGNUM* bnY = BN_new();

  if (!EC_POINT_get_affine_coordinates_GFp(ec_group, ecPoint, bnX, bnY, NULL)) {
    std::cout << "Reading EC public key failed" << std::endl;
    exit(1);
  }

  BN_bn2bin(bnX, (unsigned char*)std::begin(x));
  BN_bn2bin(bnY, (unsigned char*)std::begin(y));

  BN_free(bnX);
  BN_free(bnY);
  BIO_free(bio);

  return std::make_pair(x, y);
}

std::array<std::byte, 32> ECKeyConverter::generateSharedKey(
    const std::string& pem, ECPublicKeyPoint inPoint) {
  std::array<std::byte, 32> x;
  std::array<std::byte, 32> y;

  BIO* bio = BIO_new_mem_buf(pem.c_str(), pem.size());

  EVP_PKEY* privateKey = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
  if (privateKey == NULL) {
    std::cout << "Reading PEM private key failed" << std::endl;
    exit(1);
  }

  EC_KEY* ecPrivateKey = EVP_PKEY_get1_EC_KEY(privateKey);
  EC_GROUP* ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

  EC_POINT* ecPoint = EC_POINT_new(ec_group);

  BIGNUM* bnX = BN_new();
  BIGNUM* bnY = BN_new();

  BN_bin2bn((unsigned char*)std::begin(inPoint.first), 32, bnX);
  BN_bin2bn((unsigned char*)std::begin(inPoint.second), 32, bnY);

  if (!EC_POINT_set_affine_coordinates_GFp(ec_group, ecPoint, bnX, bnY, NULL)) {
    std::cout << "Reading EC public key failed" << std::endl;
    exit(1);
  }

  std::array<std::byte, 32> secret;
  int sharedLen = ECDH_compute_key((unsigned char*)std::begin(secret), 32,
                                   ecPoint, ecPrivateKey, NULL);

  BN_free(bnX);
  BN_free(bnY);
  EC_POINT_free(ecPoint);
  BIO_free(bio);

  return secret;
}

ECPublicKeyPoint ECKeyConverter::converHexStringToPoint(
    const std::string& xHex, const std::string& yHex) {
  std::array<std::byte, 32> x;
  std::array<std::byte, 32> y;
  BIGNUM* input = BN_new();

  int input_length = (BN_hex2bn(&input, xHex.c_str()) + 1) / 2;
  BN_bn2bin(input, (unsigned char*)std::begin(x));

  input_length = (BN_hex2bn(&input, yHex.c_str()) + 1) / 2;
  BN_bn2bin(input, (unsigned char*)std::begin(y));

  BN_free(input);

  return std::make_pair(x, y);
}
}  // namespace Moria