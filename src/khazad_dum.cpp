#include <iostream>

#include "tpm2/tpm2_hal.h"
#include "utils/macros.h"

int main() {
  Moria::TPM2_HAL* tpm2hall = new Moria::TPM2_HAL;
  auto pPrimaryObject = tpm2hall->createPrimaryObject();

  nlohmann::json object = {{"rsa_primary_object", pPrimaryObject->serialize()}};
  std::cout << object.dump(2) << std::endl;

  auto pKey = tpm2hall->createKey(std::move(pPrimaryObject));

  nlohmann::json object1 = {{"ecc_key", pKey->serialize()}};
  std::cout << object1.dump(2) << std::endl;
  // auto pKey = tpm2hall->createKey(std::move(pPrimaryObject));

  // auto data = tpm2hall->encrypt(std::move(pPrimaryObject));
  return 0;
}