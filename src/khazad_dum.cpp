#include <iostream>

#include "tpm2/tpm2_hal.h"
#include "utils/macros.h"

int main() {
  Moria::TPM2_HAL* tpm2hall = new Moria::TPM2_HAL;
  auto pKey = tpm2hall->createPrimaryKey();

  nlohmann::json object = {{"ecc_public_key", pKey->serialize()}};
  std::cout << object.dump(2) << std::endl;

  return 0;
}