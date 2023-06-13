#include <iostream>

#include "tpm2/tpm2_hal.h"

#define UNUSED(x) (void)(x)

int main() {
  Moria::TPM2_HAL* tpm2hall = new Moria::TPM2_HAL;
  auto pKey = tpm2hall->createPrimaryKey();

  UNUSED(pKey);
  return 0;
}