#include <fstream>
#include <iostream>

#include "khazad_dum.h"

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cout << "You need to provide at least 2 arguments" << std::endl
              << "Use -h for help message" << std::endl;
    return 1;
  }

  Moria::TPM2_HAL* tpm2hal = new Moria::TPM2_HAL;
  Moria::KhazadDum* khazadDum = new Moria::KhazadDum;

  // auto decryptedSecrets = khazadDum->decryptSecrets("mithril.json");
  // auto sealedSecrets = khazadDum->sealSecrets(decryptedSecrets);
  // auto secretValue = khazadDum->unsealSecret(sealedSecrets, "DB_PASSWORD");
  // secretValue = khazadDum->unsealSecret(sealedSecrets, "DB_USERNAME");

  if (strcmp(argv[1], "create_policy") == 0) {
    khazadDum->createPolicy(argv[2]);
  } else if (strcmp(argv[1], "encrypt_secrets") == 0) {
    if (argc != 5) {
      std::cout << "You need to provide exactly 4 arguments" << std::endl
                << "Use -h for help message" << std::endl;
      return 1;
    }

    khazadDum->encryptSecrets(argv[2], argv[3], argv[4]);
  } else {
    std::cout << "Invalid program usage" << std::endl
              << "Use -h for help message" << std::endl;
    return 1;
  }

  return 0;
}