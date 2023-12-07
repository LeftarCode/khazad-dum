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

  // Moria::ECKeyConverter ecKeyConverter;
  // Moria::ECPublicKeyPoint remotePublicKeyPoint =
  //     ecKeyConverter.convertPEMToPoint(privateKey);
  // /* START TEST */
  // /* TEST TPM2 CALC */
  // TPM2B_ECC_POINT inPoint = {.size = 0,
  //                            .point = {.x =
  //                                          {
  //                                              .size = 32,
  //                                          },
  //                                      .y = {.size = 32}}};

  // memcpy(inPoint.point.x.buffer, std::begin(remotePublicKeyPoint.first), 32);
  // memcpy(inPoint.point.y.buffer, std::begin(remotePublicKeyPoint.second),
  // 32);

  // auto pPrimaryObject = tpm2hal->createPrimaryObject();
  // auto secretTPM = tpm2hal->generateSharedKey(pPrimaryObject, inPoint);
  // /* TEST OPENSSL CALC */
  // // Zmienic na punkt z JSONa
  // Moria::ECPublicKeyPoint tpmPublicKeyPoint =
  //     ecKeyConverter.converHexStringToPoint(x, y);
  // auto secretOSSL =
  //     ecKeyConverter.generateSharedKey(privateKey, tpmPublicKeyPoint);
  // /* END TEST */

  // std::ostringstream secretTPMSTR;
  // std::ostringstream secretOSSLSTR;
  // for (auto byte : secretTPM) {
  //   secretTPMSTR << std::setw(2) << std::setfill('0') << std::hex
  //                << +static_cast<unsigned char>(byte);
  // }
  // for (auto byte : secretOSSL) {
  //   secretOSSLSTR << std::setw(2) << std::setfill('0') << std::hex
  //                 << +static_cast<unsigned char>(byte);
  // }
  // std::cout << "TPM2: " << secretTPMSTR.str() << std::endl;
  // std::cout << "OSSL: " << secretOSSLSTR.str() << std::endl;

  return 0;
}