#include <fstream>
#include <iostream>

#include "tpm2/tpm2_hal.h"
#include "utils/macros.h"

int main(int argc, char** argv) {
  if (argc == 3) {
    std::cout << "You need to provide at least 2 arguments" << std::endl
              << "Use -h for help message" << std::endl;
    return 1;
  }

  if (strcmp(argv[1], "create_policy") == 0) {
    Moria::TPM2_HAL* tpm2hall = new Moria::TPM2_HAL;
    auto pPrimaryObject = tpm2hall->createPrimaryObject();

    nlohmann::json object = {
        {"ecc_primary_object", pPrimaryObject->serialize()}};

    std::ofstream policyOutputFile;
    policyOutputFile.open(argv[2]);
    if (policyOutputFile.is_open()) {
      policyOutputFile << object.dump(2) << std::endl;
    }
  } else if (strcmp(argv[1], "seal_secrets") == 0) {
    if (argc == 4) {
      std::cout << "You need to provide exactly 3 arguments" << std::endl
                << "Use -h for help message" << std::endl;
      return 1;
    }

    std::cout << "seal_secrets" << std::endl;
  } else {
    std::cout << "Invalid program usage" << std::endl
              << "Use -h for help message" << std::endl;
    return 1;
  }

  // TPM2B_ECC_POINT inPoint = {
  //     .size = 0,
  //     .point = {
  //         .x =
  //             {
  //                 .size = 32,
  //                 .buffer = {0x25, 0xdb, 0x1f, 0x8b, 0xbc, 0xfa, 0xbc, 0x31,
  //                            0xf8, 0x17, 0x6a, 0xcb, 0xb2, 0xf8, 0x40, 0xa3,
  //                            0xb6, 0xa5, 0xd3, 0x40, 0x65, 0x9d, 0x37, 0xee,
  //                            0xd9, 0xfd, 0x52, 0x47, 0xf5, 0x14, 0xd5, 0x98},
  //             },
  //         .y = {.size = 32,
  //               .buffer = {0xed, 0x62, 0x3e, 0x3d, 0xd2, 0x09, 0x08, 0xcf,
  //                          0x58, 0x3c, 0x81, 0x4b, 0xbf, 0x65, 0x7e, 0x08,
  //                          0xab, 0x9f, 0x40, 0xff, 0xea, 0x51, 0xda, 0x21,
  //                          0x29, 0x8c, 0xe2, 0x4d, 0xeb, 0x34, 0x4c,
  //                          0xcc}}}};
  // auto secret = tpm2hall->generateSharedKey(pPrimaryObject, inPoint);

  // std::ostringstream yStream;
  // for (auto byte : secret) {
  //   yStream << std::setw(2) << std::setfill('0') << std::hex
  //           << +static_cast<unsigned char>(byte);
  // }

  // std::cout << "AES Key: " << yStream.str() << std::endl;

  return 0;
}