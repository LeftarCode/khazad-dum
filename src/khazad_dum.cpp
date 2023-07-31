#include <fstream>
#include <iostream>

#include "crypto/ec/ec_key_converter.h"
#include "crypto/symmetric/aes_processor.h"
#include "tpm2/tpm2_hal.h"
#include "utils/macros.h"

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cout << "You need to provide at least 2 arguments" << std::endl
              << "Use -h for help message" << std::endl;
    return 1;
  }

  Moria::TPM2_HAL* tpm2hal = new Moria::TPM2_HAL;

  if (strcmp(argv[1], "create_policy") == 0) {
    auto pPrimaryObject = tpm2hal->createPrimaryObject();
    std::ofstream policyOutputFile;

    nlohmann::json object = {
        {"tpm_ecc_public_key", pPrimaryObject->serialize()}};

    policyOutputFile.open(argv[2]);
    if (!policyOutputFile.is_open()) {
      std::cout << "Could not open specified file" << std::endl;
      return 1;
    }
    policyOutputFile << object.dump(2) << std::endl;
  } else if (strcmp(argv[1], "seal_secrets") == 0) {
    if (argc != 5) {
      std::cout << "You need to provide exactly 4 arguments" << std::endl
                << "Use -h for help message" << std::endl;
      return 1;
    }

    std::ifstream policyInputFile(argv[2]);
    if (!policyInputFile.is_open()) {
      std::cout << "Could not open specified policy file" << std::endl;
      return 1;
    }
    nlohmann::json policyJson = nlohmann::json::parse(policyInputFile);
    std::string x = policyJson["tpm_ecc_public_key"]["pub_key"]["x"];
    std::string y = policyJson["tpm_ecc_public_key"]["pub_key"]["y"];

    std::ifstream secretsInputFile(argv[3]);
    if (!secretsInputFile.is_open()) {
      std::cout << "Could not open specified secrets file" << std::endl;
      return 1;
    }
    nlohmann::json secretsJson = nlohmann::json::parse(secretsInputFile);

    std::ifstream privateKeyInputFile(argv[4]);
    if (!privateKeyInputFile.is_open()) {
      std::cout << "Could not open specified private key file" << std::endl;
      return 1;
    }

    std::string privateKey(
        (std::istreambuf_iterator<char>(privateKeyInputFile)),
        std::istreambuf_iterator<char>());

    Moria::ECKeyConverter ecKeyConverter;
    Moria::ECPublicKeyPoint tpmPublicKeyPoint =
        ecKeyConverter.converHexStringToPoint(x, y);
    auto ecdhSecret =
        ecKeyConverter.generateSharedKey(privateKey, tpmPublicKeyPoint);

    Moria::AESProcessor aesProcessor(Moria::kAES256GCM, ecdhSecret);
    auto iv = aesProcessor.generateInitialVector();

    auto secretsElement = secretsJson["secrets"];
    for (auto& secret : secretsElement.items()) {
      secretsElement[secret.key()] = aesProcessor.encrypt(secret.value(), iv);
    }

    std::ostringstream ivStringStream;
    for (auto byte : iv) {
      ivStringStream << std::setw(2) << std::setfill('0') << std::hex
                     << +static_cast<unsigned char>(byte);
    }
    std::ostringstream xStringStream;
    for (auto byte : iv) {
      xStringStream << std::setw(2) << std::setfill('0') << std::hex
                    << +static_cast<unsigned char>(byte);
    }
    std::ostringstream yStringStream;
    for (auto byte : iv) {
      yStringStream << std::setw(2) << std::setfill('0') << std::hex
                    << +static_cast<unsigned char>(byte);
    }

    nlohmann::json devPublicKeyJSON = {{"x", "PUT_DEV_X"}, {"y", "PUT_DEV_Y"}};

    nlohmann::json object = {
        {"tpm_ecc_public_key", policyJson["tpm_ecc_public_key"]},
        {"dev_ecc_public_key", devPublicKeyJSON},
        {"secrets", secretsElement},
        {"iv", ivStringStream.str()}};
    std::cout << object.dump(2) << std::endl;
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