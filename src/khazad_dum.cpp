#include "khazad_dum.h"

namespace Moria {
void KhazadDum::createPolicy(std::string policyOutputFilename) {
  auto pPrimaryObject = tpm2hal->createPrimaryObject();
  std::ofstream policyOutputFile;

  nlohmann::json object = {{"tpm_ecc_key", pPrimaryObject->serialize()}};

  policyOutputFile.open(policyOutputFilename);
  if (!policyOutputFile.is_open()) {
    std::cout << "Could not open specified file" << std::endl;
    return;
  }

  policyOutputFile << object.dump(2) << std::endl;
}

void KhazadDum::encryptSecrets(std::string policyInputFilename,
                               std::string secretsInputFilename,
                               std::string privateKeyInputFilename) {
  std::ifstream policyInputFile(policyInputFilename);
  if (!policyInputFile.is_open()) {
    std::cout << "Could not open specified policy file" << std::endl;
    return;
  }
  nlohmann::json policyJson = nlohmann::json::parse(policyInputFile);
  std::string x = policyJson["tpm_ecc_key"]["pub_key"]["x"];
  std::string y = policyJson["tpm_ecc_key"]["pub_key"]["y"];

  std::ifstream secretsInputFile(secretsInputFilename);
  if (!secretsInputFile.is_open()) {
    std::cout << "Could not open specified secrets file" << std::endl;
    return;
  }
  nlohmann::json secretsJson = nlohmann::json::parse(secretsInputFile);

  std::ifstream privateKeyInputFile(privateKeyInputFilename);
  if (!privateKeyInputFile.is_open()) {
    std::cout << "Could not open specified private key file" << std::endl;
    return;
  }

  std::string privateKey((std::istreambuf_iterator<char>(privateKeyInputFile)),
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
    std::string cleartext = secret.key();
    cleartext += "|";
    cleartext += secret.value();
    secretsElement[secret.key()] = aesProcessor.encrypt(cleartext, iv);
  }

  Moria::ECPublicKeyPoint devPublicKey =
      ecKeyConverter.convertPEMToPoint(privateKey);
  std::ostringstream xStringStream;
  for (auto byte : devPublicKey.first) {
    xStringStream << std::setw(2) << std::setfill('0') << std::hex
                  << +static_cast<unsigned char>(byte);
  }
  std::ostringstream yStringStream;
  for (auto byte : devPublicKey.second) {
    yStringStream << std::setw(2) << std::setfill('0') << std::hex
                  << +static_cast<unsigned char>(byte);
  }

  std::ostringstream ivStringStream;
  for (auto byte : iv) {
    ivStringStream << std::setw(2) << std::setfill('0') << std::hex
                   << +static_cast<unsigned char>(byte);
  }

  nlohmann::json devPublicKeyJSON = {
      "pub_key", {{"x", xStringStream.str()}, {"y", yStringStream.str()}}};

  nlohmann::json object = {{"tpm_ecc_key", policyJson["tpm_ecc_key"]},
                           {"dev_ecc_key", devPublicKeyJSON},
                           {"secrets", secretsElement},
                           {"iv", ivStringStream.str()}};
  std::cout << object.dump(2) << std::endl;
}
};  // namespace Moria