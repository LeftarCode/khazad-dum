#include "khazad_dum.h"

namespace Moria {
std::string KhazadDum::convertBytesVectorToHexString(
    const std::vector<std::byte>& v) {
  std::ostringstream stringStream;
  for (int i = 0; i < v.size(); i++) {
    stringStream << std::setw(2) << std::setfill('0') << std::hex
                 << +static_cast<unsigned char>(v[i]);
  }

  return stringStream.str();
}

std::string KhazadDum::convert32BytesArrayToHexString(
    const std::array<std::byte, 32>& a) {
  std::ostringstream stringStream;
  for (int i = 0; i < 32; i++) {
    stringStream << std::setw(2) << std::setfill('0') << std::hex
                 << +static_cast<unsigned char>(a[i]);
  }

  return stringStream.str();
}

std::string KhazadDum::convert16BytesArrayToHexString(
    const std::array<std::byte, 16>& a) {
  std::ostringstream stringStream;
  for (int i = 0; i < 16; i++) {
    stringStream << std::setw(2) << std::setfill('0') << std::hex
                 << +static_cast<unsigned char>(a[i]);
  }

  return stringStream.str();
}

std::string KhazadDum::convert12BytesArrayToHexString(
    const std::array<std::byte, 12>& a) {
  std::ostringstream stringStream;
  for (int i = 0; i < 12; i++) {
    stringStream << std::setw(2) << std::setfill('0') << std::hex
                 << +static_cast<unsigned char>(a[i]);
  }

  return stringStream.str();
}

std::vector<std::byte> KhazadDum::convertHexStringToBytesVector(
    const std::string& s) {
  std::vector<std::byte> v;
  BIGNUM* input = BN_new();
  int input_length = (BN_hex2bn(&input, s.c_str()) + 1) / 2;
  v.resize(input_length);
  BN_bn2bin(input, (unsigned char*)v.data());

  return v;
}

std::array<std::byte, 32> KhazadDum::convertHexStringTo32BytesArray(
    const std::string& s) {
  std::array<std::byte, 32> a;
  BIGNUM* input = BN_new();
  int input_length = (BN_hex2bn(&input, s.c_str()) + 1) / 2;
  if (input_length > 32) {
    return {};
  }
  BN_bn2bin(input, (unsigned char*)std::begin(a));

  return a;
}

std::array<std::byte, 16> KhazadDum::convertHexStringTo16BytesArray(
    const std::string& s) {
  std::array<std::byte, 16> a;
  BIGNUM* input = BN_new();
  int input_length = (BN_hex2bn(&input, s.c_str()) + 1) / 2;
  if (input_length > 16) {
    return {};
  }
  BN_bn2bin(input, (unsigned char*)std::begin(a));

  return a;
}

std::array<std::byte, 12> KhazadDum::convertHexStringTo12BytesArray(
    const std::string& s) {
  std::array<std::byte, 12> a;
  BIGNUM* input = BN_new();
  int input_length = (BN_hex2bn(&input, s.c_str()) + 1) / 2;
  if (input_length > 12) {
    return {};
  }
  BN_bn2bin(input, (unsigned char*)std::begin(a));

  return a;
}

KhazadDum::KhazadDum() { pPrimaryObject = tpm2hal->createPrimaryObject(); }

void KhazadDum::createPolicy(std::string policyOutputFilename) {
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

  ECKeyConverter ecKeyConverter;
  ECPublicKeyPoint tpmPublicKeyPoint =
      ecKeyConverter.converHexStringToPoint(x, y);
  auto ecdhSecret =
      ecKeyConverter.generateSharedKey(privateKey, tpmPublicKeyPoint);

  AESProcessor aesProcessor(Moria::kAES256GCM, ecdhSecret);

  auto secretsElement = secretsJson["secrets"];
  for (auto& secret : secretsElement.items()) {
    Secret secretToEncrypt = {.name = secret.key(), .value = secret.value()};
    EncryptedSecret encryptedSecret =
        aesProcessor.encryptSecret(secretToEncrypt);

    std::string encryptedValueString =
        convertBytesVectorToHexString(encryptedSecret.value);
    std::string ivString = convert12BytesArrayToHexString(encryptedSecret.iv);
    std::string tagString = convert16BytesArrayToHexString(encryptedSecret.tag);

    nlohmann::json object = {
        {"value", encryptedValueString}, {"iv", ivString}, {"tag", tagString}};
    secretsElement[secret.key()] = object;
  }

  Moria::ECPublicKeyPoint devPublicKey =
      ecKeyConverter.convertPEMToPoint(privateKey);
  std::string xString = convert32BytesArrayToHexString(devPublicKey.first);
  std::string yString = convert32BytesArrayToHexString(devPublicKey.second);

  nlohmann::json devPublicKeyJSON = {{"x", xString}, {"y", yString}};

  nlohmann::json object = {{"tpm_ecc_key", policyJson["tpm_ecc_key"]},
                           {"dev_ecc_key", devPublicKeyJSON},
                           {"secrets", secretsElement}};
  std::cout << object.dump(2) << std::endl;
}

std::vector<Secret> KhazadDum::decryptSecrets(std::string policyInputFilename) {
  std::ifstream policyInputFile(policyInputFilename);
  if (!policyInputFile.is_open()) {
    std::cout << "Could not open specified policy file" << std::endl;
    return {};
  }
  nlohmann::json policyJson = nlohmann::json::parse(policyInputFile);
  nlohmann::json devEccKey = policyJson["dev_ecc_key"];

  std::string x = devEccKey["x"];
  std::string y = devEccKey["y"];

  ECKeyConverter ecKeyConverter;
  ECPublicKeyPoint devPublicKeyPoint =
      ecKeyConverter.converHexStringToPoint(x, y);

  TPM2B_ECC_POINT inPoint = {.size = 0,
                             .point = {.x = {.size = 32}, .y = {.size = 32}}};

  memcpy(inPoint.point.x.buffer, std::begin(devPublicKeyPoint.first), 32);
  memcpy(inPoint.point.y.buffer, std::begin(devPublicKeyPoint.second), 32);

  auto secretTPM = tpm2hal->generateSharedKey(pPrimaryObject, inPoint);

  AESProcessor aesProcessor(kAES256GCM, secretTPM);
  std::vector<Secret> secrets;
  for (const auto& secret : policyJson["secrets"].items()) {
    EncryptedSecret encryptedSecret;
    encryptedSecret.name = secret.key();
    encryptedSecret.value =
        convertHexStringToBytesVector(secret.value()["value"]);
    encryptedSecret.iv = convertHexStringTo12BytesArray(secret.value()["iv"]);
    encryptedSecret.tag = convertHexStringTo16BytesArray(secret.value()["tag"]);

    secrets.push_back(aesProcessor.decryptSecret(encryptedSecret));
  }

  return secrets;
}
};  // namespace Moria