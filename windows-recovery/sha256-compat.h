#pragma once
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <stdexcept>
using CC_LONG = unsigned long;
constexpr unsigned CC_SHA256_DIGEST_LENGTH = 32;
inline unsigned char *CC_SHA256(const void *data, CC_LONG size, unsigned char *digest) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
    throw std::runtime_error("SHA256 provider failed");
  const auto result = BCryptHash(algorithm, nullptr, 0,
      reinterpret_cast<PUCHAR>(const_cast<void *>(data)), size, digest, 32);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  if (result < 0) throw std::runtime_error("SHA256 failed");
  return digest;
}
#else
#include <CommonCrypto/CommonDigest.h>
#endif
