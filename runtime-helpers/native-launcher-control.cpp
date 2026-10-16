// Authored receiver for real native argument, environment and exit propagation.
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fcntl.h>
#include <io.h>
std::string utf8(const wchar_t *value) {
  const auto length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, nullptr, 0, nullptr, nullptr);
  if (!length) std::exit(63);
  std::string result(static_cast<size_t>(length), '\0');
  if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, result.data(), length, nullptr, nullptr)) std::exit(63);
  result.pop_back(); return result;
}
#endif
std::string hex(const std::string &value) {
  const char digits[] = "0123456789abcdef";
  std::string result;
  for (const auto character : value) {
    const auto byte = static_cast<unsigned char>(character);
    result += digits[byte >> 4]; result += digits[byte & 15];
  }
  return result;
}
#ifdef _WIN32
int wmain(int argc, wchar_t **argv) {
  if (_setmode(_fileno(stdout), _O_BINARY) < 0) return 62;
  for (int index = 0; index < argc; ++index) std::cout << "arg\t" << hex(utf8(argv[index])) << '\n';
#else
int main(int argc, char **argv) {
  for (int index = 0; index < argc; ++index) std::cout << "arg\t" << hex(argv[index]) << '\n';
#endif
#ifdef _WIN32
  for (const auto *name : {L"USE_BUILTIN_RIPGREP", L"RIPGREP_CONFIG_PATH", L"PATH"}) {
    const auto needed = GetEnvironmentVariableW(name, nullptr, 0);
    std::wstring value(needed ? needed : 1, L'\0');
    if (needed && GetEnvironmentVariableW(name, value.data(), needed) >= needed) return 61;
    std::cout << utf8(name) << '\t' << (needed ? hex(utf8(value.c_str())) : "<unset>") << '\n';
  }
#else
  for (const auto *name : {"USE_BUILTIN_RIPGREP", "RIPGREP_CONFIG_PATH", "PATH"}) {
    const auto *value = std::getenv(name);
    std::cout << name << '\t' << (value ? hex(value) : "<unset>") << '\n';
  }
#endif
  return 37;
}
