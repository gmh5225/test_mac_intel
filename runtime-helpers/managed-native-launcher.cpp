// Authored managed search adapter. Original Bun multicall routing is separate.
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#ifndef ENGINE_NAME
#error ENGINE_NAME must name one packaged client
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int fail(const wchar_t *operation) {
  std::wcerr << L"recovered search runtime: " << operation << L": " << GetLastError() << L'\n';
  return 126;
}

bool regular_file(const std::wstring &path) {
  const auto attributes = GetFileAttributesW(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES &&
         !(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}

std::wstring quoted(const std::wstring &value) {
  // Windows CRT command-line quoting; shared algorithm with the qualified
  // AppContainer launcher. Always quote, including empty arguments.
  std::wstring result = L"\"";
  size_t slashes = 0;
  for (const auto character : value) {
    if (character == L'\\') {
      ++slashes;
    } else if (character == L'\"') {
      result.append(slashes * 2 + 1, L'\\');
      result += character;
      slashes = 0;
    } else {
      result.append(slashes, L'\\');
      result += character;
      slashes = 0;
    }
  }
  result.append(slashes * 2, L'\\');
  return result + L'\"';
}

int wmain(int argc, wchar_t **argv) {
  std::vector<wchar_t> buffer(32768);
  const auto length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (!length || length >= buffer.size()) return fail(L"resolve launcher");
  const std::wstring executable(buffer.data(), length);
  const auto slash = executable.find_last_of(L"\\/");
  if (slash == std::wstring::npos) { SetLastError(ERROR_INVALID_NAME); return fail(L"resolve directory"); }
  const auto directory = executable.substr(0, slash);
  const auto helpers = directory + L"\\search";
  const auto search = helpers + L"\\rg.exe";
  const auto engine = directory + L"\\" ENGINE_NAME;
  const auto attributes = GetFileAttributesW(helpers.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
      (attributes & FILE_ATTRIBUTE_REPARSE_POINT) || !regular_file(search)) {
    SetLastError(ERROR_FILE_NOT_FOUND); return fail(L"search helper unavailable");
  }
  if (!regular_file(engine)) { SetLastError(ERROR_FILE_NOT_FOUND); return fail(L"client unavailable"); }
  const auto needed = GetEnvironmentVariableW(L"PATH", nullptr, 0);
  std::vector<wchar_t> previous(needed ? needed : 1);
  if (needed && GetEnvironmentVariableW(L"PATH", previous.data(), needed) >= needed)
    return fail(L"read PATH");
  std::wstring path = helpers;
  if (needed > 1) path += L";" + std::wstring(previous.data());
  if (!SetEnvironmentVariableW(L"PATH", path.c_str()) ||
      !SetEnvironmentVariableW(L"USE_BUILTIN_RIPGREP", L"false"))
    return fail(L"configure managed search");
  if (!SetEnvironmentVariableW(L"RIPGREP_CONFIG_PATH", nullptr) && GetLastError() != ERROR_ENVVAR_NOT_FOUND)
    return fail(L"ignore external ripgrep configuration");
  std::wstring command = quoted(engine);
  for (int index = 1; index < argc; ++index) command += L" " + quoted(argv[index]);
  STARTUPINFOW startup{}; startup.cb = static_cast<DWORD>(sizeof(startup));
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  PROCESS_INFORMATION child{};
  if (!CreateProcessW(engine.c_str(), command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startup, &child))
    return fail(L"execute client");
  CloseHandle(child.hThread);
  if (WaitForSingleObject(child.hProcess, INFINITE) != WAIT_OBJECT_0) {
    CloseHandle(child.hProcess); return fail(L"wait for client");
  }
  DWORD status = 126;
  if (!GetExitCodeProcess(child.hProcess, &status)) {
    CloseHandle(child.hProcess); return fail(L"read client status");
  }
  CloseHandle(child.hProcess);
  ExitProcess(status);
}

#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

int fail(const char *operation) {
  std::cerr << "recovered search runtime: " << operation << ": " << std::strerror(errno) << '\n';
  return 126;
}

bool regular_file(const std::string &path) {
  struct stat info{};
  if (lstat(path.c_str(), &info) != 0) return false;
  if (!S_ISREG(info.st_mode)) { errno = EINVAL; return false; }
  return access(path.c_str(), R_OK | X_OK) == 0;
}

int main(int, char **argv) {
  uint32_t length = 0;
  if (_NSGetExecutablePath(nullptr, &length) != -1 || !length || length > 1024 * 1024)
    return fail("resolve launcher size");
  std::vector<char> buffer(length);
  if (_NSGetExecutablePath(buffer.data(), &length)) return fail("resolve launcher");
  char resolved[PATH_MAX];
  if (!realpath(buffer.data(), resolved)) return fail("resolve launcher path");
  const std::string executable(resolved);
  const auto slash = executable.rfind('/');
  if (slash == std::string::npos) { errno = EINVAL; return fail("resolve directory"); }
  const auto directory = executable.substr(0, slash);
  const auto helpers = directory + "/search";
  const auto search = helpers + "/rg";
  auto engine = directory + "/" ENGINE_NAME;
  struct stat folder{};
  if (lstat(helpers.c_str(), &folder) != 0) return fail("search helper unavailable");
  if (!S_ISDIR(folder.st_mode)) { errno = EINVAL; return fail("search helper unavailable"); }
  if (!regular_file(search)) return fail("search helper unavailable");
  if (!regular_file(engine)) return fail("client unavailable");
  std::string path = helpers;
  if (const auto *previous = std::getenv("PATH"); previous && *previous) path += ":" + std::string(previous);
  if (setenv("PATH", path.c_str(), 1) || setenv("USE_BUILTIN_RIPGREP", "false", 1) || unsetenv("RIPGREP_CONFIG_PATH"))
    return fail("configure managed search");
  argv[0] = engine.data();
  execv(engine.c_str(), argv);
  return fail("execute client");
}
#else
#error This adapter is for macOS and Windows; use the qualified Linux adapter.
#endif
