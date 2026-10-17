// Managed component adapter; the engine's built-in multicall role is separate.
#include <unistd.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits.h>
#include <string>
#ifndef ENGINE_NAME
#error ENGINE_NAME must select a packaged client
#endif

int fail(const char *operation) {
  std::cerr << "recovered runtime: " << operation << ": " << std::strerror(errno) << '\n';
  return 126;
}

bool executable_file(const std::string &path) {
  struct stat info{};
  if (lstat(path.c_str(), &info) != 0) return false;
  if (!S_ISREG(info.st_mode)) { errno = EINVAL; return false; }
  return access(path.c_str(), R_OK | X_OK) == 0;
}

int main(int, char **argv) {
  char path[PATH_MAX];
  auto length = readlink("/proc/self/exe", path, sizeof(path));
  if (length < 0) return fail("resolve launcher");
  if (static_cast<size_t>(length) == sizeof(path)) { errno = ENAMETOOLONG; return fail("resolve launcher"); }
  std::string executable(path, length);
  auto slash = executable.rfind('/');
  if (slash == std::string::npos) { errno = EINVAL; return fail("resolve directory"); }
  const auto directory = executable.substr(0, slash);
  const auto seccomp = directory + "/sandbox/apply-seccomp";
  if (!executable_file(seccomp)) return fail("seccomp helper unavailable");
  const char *role = std::getenv("ARGV0");
  if (role && std::strcmp(role, "apply-seccomp") == 0) {
    argv[0] = const_cast<char *>(seccomp.c_str());
    execv(seccomp.c_str(), argv);
    return fail("execute seccomp helper");
  }
  const auto helpers = directory + "/search";
  const auto search = helpers + "/rg";
  auto engine = directory + "/" ENGINE_NAME;
  if (!executable_file(engine)) return fail("client unavailable");
  if (!executable_file(search)) return fail("search helper unavailable");
  std::string path_value = helpers;
  if (const char *prior = std::getenv("PATH"); prior && *prior) path_value += ":" + std::string(prior);
  if (setenv("PATH", path_value.c_str(), 1) || setenv("USE_BUILTIN_RIPGREP", "false", 1) ||
      setenv("CLAUDE_RECOVERY_SECCOMP_PATH", seccomp.c_str(), 1))
    return fail("configure managed components");
  if (unsetenv("RIPGREP_CONFIG_PATH")) return fail("ignore external ripgrep configuration");
  argv[0] = engine.data();
  execv(engine.c_str(), argv);
  return fail("execute client");
}
