// Authored Windows argv[0] transport. Child processes inherit the AppContainer.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

static std::wstring quote(const wchar_t *value) {
  std::wstring out = L"\"";
  unsigned slashes = 0;
  for (const wchar_t *p = value; *p; ++p) {
    if (*p == L'\\') { ++slashes; continue; }
    out.append(slashes * (*p == L'"' ? 2 : 1), L'\\');
    slashes = 0;
    if (*p == L'"') out.push_back(L'\\');
    out.push_back(*p);
  }
  out.append(slashes * 2, L'\\');
  out.push_back(L'"');
  return out;
}
static void hex(FILE *stream, const wchar_t *value) {
  if (!value) { std::fputs("null", stream); return; }
  std::fputc('"', stream);
  for (auto p = value; *p; ++p) std::fprintf(stream, "%04x", static_cast<unsigned>(*p));
  std::fputc('"', stream);
}
int wmain(int argc, wchar_t **argv) {
  std::wstring actual = argc ? argv[0] : L"";
  auto separator = actual.find_last_of(L"\\/");
  if (separator != std::wstring::npos) actual.erase(0, separator + 1);
  if (actual == L"receiver.exe") {
    if (argc != 2 || _setmode(_fileno(stdout), _O_BINARY) == -1 ||
        _setmode(_fileno(stderr), _O_BINARY) == -1) return 65;
    FILE *input = _wfopen(argv[1], L"rb");
    if (!input) return 66;
    std::fputs("{\"kind\":\"owned-rg-preprocessor\",\"env_utf16_hex\":", stdout);
    hex(stdout, _wgetenv(L"ARGV0"));
    std::fputs(",\"input_utf16_hex\":", stdout); hex(stdout, argv[1]);
    std::fputs("}\n", stdout);
    char bytes[4096];
    while (auto count = std::fread(bytes, 1, sizeof(bytes), input)) {
      if (std::fwrite(bytes, 1, count, stdout) != count) { std::fclose(input); return 67; }
    }
    bool failed = std::ferror(input) != 0;
    std::fclose(input);
    return failed ? 68 : 0;
  }
  if (argc == 2 && std::wstring(argv[1]) == L"--capture") {
    std::fputs("{\"argv0_utf16_hex\":", stdout); hex(stdout, argv[0]);
    std::fputs(",\"env_utf16_hex\":", stdout); hex(stdout, _wgetenv(L"ARGV0"));
    std::puts("}"); return 37;
  }
  if (argc < 3) return 64;
  std::wstring command;
  for (int i = 2; i < argc; ++i) {
    if (i != 2) command.push_back(L' ');
    command += quote(argv[i]);
  }
  std::vector<wchar_t> buffer(command.begin(), command.end()); buffer.push_back(0);
  STARTUPINFOW start{}; start.cb = sizeof(start);
  start.dwFlags = STARTF_USESTDHANDLES;
  start.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  start.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  start.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(argv[1], buffer.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &start, &process)) {
    std::fprintf(stderr, "owned role CreateProcessW: %lu\n", GetLastError()); return 126;
  }
  CloseHandle(process.hThread);
  if (WaitForSingleObject(process.hProcess, INFINITE) != WAIT_OBJECT_0) return 126;
  DWORD code = 126; GetExitCodeProcess(process.hProcess, &code); CloseHandle(process.hProcess);
  return static_cast<int>(code);
}
