/* Own fixture server and client share only this fresh, network-isolated root. */
#define main fixtureMain
#include "offline-fixture.cpp"
#undef main
#include <sys/wait.h>
#include <cstdlib>

int waitFor(pid_t pid) {
  int status; while (waitpid(pid, &status, 0) < 0) require(errno == EINTR, "wait owned child");
  return WIFEXITED(status) ? WEXITSTATUS(status) : WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 255;
}
int main(int argc, char **argv) try {
  require(argc >= 2, "client command or --qualification"); alarm(55); signal(SIGPIPE, SIG_IGN);
  const auto before = [](const char *name, const char *path) {
    char value[96]; auto n = readlink(path, value, sizeof(value) - 1);
    require(n > 0 && n < (ssize_t)sizeof(value) - 1, "outer namespace identity"); value[n] = 0;
    require(setenv(name, value, 1) == 0, "namespace environment");
  };
  before("NEVERD_OUTER_PID_NS", "/proc/self/ns/pid"); before("NEVERD_OUTER_USER_NS", "/proc/self/ns/user");
  before("NEVERD_OUTER_MOUNT_NS", "/proc/self/ns/mnt");
  before("NEVERD_OUTER_NET_NS", "/proc/self/ns/net");
  auto server = fork(); require(server >= 0, "fork owned fixture");
  if (server == 0) _exit(serve("/report/spec.json", "/report"));
  J ready;
  for (int i = 0; i < 5000; ++i) {
    if (fs::exists("/report/ready.jsonl") && fs::file_size("/report/ready.jsonl")) { ready = read("/report/ready.jsonl"); break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  require(ready.is_object() && ready.at("pid") == server, "owned fixture ready");
  const unsigned port = ready.at("port"); require(port > 1024 && port < 65536, "fixture port");
  auto url = "http://127.0.0.1:" + std::to_string(port);
  require(setenv("ANTHROPIC_BASE_URL", url.c_str(), 1) == 0, "fixture environment");
  const auto portText = std::to_string(port);
  require(setenv("NEVERD_FIXTURE_PORT", portText.c_str(), 1) == 0, "fixture port environment");
  int code;
  if (std::string(argv[1]) == "--qualification") code = probe(port, 1);
  else {
    auto client = fork(); require(client >= 0, "fork owned client");
    if (client == 0) { execv(argv[1], argv + 1); perror("client exec"); _exit(126); }
    code = waitFor(client);
  }
  require(kill(server, SIGTERM) == 0, "stop owned fixture"); auto serverCode = waitFor(server);
  log("/report/driver-execution.jsonl", {{"client_exit", code}, {"fixture_exit", serverCode}, {"owned_server", true}});
  return code;
} catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 70; }
