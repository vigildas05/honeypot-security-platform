// Canned-response fake shell.
//
// SAFETY: this module must never execute anything. It only maps attacker input
// strings to canned output strings. It does not import child_process, fs, vm,
// or anything else capable of side effects, and a unit test enforces that.

const HOSTNAME_DEFAULT = "srv-web-01";
const KERNEL = "5.15.0-105-generic";
const UNAME_A = (/** @type {string} */ host) =>
  `Linux ${host} ${KERNEL} #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux`;

const MAX_OUTPUT = 4096;

/** @type {Record<string, string>} */
const FILES = {
  "/etc/passwd": [
    "root:x:0:0:root:/root:/bin/bash",
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin",
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"
  ].join("\n"),
  "/etc/os-release": [
    'PRETTY_NAME="Ubuntu 22.04.4 LTS"',
    'NAME="Ubuntu"',
    'VERSION_ID="22.04"',
    'VERSION="22.04.4 LTS (Jammy Jellyfish)"',
    "ID=ubuntu",
    "ID_LIKE=debian"
  ].join("\n"),
  "/proc/cpuinfo": [
    "processor\t: 0",
    "vendor_id\t: GenuineIntel",
    "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz",
    "cpu MHz\t\t: 2399.998",
    "cache size\t: 35840 KB",
    "",
    "processor\t: 1",
    "vendor_id\t: GenuineIntel",
    "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz",
    "cpu MHz\t\t: 2399.998",
    "cache size\t: 35840 KB"
  ].join("\n"),
  "/proc/meminfo": ["MemTotal:        2030712 kB", "MemFree:          214332 kB", "MemAvailable:    1288544 kB"].join("\n"),
  "/proc/version": `Linux version ${KERNEL} (buildd@lcy02-amd64-033) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #115-Ubuntu SMP`,
  "/etc/issue": "Ubuntu 22.04.4 LTS \\n \\l",
  "/root/.bash_history": "",
  "/root/.ssh/authorized_keys": ""
};

/** @type {Record<string, string[]>} */
const DIRS = {
  "/": ["bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"],
  "/root": [],
  "/root/.ssh": ["authorized_keys"],
  "/home": ["ubuntu"],
  "/home/ubuntu": [],
  "/tmp": [],
  "/var": ["backups", "cache", "lib", "log", "tmp", "www"],
  "/var/tmp": [],
  "/etc": ["hostname", "hosts", "issue", "os-release", "passwd", "shadow", "ssh"]
};
const HIDDEN = { "/root": [".bashrc", ".profile", ".ssh"], "/home/ubuntu": [".bashrc", ".profile"] };

// Commands whose only canned behavior is "succeed silently".
const SILENT = new Set([
  "cd", "export", "unset", "set", "alias", "unalias", "chmod", "chown", "chattr", "chgrp", "rm",
  "mkdir", "rmdir", "touch", "cp", "mv", "ln", "kill", "pkill", "killall", "sleep", "nohup",
  "sync", "true", "ulimit", "umask", "history", "clear", "source", ".", "mount", "systemctl",
  "service", "iptables", "ufw", "useradd", "usermod", "passwd", "chpasswd", "sh", "bash", "dash",
  "tar", "unzip", "gzip", "base64", "sed", "awk", "grep", "head", "tail", "sort", "uniq", "wc",
  "cut", "tr", "xargs", "tee", "sha256sum", "md5sum", "dd", "setsid", "disown", "wait", "trap", "exec"
]);
const NOT_INSTALLED = new Set(["python", "python2", "python3", "perl", "gcc", "cc", "make", "nc", "ncat", "socat", "ftp", "php", "ruby", "docker"]);
const PIPE_FILTERS = new Set(["grep", "head", "tail", "wc", "awk", "sed", "sort", "uniq", "cut", "tr", "xargs", "tee", "less", "more"]);

/**
 * @typedef {{ username: string, hostname: string, cwd: string, home: string }} ShellState
 */

/**
 * @param {{ username: string, hostname?: string }} opts
 * @returns {ShellState}
 */
export function createShellState({ username, hostname = HOSTNAME_DEFAULT }) {
  const home = username === "root" ? "/root" : `/home/${safeName(username)}`;
  return { username: safeName(username), hostname, cwd: home, home };
}

/** Usernames echoed into prompts are limited to a tame character set. */
function safeName(/** @type {string} */ name) {
  const cleaned = name.replace(/[^a-zA-Z0-9_.-]/g, "").slice(0, 32);
  return cleaned || "user";
}

/** @param {ShellState} state */
export function prompt(state) {
  const dir = state.cwd === state.home ? "~" : state.cwd;
  return `${state.username}@${state.hostname}:${dir}${state.username === "root" ? "#" : "$"} `;
}

/**
 * Split a command line into words, honoring simple quotes and backslashes.
 * This is a tokenizer for canned responses only; nothing is evaluated.
 * @param {string} line
 * @returns {string[]}
 */
export function tokenize(line) {
  const words = [];
  let current = "";
  let quote = "";
  let inWord = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === quote) quote = "";
      else if (ch === "\\" && quote === '"' && i + 1 < line.length) current += line[++i];
      else current += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      inWord = true;
    } else if (ch === "\\" && i + 1 < line.length) {
      current += line[++i];
      inWord = true;
    } else if (/\s/.test(ch)) {
      if (inWord) words.push(current);
      current = "";
      inWord = false;
    } else {
      current += ch;
      inWord = true;
    }
  }
  if (inWord) words.push(current);
  return words;
}

/**
 * Split on ; && || (outside quotes) into sequential segments, and each segment
 * on | into pipeline stages.
 * @param {string} line
 * @returns {string[][]}
 */
export function splitCommands(line) {
  /** @type {string[][]} */
  const segments = [];
  /** @type {string[]} */
  let stages = [];
  let current = "";
  let quote = "";
  const pushStage = () => {
    if (current.trim()) stages.push(current.trim());
    current = "";
  };
  const pushSegment = () => {
    pushStage();
    if (stages.length) segments.push(stages);
    stages = [];
  };
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    const next = line[i + 1];
    if (quote) {
      if (ch === quote) quote = "";
      current += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      current += ch;
    } else if (ch === ";" || ch === "\n") {
      pushSegment();
    } else if ((ch === "&" && next === "&") || (ch === "|" && next === "|")) {
      pushSegment();
      i++;
    } else if (ch === "|") {
      pushStage();
    } else if (ch === "&" && next !== ">" && line[i - 1] !== ">") {
      pushSegment(); // trailing/background '&'
    } else {
      current += ch;
    }
  }
  pushSegment();
  return segments;
}

/** @param {ShellState} state @param {string} target */
function resolvePath(state, target) {
  if (!target || target === "~") return state.home;
  let path = target.startsWith("~/") ? `${state.home}/${target.slice(2)}` : target;
  if (!path.startsWith("/")) path = `${state.cwd === "/" ? "" : state.cwd}/${path}`;
  const parts = [];
  for (const part of path.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") parts.pop();
    else parts.push(part);
  }
  return `/${parts.join("/")}`;
}

/**
 * Strip shell redirections; report whether stdout was redirected away.
 * @param {string[]} words
 */
function stripRedirections(words) {
  const out = [];
  let stdoutRedirected = false;
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (/^(\d?>>?|&>|<)$/.test(w)) {
      if (w !== "<" && !w.startsWith("2")) stdoutRedirected = true;
      i++; // skip target
    } else if (/^(\d?>>?|&>|<)\S+$/.test(w)) {
      if (!w.startsWith("<") && !w.startsWith("2")) stdoutRedirected = true;
    } else if (/^\d>&\d$/.test(w)) {
      // 2>&1 etc.
    } else {
      out.push(w);
    }
  }
  return { words: out, stdoutRedirected };
}

/**
 * @param {ShellState} state
 * @param {string[]} words
 * @returns {{ output: string, exit?: boolean }}
 */
function runSimple(state, words) {
  const { words: args, stdoutRedirected } = stripRedirections(words);
  if (args.length === 0) return { output: "" };
  let [cmd, ...rest] = args;
  if (cmd === "sudo") {
    if (rest.length === 0) return { output: "usage: sudo -h | -K | -k | -V" };
    [cmd, ...rest] = rest.filter((a) => !a.startsWith("-"));
    if (!cmd) return { output: "" };
  }
  const base = cmd.split("/").pop() ?? cmd;
  const result = respond(state, base, rest, cmd);
  return stdoutRedirected ? { ...result, output: "" } : result;
}

/**
 * @param {ShellState} state
 * @param {string} cmd basename of the command
 * @param {string[]} args
 * @param {string} typed what the attacker actually typed as argv[0]
 * @returns {{ output: string, exit?: boolean }}
 */
function respond(state, cmd, args, typed) {
  const isRoot = state.username === "root";
  switch (cmd) {
    case "exit":
    case "logout":
    case "quit":
      return { output: "", exit: true };
    case "whoami":
      return { output: state.username };
    case "id":
      return {
        output: isRoot
          ? "uid=0(root) gid=0(root) groups=0(root)"
          : `uid=1000(${state.username}) gid=1000(${state.username}) groups=1000(${state.username}),27(sudo)`
      };
    case "hostname":
      return { output: state.hostname };
    case "uname":
      if (args.includes("-a")) return { output: UNAME_A(state.hostname) };
      if (args.includes("-r")) return { output: KERNEL };
      if (args.includes("-m") || args.includes("-p")) return { output: "x86_64" };
      if (args.includes("-n")) return { output: state.hostname };
      return { output: "Linux" };
    case "arch":
      return { output: "x86_64" };
    case "pwd":
      return { output: state.cwd };
    case "cd": {
      const target = resolvePath(state, args[0] ?? "~");
      if (FILES[target] !== undefined) return { output: `-bash: cd: ${args[0]}: Not a directory` };
      state.cwd = target;
      return { output: "" };
    }
    case "ls": {
      const showHidden = args.some((a) => /^-\w*a/.test(a));
      const long = args.some((a) => /^-\w*l/.test(a));
      const target = resolvePath(state, args.find((a) => !a.startsWith("-")) ?? state.cwd);
      if (FILES[target] !== undefined) return { output: target };
      const entries = [
        ...(showHidden ? [".", "..", ...(/** @type {Record<string,string[]>} */ (HIDDEN)[target] ?? [])] : []),
        ...(DIRS[target] ?? [])
      ];
      if (!long) return { output: entries.join("  ") };
      return {
        output: [`total ${entries.length * 4}`, ...entries.map((e) => `drwxr-xr-x 2 root root 4096 Apr 18 10:12 ${e}`)].join("\n")
      };
    }
    case "cat": {
      const outputs = [];
      for (const arg of args.filter((a) => !a.startsWith("-"))) {
        const path = resolvePath(state, arg);
        if (path === "/etc/hostname") outputs.push(state.hostname);
        else if (path === "/etc/shadow" && !isRoot) outputs.push("cat: /etc/shadow: Permission denied");
        else if (path === "/etc/shadow") outputs.push("root:$6$Tq2nq5Jz$Wn0x9mYfC1:19800:0:99999:7:::");
        else if (FILES[path] !== undefined) outputs.push(FILES[path]);
        else outputs.push(`cat: ${arg}: No such file or directory`);
      }
      return { output: outputs.filter(Boolean).join("\n") };
    }
    case "echo": {
      const text = args.filter((a, i) => !(i === 0 && /^-[neE]+$/.test(a))).join(" ");
      return { output: text };
    }
    case "nproc":
      return { output: "2" };
    case "free":
      return {
        output: args.includes("-h")
          ? "               total        used        free      shared  buff/cache   available\nMem:           1.9Gi       612Mi       209Mi       1.0Mi       1.1Gi       1.2Gi\nSwap:             0B          0B          0B"
          : "               total        used        free      shared  buff/cache   available\nMem:         2030712      627312      214332        1028     1189068     1288544\nSwap:              0           0           0"
      };
    case "uptime":
      return { output: " 10:41:07 up 47 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01" };
    case "w":
      return {
        output: ` 10:41:07 up 47 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n${state.username.padEnd(8)} pts/0    -                10:40    0.00s  0.01s  0.00s w`
      };
    case "ps":
      return {
        output: "    PID TTY          TIME CMD\n      1 ?        00:00:12 systemd\n    612 ?        00:00:00 sshd\n   1187 ?        00:01:43 nginx\n   2044 pts/0    00:00:00 bash\n   2051 pts/0    00:00:00 ps"
      };
    case "df":
      return { output: "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        29G  6.1G   23G  21% /\ntmpfs           992M     0  992M   0% /dev/shm" };
    case "lscpu":
      return { output: "Architecture:            x86_64\nCPU(s):                  2\nModel name:              Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz" };
    case "top":
      return { output: "top: failed tty get" };
    case "crontab":
      if (args.includes("-l")) return { output: `no crontab for ${state.username}` };
      return { output: "" };
    case "wget": {
      const url = args.find((a) => !a.startsWith("-")) ?? "";
      if (!url) return { output: "wget: missing URL" };
      const host = hostOf(url);
      return { output: `--2024-04-18 10:41:07--  ${url}\nResolving ${host} (${host})... failed: Temporary failure in name resolution.\nwget: unable to resolve host address '${host}'` };
    }
    case "curl": {
      const url = args.find((a) => !a.startsWith("-") && /[./]/.test(a)) ?? "";
      if (!url) return { output: "curl: try 'curl --help' or 'curl --manual' for more information" };
      return { output: `curl: (6) Could not resolve host: ${hostOf(url)}` };
    }
    case "tftp":
      return { output: "Transfer timed out." };
    case "busybox":
      return { output: args[0] ? `${args[0]}: applet not found` : "BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3) multi-call binary." };
    case "which": {
      return { output: args.filter((a) => !NOT_INSTALLED.has(a)).map((a) => `/usr/bin/${a}`).join("\n") };
    }
    case "env":
    case "printenv":
      return { output: `SHELL=/bin/bash\nPWD=${state.cwd}\nLOGNAME=${state.username}\nHOME=${state.home}\nUSER=${state.username}\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` };
    default:
      if (SILENT.has(cmd)) return { output: "" };
      if (cmd.startsWith("./") || typed.startsWith("/tmp/") || typed.startsWith("./")) {
        return { output: `-bash: ${typed}: Permission denied` };
      }
      return { output: `-bash: ${typed}: command not found` };
  }
}

/** @param {string} url */
function hostOf(url) {
  const m = /^(?:[a-z]+:\/\/)?([^/:?#\s]+)/i.exec(url);
  return m ? m[1] : url;
}

/**
 * Produce the canned response for one input line.
 * @param {ShellState} state
 * @param {string} line
 * @returns {{ output: string, exit: boolean }}
 */
export function runLine(state, line) {
  const outputs = [];
  for (const stages of splitCommands(line)) {
    // Pipelines: there is no real stdin, so filter stages (grep, wc, ...) are
    // treated as pass-through and every other stage's output is shown, which
    // approximates stdout+stderr well enough for bots.
    for (const [index, stage] of stages.entries()) {
      const words = tokenize(stage);
      const base = (words[0] ?? "").split("/").pop() ?? "";
      if (index > 0 && PIPE_FILTERS.has(base)) continue;
      const result = runSimple(state, words);
      if (result.output) outputs.push(result.output);
      if (result.exit) return { output: clip(outputs.join("\n")), exit: true };
    }
  }
  return { output: clip(outputs.join("\n")), exit: false };
}

/** @param {string} s */
function clip(s) {
  return s.length > MAX_OUTPUT ? s.slice(0, MAX_OUTPUT) : s;
}
