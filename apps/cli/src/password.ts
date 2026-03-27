import { createInterface } from "node:readline/promises";

/**
 * Read a single line of visible input from the terminal.
 * Throws if stdin is not a TTY.
 */
export async function readLine(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new Error("Cannot read input: stdin is not a TTY");
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return await rl.question(prompt);
  } finally {
    rl.close();
  }
}

/**
 * Ask a yes/no question. Returns true for yes, false for no.
 * defaultYes controls the default when user just presses Enter.
 */
export async function confirm(question: string, defaultYes = true): Promise<boolean> {
  const hint = defaultYes ? "Y/n" : "y/N";
  const answer = (await readLine(`${question} (${hint}) `)).trim().toLowerCase();
  if (answer === "") return defaultYes;
  return answer === "y" || answer === "yes";
}

/**
 * Secure masked password input - reads from stdin char-by-char,
 * echoing * instead of the actual characters.
 * Raw mode is required here because we need to intercept each keypress.
 */
export async function readPasswordMasked(prompt = "Master password: "): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new Error("Cannot read password: stdin is not a TTY");
  }

  process.stdout.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding("utf8");

  let password = "";

  return new Promise<string>((resolve, reject) => {
    const onData = (char: string) => {
      const code = char.charCodeAt(0);

      if (char === "\r" || char === "\n") {
        cleanup();
        process.stdout.write("\n");
        resolve(password);
        return;
      }

      if (code === 3) {
        cleanup();
        process.stdout.write("\n");
        reject(new Error("Password input cancelled"));
        return;
      }

      if (code === 4) {
        cleanup();
        process.stdout.write("\n");
        resolve(password);
        return;
      }

      if (code === 127 || code === 8) {
        if (password.length > 0) {
          password = password.slice(0, -1);
          process.stdout.write("\b \b");
        }
        return;
      }

      if (code === 27) return;

      if (code >= 32) {
        password += char;
        process.stdout.write("*");
      }
    };

    const cleanup = () => {
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdin.removeListener("data", onData);
    };

    process.stdin.on("data", onData);
  });
}
