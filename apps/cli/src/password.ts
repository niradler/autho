/**
 * Secure masked password input - reads from stdin char-by-char,
 * echoing * instead of the actual characters.
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

      // Enter / Return
      if (char === "\r" || char === "\n") {
        cleanup();
        process.stdout.write("\n");
        resolve(password);
        return;
      }

      // Ctrl+C
      if (code === 3) {
        cleanup();
        process.stdout.write("\n");
        reject(new Error("Password input cancelled"));
        return;
      }

      // Ctrl+D (EOF)
      if (code === 4) {
        cleanup();
        process.stdout.write("\n");
        resolve(password);
        return;
      }

      // Backspace / Delete
      if (code === 127 || code === 8) {
        if (password.length > 0) {
          password = password.slice(0, -1);
          process.stdout.write("\b \b");
        }
        return;
      }

      // Escape sequences (arrows, etc.) - ignore
      if (code === 27) {
        return;
      }

      // Regular printable character
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
