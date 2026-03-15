import { randomBytes } from "node:crypto";
import {
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import { basename, join, relative, resolve } from "node:path";

import {
  decryptWithKey,
  encryptWithKey,
  type EncryptedBlob,
} from "../../crypto/src/index.ts";
import {
  ensurePrivateDir,
  ensurePrivateParent,
  writeBinaryFileSecure,
  writeTextFileSecure,
} from "./paths.ts";

type FileEnvelope = {
  kind: "file";
  originalName: string;
  payload: EncryptedBlob;
  version: 1;
  wrappedKey: EncryptedBlob;
};

type FolderEnvelope = {
  entries: Array<{
    path: string;
    payload: EncryptedBlob;
  }>;
  kind: "folder";
  rootName: string;
  version: 1;
  wrappedKey: EncryptedBlob;
};

function normalizeRelativePath(input: string): string {
  return input.replace(/\\/g, "/");
}

function walkFiles(rootPath: string): string[] {
  const entries = readdirSync(rootPath, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    const entryPath = join(rootPath, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkFiles(entryPath));
      continue;
    }
    if (entry.isFile()) {
      files.push(entryPath);
    }
  }

  return files;
}

export function defaultEncryptedFilePath(inputPath: string): string {
  return `${inputPath}.autho`;
}

export function defaultDecryptedFilePath(inputPath: string): string {
  return inputPath.endsWith(".autho")
    ? inputPath.slice(0, -".autho".length)
    : `${inputPath}.decrypted`;
}

export function defaultEncryptedFolderPath(inputPath: string): string {
  return `${inputPath}.autho-folder`;
}

export function defaultDecryptedFolderPath(inputPath: string): string {
  return inputPath.endsWith(".autho-folder")
    ? inputPath.slice(0, -".autho-folder".length)
    : `${inputPath}.folder`;
}

export function encryptFileArtifact(inputPath: string, outputPath: string, rootKey: Buffer): {
  outputPath: string;
} {
  const fileKey = randomBytes(32);
  const payload = encryptWithKey(
    readFileSync(inputPath),
    fileKey,
    `autho:file:${basename(inputPath)}`,
  );
  const envelope: FileEnvelope = {
    kind: "file",
    originalName: basename(inputPath),
    payload,
    version: 1,
    wrappedKey: encryptWithKey(fileKey, rootKey, "autho:file:dek"),
  };

  writeTextFileSecure(outputPath, JSON.stringify(envelope, null, 2));

  return { outputPath };
}

export function decryptFileArtifact(inputPath: string, outputPath: string, rootKey: Buffer): {
  outputPath: string;
} {
  const envelope = JSON.parse(readFileSync(inputPath, "utf8")) as FileEnvelope;
  if (envelope.kind !== "file" || envelope.version !== 1) {
    throw new Error(`Unsupported file artifact: ${inputPath}`);
  }

  const fileKey = decryptWithKey(envelope.wrappedKey, rootKey, "autho:file:dek");
  const content = decryptWithKey(
    envelope.payload,
    fileKey,
    `autho:file:${envelope.originalName}`,
  );

  writeBinaryFileSecure(outputPath, content);

  return { outputPath };
}

export function encryptFolderArtifact(inputPath: string, outputPath: string, rootKey: Buffer): {
  fileCount: number;
  outputPath: string;
} {
  const folderKey = randomBytes(32);
  const files = walkFiles(inputPath);
  const rootName = basename(inputPath);

  const envelope: FolderEnvelope = {
    entries: files.map((filePath) => {
      const relativePath = normalizeRelativePath(relative(inputPath, filePath));
      return {
        path: relativePath,
        payload: encryptWithKey(
          readFileSync(filePath),
          folderKey,
          `autho:folder:${relativePath}`,
        ),
      };
    }),
    kind: "folder",
    rootName,
    version: 1,
    wrappedKey: encryptWithKey(folderKey, rootKey, `autho:folder:dek:${rootName}`),
  };

  writeTextFileSecure(outputPath, JSON.stringify(envelope, null, 2));

  return {
    fileCount: envelope.entries.length,
    outputPath,
  };
}

export function decryptFolderArtifact(inputPath: string, outputPath: string, rootKey: Buffer): {
  fileCount: number;
  outputPath: string;
} {
  const envelope = JSON.parse(readFileSync(inputPath, "utf8")) as FolderEnvelope;
  if (envelope.kind !== "folder" || envelope.version !== 1) {
    throw new Error(`Unsupported folder artifact: ${inputPath}`);
  }

  const folderKey = decryptWithKey(
    envelope.wrappedKey,
    rootKey,
    `autho:folder:dek:${envelope.rootName}`,
  );

  const resolvedOutput = resolve(outputPath);
  ensurePrivateDir(outputPath);
  for (const entry of envelope.entries) {
    const destination = join(outputPath, entry.path);
    const resolvedDest = resolve(destination);
    if (!resolvedDest.startsWith(resolvedOutput + "/") && !resolvedDest.startsWith(resolvedOutput + "\\") && resolvedDest !== resolvedOutput) {
      throw new Error(`Path traversal detected in folder artifact: ${entry.path}`);
    }
    ensurePrivateParent(destination);
    const content = decryptWithKey(
      entry.payload,
      folderKey,
      `autho:folder:${entry.path}`,
    );
    writeBinaryFileSecure(destination, content);
  }

  return {
    fileCount: envelope.entries.length,
    outputPath,
  };
}

export function assertPathIsDirectory(path: string): void {
  if (!statSync(path).isDirectory()) {
    throw new Error(`Expected directory: ${path}`);
  }
}

export function assertPathIsFile(path: string): void {
  if (!statSync(path).isFile()) {
    throw new Error(`Expected file: ${path}`);
  }
}
