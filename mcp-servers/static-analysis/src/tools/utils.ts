import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export type PathValidation =
  | { valid: true; resolvedPath: string }
  | { valid: false; error: string };

export function validatePath(rootDir: string): PathValidation {
  const resolvedPath = path.resolve(rootDir);
  try {
    const lstat = fs.lstatSync(resolvedPath);
    if (lstat.isSymbolicLink()) {
      return {
        valid: false,
        error: `ERROR: INVALID_PATH - Path must not be a symlink: ${resolvedPath}`,
      };
    }
    const realPath = fs.realpathSync(resolvedPath);
    const stat = fs.statSync(realPath);
    if (!stat.isDirectory()) {
      return {
        valid: false,
        error: `ERROR: INVALID_PATH - Path is not a directory: ${realPath}`,
      };
    }
    return { valid: true, resolvedPath: realPath };
  } catch (error) {
    const errnoError = error as NodeJS.ErrnoException;
    if (errnoError.code === "ENOENT") {
      return {
        valid: false,
        error: `ERROR: INVALID_PATH - Directory does not exist: ${resolvedPath}`,
      };
    }
    const message = error instanceof Error ? error.message : String(error);
    return {
      valid: false,
      error: `ERROR: INVALID_PATH - Failed to validate path: ${message}`,
    };
  }
}

export function createSecureTempFile(prefix: string): {
  tempDir: string;
  tempFile: string;
} {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const tempFile = path.join(tempDir, "output.json");
  return { tempDir, tempFile };
}

export function cleanupTempDir(tempDir: string): void {
  try {
    fs.rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Cleanup failures are non-fatal
  }
}
