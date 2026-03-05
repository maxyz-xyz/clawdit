import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
export function validatePath(rootDir) {
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
    }
    catch (error) {
        const errnoError = error;
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
export function createSecureTempFile(prefix) {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    const tempFile = path.join(tempDir, "output.json");
    return { tempDir, tempFile };
}
export function cleanupTempDir(tempDir) {
    try {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
    catch {
        // Cleanup failures are non-fatal
    }
}
//# sourceMappingURL=utils.js.map