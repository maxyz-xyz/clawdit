export type PathValidation = {
    valid: true;
    resolvedPath: string;
} | {
    valid: false;
    error: string;
};
export declare function validatePath(rootDir: string): PathValidation;
export declare function createSecureTempFile(prefix: string): {
    tempDir: string;
    tempFile: string;
};
export declare function cleanupTempDir(tempDir: string): void;
