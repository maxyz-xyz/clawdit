import { execFile } from "node:child_process";
import * as fs from "node:fs";
import { cleanupTempDir, createSecureTempFile, validatePath } from "./utils.js";
const SLITHER_TIMEOUT_MS = 5 * 60 * 1000;
const COMPILATION_ERROR_KEYWORDS = [
    "compilation",
    "solc",
    "compiler",
    "syntax error",
];
function isCompilationError(stderr) {
    const lower = stderr.toLowerCase();
    return COMPILATION_ERROR_KEYWORDS.some((k) => lower.includes(k));
}
function mapSeverity(impact) {
    const map = {
        Critical: "CRITICAL",
        High: "HIGH",
        Medium: "MEDIUM",
        Low: "LOW",
        Informational: "INFORMATIONAL",
        Optimization: "GAS",
    };
    return map[impact] ?? "INFORMATIONAL";
}
function mapConfidence(confidence) {
    const map = {
        High: "Confirmed",
        Medium: "Likely",
        Low: "Possible",
    };
    return map[confidence] ?? "Possible";
}
function parseOutput(output) {
    if (!output.success)
        return [];
    const detectors = output.results?.detectors;
    if (!Array.isArray(detectors))
        return [];
    return detectors.map((d) => {
        const elements = Array.isArray(d.elements) ? d.elements : [];
        const files = new Set();
        for (const el of elements) {
            if (el.source_mapping?.filename_relative) {
                files.add(el.source_mapping.filename_relative);
            }
        }
        const firstLines = elements[0]?.source_mapping?.lines ?? [];
        const lineRange = firstLines.length > 0
            ? { start: Math.min(...firstLines), end: Math.max(...firstLines) }
            : { start: 0, end: 0 };
        return {
            title: d.check ?? "unknown-detector",
            severity: mapSeverity(d.impact),
            confidence: mapConfidence(d.confidence),
            source: "slither",
            affected_files: [...files],
            affected_lines: lineRange,
            description: d.description ?? "",
            detector_id: d.check,
        };
    });
}
export async function executeSlither(rootDir) {
    const validation = validatePath(rootDir);
    if (!validation.valid)
        return { success: false, findings: [], error: validation.error };
    const { tempDir, tempFile } = createSecureTempFile("slither-");
    try {
        await new Promise((resolve, reject) => {
            execFile("uvx", ["slither-analyzer", ".", "--json", tempFile], { cwd: validation.resolvedPath, timeout: SLITHER_TIMEOUT_MS }, (error, _stdout, stderr) => {
                if (error) {
                    const e = error;
                    if (e.code === "ENOENT") {
                        reject(new Error("ERROR: TOOL_NOT_FOUND - uvx not found - install with: brew install uv"));
                        return;
                    }
                    if (error.killed || e.code === "ETIMEDOUT") {
                        reject(new Error("ERROR: EXECUTION_TIMEOUT - Slither timed out after 5 minutes"));
                        return;
                    }
                    if (!fs.existsSync(tempFile)) {
                        if (isCompilationError(stderr)) {
                            reject(new Error(`ERROR: COMPILATION_FAILED - ${stderr}`));
                            return;
                        }
                        reject(new Error(`ERROR: EXECUTION_FAILED - ${stderr || error.message}`));
                        return;
                    }
                }
                resolve();
            });
        });
        const content = fs.readFileSync(tempFile, "utf-8");
        const output = JSON.parse(content);
        if (!output || typeof output !== "object" || output.success === false) {
            return {
                success: false,
                findings: [],
                error: "Slither reported analysis failure",
            };
        }
        return { success: true, findings: parseOutput(output) };
    }
    catch (error) {
        return {
            success: false,
            findings: [],
            error: error instanceof Error ? error.message : String(error),
        };
    }
    finally {
        cleanupTempDir(tempDir);
    }
}
//# sourceMappingURL=run-slither.js.map