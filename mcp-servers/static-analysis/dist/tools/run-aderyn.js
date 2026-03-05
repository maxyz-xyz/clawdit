import { execFile } from "node:child_process";
import * as fs from "node:fs";
import { cleanupTempDir, createSecureTempFile, validatePath } from "./utils.js";
const ADERYN_TIMEOUT_MS = 5 * 60 * 1000;
const COMPILATION_ERROR_KEYWORDS = [
    "compilation",
    "solc",
    "compiler",
    "compile",
    "syntax error",
];
function isCompilationError(stderr) {
    const lower = stderr.toLowerCase();
    return COMPILATION_ERROR_KEYWORDS.some((k) => lower.includes(k));
}
function issueToFinding(issue, severity) {
    const instances = Array.isArray(issue.instances) ? issue.instances : [];
    const files = new Set();
    for (const inst of instances) {
        if (inst.contract_path)
            files.add(inst.contract_path);
    }
    const lines = instances
        .map((i) => i.line_no)
        .filter((n) => typeof n === "number" && n > 0);
    const lineRange = lines.length > 0
        ? { start: Math.min(...lines), end: Math.max(...lines) }
        : { start: 0, end: 0 };
    return {
        title: issue.title ?? "unknown-issue",
        severity,
        confidence: "Confirmed",
        source: "aderyn",
        affected_files: [...files],
        affected_lines: lineRange,
        description: issue.description ?? "",
        detector_id: issue.detector_name,
    };
}
export async function executeAderyn(rootDir) {
    const validation = validatePath(rootDir);
    if (!validation.valid)
        return { success: false, findings: [], error: validation.error };
    const { tempDir, tempFile } = createSecureTempFile("aderyn-");
    try {
        await new Promise((resolve, reject) => {
            execFile("aderyn", [".", "-o", tempFile], { cwd: validation.resolvedPath, timeout: ADERYN_TIMEOUT_MS }, (error, _stdout, stderr) => {
                if (error) {
                    const e = error;
                    if (e.code === "ENOENT") {
                        reject(new Error("ERROR: TOOL_NOT_FOUND - Aderyn not found - install with: cargo install aderyn"));
                        return;
                    }
                    if (error.killed || e.code === "ETIMEDOUT") {
                        reject(new Error("ERROR: EXECUTION_TIMEOUT - Aderyn timed out after 5 minutes"));
                        return;
                    }
                    if (isCompilationError(stderr)) {
                        reject(new Error(`ERROR: COMPILATION_FAILED - ${stderr}`));
                        return;
                    }
                    if (!fs.existsSync(tempFile)) {
                        reject(new Error(`ERROR: EXECUTION_FAILED - ${stderr || error.message}`));
                        return;
                    }
                }
                resolve();
            });
        });
        const content = fs.readFileSync(tempFile, "utf-8");
        const output = JSON.parse(content);
        const findings = [];
        const highIssues = output.high_issues?.issues;
        if (Array.isArray(highIssues)) {
            for (const issue of highIssues) {
                findings.push(issueToFinding(issue, "HIGH"));
            }
        }
        const lowIssues = output.low_issues?.issues;
        if (Array.isArray(lowIssues)) {
            for (const issue of lowIssues) {
                findings.push(issueToFinding(issue, "LOW"));
            }
        }
        return { success: true, findings };
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
//# sourceMappingURL=run-aderyn.js.map