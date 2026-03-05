export interface AderynFinding {
    title: string;
    severity: string;
    confidence: string;
    source: "aderyn";
    affected_files: string[];
    affected_lines: {
        start: number;
        end: number;
    };
    description: string;
    detector_id?: string;
}
export interface AderynResult {
    success: boolean;
    findings: AderynFinding[];
    error?: string;
}
export declare function executeAderyn(rootDir: string): Promise<AderynResult>;
