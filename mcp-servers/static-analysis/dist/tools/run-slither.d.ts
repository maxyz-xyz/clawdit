export interface SlitherFinding {
    title: string;
    severity: string;
    confidence: string;
    source: "slither";
    affected_files: string[];
    affected_lines: {
        start: number;
        end: number;
    };
    description: string;
    detector_id?: string;
}
export interface SlitherResult {
    success: boolean;
    findings: SlitherFinding[];
    error?: string;
}
export declare function executeSlither(rootDir: string): Promise<SlitherResult>;
