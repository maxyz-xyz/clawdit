#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
// ── Config ──────────────────────────────────────────────────────────────────
const API_BASE = "https://solodit.cyfrin.io/api/v1/solodit";
const SOLODIT_BASE = "https://solodit.cyfrin.io";
const API_KEY = process.env.SOLODIT_API_KEY;
function ensureApiKey() {
    if (!API_KEY) {
        throw new Error("SOLODIT_API_KEY not set. Get your key at: https://solodit.cyfrin.io → Profile → API Keys, then export SOLODIT_API_KEY=sk_your_key");
    }
}
// ── Rate Limiter ────────────────────────────────────────────────────────────
class RateLimiter {
    remaining = 20;
    resetAt = 0;
    update(headers) {
        const rem = headers.get("x-ratelimit-remaining");
        const reset = headers.get("x-ratelimit-reset");
        if (rem !== null)
            this.remaining = parseInt(rem, 10);
        if (reset !== null)
            this.resetAt = parseInt(reset, 10) * 1000;
    }
    async waitIfNeeded() {
        if (this.remaining <= 1 && this.resetAt > Date.now()) {
            const waitMs = this.resetAt - Date.now() + 500;
            await new Promise((r) => setTimeout(r, waitMs));
        }
    }
    status() {
        return { remaining: this.remaining, resetAt: this.resetAt };
    }
}
const rateLimiter = new RateLimiter();
class SimpleCache {
    store = new Map();
    get(key) {
        const entry = this.store.get(key);
        if (!entry)
            return undefined;
        if (Date.now() > entry.expiresAt) {
            this.store.delete(key);
            return undefined;
        }
        return entry.data;
    }
    set(key, data, ttlMs) {
        this.store.set(key, { data, expiresAt: Date.now() + ttlMs });
    }
}
const cache = new SimpleCache();
const SEARCH_CACHE_TTL = 5 * 60 * 1000;
const findingsById = new Map();
function indexFindings(findings) {
    for (const f of findings) {
        findingsById.set(f.id, f);
    }
}
// ── API Client ──────────────────────────────────────────────────────────────
async function callSoloditAPI(body) {
    await rateLimiter.waitIfNeeded();
    const res = await fetch(`${API_BASE}/findings`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-Cyfrin-API-Key": API_KEY,
        },
        body: JSON.stringify(body),
    });
    rateLimiter.update(res.headers);
    if (!res.ok) {
        const errBody = await res.text();
        if (res.status === 401) {
            throw new Error(`Invalid API key. Get a new one at: https://solodit.cyfrin.io → Profile → API Keys`);
        }
        if (res.status === 429) {
            throw new Error(`Rate limited. Limit resets at ${new Date(rateLimiter.status().resetAt).toISOString()}. Try again shortly.`);
        }
        throw new Error(`Solodit API error (${res.status}): ${errBody.slice(0, 200)}`);
    }
    return (await res.json());
}
// ── Formatters ──────────────────────────────────────────────────────────────
function findingUrl(slug) {
    return `${SOLODIT_BASE}/issues/${slug}`;
}
function formatFindingSummary(f) {
    const tags = f.issues_issuetagscore.map((t) => t.tags_tag.title).join(", ");
    const finders = f.issues_issue_finders
        .map((fi) => fi.wardens_warden.handle)
        .join(", ");
    const url = findingUrl(f.slug);
    let out = `### #${f.id} [${f.impact}] ${f.title}\n`;
    out += `${url}\n`;
    out += `**Firm:** ${f.firm_name || "Unknown"} | **Protocol:** ${f.protocol_name || "Unknown"} | **Quality:** ${f.quality_score}/5 | **Rarity:** ${f.general_score}/5\n`;
    if (tags)
        out += `**Tags:** ${tags}\n`;
    if (finders)
        out += `**Finders:** ${finders} (${f.finders_count} total)\n`;
    if (f.report_date)
        out += `**Date:** ${f.report_date}\n`;
    if (f.content) {
        if (f.content.length <= 500) {
            out += `\n${f.content.trim()}\n`;
        }
        else {
            const chunk = f.content.slice(0, 500);
            const paraBreak = chunk.lastIndexOf("\n\n");
            const lineBreak = chunk.lastIndexOf("\n");
            const breakAt = paraBreak > 100 ? paraBreak : lineBreak > 100 ? lineBreak : 500;
            out += `\n${f.content.slice(0, breakAt).trim()}...\n`;
        }
    }
    return out;
}
function formatFindingFull(f) {
    const tags = f.issues_issuetagscore.map((t) => t.tags_tag.title).join(", ");
    const finders = f.issues_issue_finders
        .map((fi) => fi.wardens_warden.handle)
        .join(", ");
    let categories = "";
    if (f.protocols_protocol?.protocols_protocolcategoryscore?.length) {
        categories = f.protocols_protocol.protocols_protocolcategoryscore
            .map((c) => c.protocols_protocolcategory.title)
            .join(", ");
    }
    const url = findingUrl(f.slug);
    let out = `# [${f.impact}] ${f.title}\n${url}\n\n`;
    out += `| Field | Value |\n|-------|-------|\n`;
    out += `| Severity | ${f.impact} |\n`;
    out += `| Firm | ${f.firm_name || "Unknown"} |\n`;
    out += `| Protocol | ${f.protocol_name || "Unknown"} |\n`;
    if (categories)
        out += `| Categories | ${categories} |\n`;
    out += `| Quality | ${f.quality_score}/5 |\n`;
    out += `| Rarity | ${f.general_score}/5 |\n`;
    if (tags)
        out += `| Tags | ${tags} |\n`;
    if (finders)
        out += `| Finders | ${finders} (${f.finders_count}) |\n`;
    if (f.report_date)
        out += `| Date | ${f.report_date} |\n`;
    if (f.contest_prize_txt)
        out += `| Prize Pool | ${f.contest_prize_txt} |\n`;
    if (f.sponsor_name)
        out += `| Sponsor | ${f.sponsor_name} |\n`;
    out += `| Solodit | ${url} |\n`;
    if (f.github_link)
        out += `| GitHub | ${f.github_link} |\n`;
    out += `\n---\n\n`;
    out += f.content || "(no content)";
    return out;
}
// ── MCP Server ──────────────────────────────────────────────────────────────
const server = new McpServer({
    name: "solodit",
    version: "0.1.0",
});
server.tool("search_findings", "Search Solodit's 20k+ smart contract security findings from real audits. Returns severity, firm, protocol, tags, quality score, content snippet, and Solodit URL.", {
    keywords: z
        .string()
        .optional()
        .describe("Text search in title and content"),
    severity: z
        .array(z.string())
        .optional()
        .describe('Filter by severity: "HIGH", "MEDIUM", "LOW", "GAS"'),
    firms: z
        .array(z.string())
        .optional()
        .describe('Audit firm names (e.g., ["Sherlock", "Code4rena"])'),
    tags: z
        .array(z.string())
        .optional()
        .describe('Vulnerability tags (e.g., ["Reentrancy", "Oracle"])'),
    language: z
        .string()
        .optional()
        .describe('Programming language (e.g., "Solidity")'),
    protocol: z
        .string()
        .optional()
        .describe("Protocol name (partial match)"),
    reported: z
        .enum(["30", "60", "90", "alltime"])
        .optional()
        .describe("Time period filter"),
    sort_by: z
        .enum(["Recency", "Quality", "Rarity"])
        .optional()
        .describe("Sort order (default: Recency)"),
    sort_direction: z
        .enum(["Desc", "Asc"])
        .optional()
        .describe("Sort direction (default: Desc)"),
    page: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe("Page number (default 1)"),
    page_size: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .describe("Results per page (default 10, max 100)"),
    advanced_filters: z
        .object({
        quality_score: z.number().min(0).max(5).optional(),
        rarity_score: z.number().min(0).max(5).optional(),
        user: z.string().optional(),
        min_finders: z.number().int().optional(),
        max_finders: z.number().int().optional(),
        reported_after: z.string().optional(),
        protocol_category: z.array(z.string()).optional(),
        forked: z.array(z.string()).optional(),
    })
        .optional()
        .describe("Advanced filters"),
}, async (params) => {
    ensureApiKey();
    const page = params.page ?? 1;
    const pageSize = params.page_size ?? 10;
    const filters = {};
    if (params.keywords)
        filters.keywords = params.keywords;
    if (params.severity)
        filters.impact = params.severity.map((s) => s.toUpperCase());
    if (params.firms)
        filters.firms = params.firms.map((v) => ({ value: v }));
    if (params.tags)
        filters.tags = params.tags.map((v) => ({ value: v }));
    if (params.language)
        filters.languages = [{ value: params.language }];
    if (params.protocol)
        filters.protocol = params.protocol;
    if (params.reported)
        filters.reported = { value: params.reported };
    if (params.sort_by) {
        filters.sortField = params.sort_by;
        filters.sortDirection = params.sort_direction ?? "Desc";
    }
    const adv = params.advanced_filters;
    if (adv) {
        if (adv.quality_score !== undefined)
            filters.qualityScore = adv.quality_score;
        if (adv.rarity_score !== undefined)
            filters.rarityScore = adv.rarity_score;
        if (adv.user)
            filters.user = adv.user;
        if (adv.min_finders !== undefined)
            filters.minFinders = String(adv.min_finders);
        if (adv.max_finders !== undefined)
            filters.maxFinders = String(adv.max_finders);
        if (adv.reported_after) {
            filters.reported = { value: "after" };
            filters.reportedAfter = adv.reported_after;
        }
        if (adv.protocol_category)
            filters.protocolCategory = adv.protocol_category.map((v) => ({
                value: v,
            }));
        if (adv.forked)
            filters.forked = adv.forked.map((v) => ({ value: v }));
    }
    const body = { page, pageSize, filters };
    const cacheKey = JSON.stringify(body);
    const cached = cache.get(cacheKey);
    let data;
    if (cached) {
        data = cached;
    }
    else {
        data = await callSoloditAPI(body);
        cache.set(cacheKey, data, SEARCH_CACHE_TTL);
        indexFindings(data.findings);
    }
    const { metadata, rateLimit } = data;
    let output = `**${metadata.totalResults} findings found** (page ${metadata.currentPage}/${metadata.totalPages}, ${pageSize}/page)\n`;
    if (rateLimit.remaining <= 5) {
        output += `**Warning:** Rate limit low — ${rateLimit.remaining}/${rateLimit.limit} remaining\n`;
    }
    output += `\n---\n\n`;
    if (data.findings.length === 0) {
        output += "No findings match your query. Try broadening your filters.";
    }
    else {
        for (const f of data.findings) {
            output += formatFindingSummary(f) + "\n---\n\n";
        }
    }
    return { content: [{ type: "text", text: output }] };
});
server.tool("get_finding", "Get full details for a specific Solodit finding by numeric ID, URL, or slug.", {
    identifier: z
        .string()
        .describe("Finding numeric ID, Solodit URL, or finding slug"),
}, async (params) => {
    ensureApiKey();
    let slug = params.identifier;
    const numericId = slug.replace(/^#/, "").trim();
    if (/^\d+$/.test(numericId)) {
        const cached = findingsById.get(numericId);
        if (cached) {
            return {
                content: [{ type: "text", text: formatFindingFull(cached) }],
            };
        }
    }
    if (slug.includes("solodit.cyfrin.io/issues/")) {
        const match = slug.match(/\/issues\/([^/?#]+)/);
        if (match)
            slug = match[1];
    }
    const words = slug.replace(/-/g, " ").trim().split(/\s+/);
    const keywords = words.slice(0, 8).join(" ");
    const data = await callSoloditAPI({
        page: 1,
        pageSize: 20,
        filters: { keywords },
    });
    indexFindings(data.findings);
    let finding = data.findings.find((f) => f.slug === slug || f.id === numericId);
    let inexactMatch = false;
    if (!finding) {
        const shortKeywords = words.slice(0, 5).join(" ");
        const retry = await callSoloditAPI({
            page: 1,
            pageSize: 20,
            filters: { keywords: shortKeywords },
        });
        indexFindings(retry.findings);
        finding = retry.findings.find((f) => f.slug === slug || f.id === numericId);
        if (!finding && retry.findings.length > 0) {
            finding = retry.findings[0];
            inexactMatch = true;
        }
    }
    if (!finding && data.findings.length > 0) {
        finding = data.findings[0];
        inexactMatch = true;
    }
    if (!finding) {
        return {
            content: [
                {
                    type: "text",
                    text: `Finding not found for: ${params.identifier}\n\nTry using search_findings with keywords instead.`,
                },
            ],
        };
    }
    let output = "";
    if (inexactMatch) {
        output += `> **Note:** Exact match not found for "${slug}". Showing closest result.\n\n`;
    }
    output += formatFindingFull(finding);
    return { content: [{ type: "text", text: output }] };
});
server.tool("get_filter_options", "List available filter values for Solodit search (firms, tags, categories, languages).", {}, async () => {
    const output = `# Solodit Filter Options

## Severity Levels
HIGH, MEDIUM, LOW, GAS

## Top Audit Firms
Code4rena, Sherlock, Cantina, Pashov Audit Group, OpenZeppelin, Halborn, Quantstamp, MixBytes, OtterSec, Spearbit, TrailOfBits, Cyfrin

## Top Vulnerability Tags
Business Logic, Validation, Wrong Math, Front-Running, DOS, Fee On Transfer, Oracle, Reentrancy, Access Control, Decimals, Liquidation, Overflow/Underflow, Slippage, Rounding, Stale Price, ERC4626, Flash Loan, Weird ERC20, Chainlink

## Protocol Categories
Dexes, CDP, Services, Cross Chain, Yield, Liquid Staking, Synthetics, Staking Pool, Bridge, Launchpad, RWA, Lending, Insurance, NFT Marketplace, Gaming

## Sort Options
Recency (default), Quality, Rarity`;
    return { content: [{ type: "text", text: output }] };
});
// ── Start ───────────────────────────────────────────────────────────────────
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
}
main().catch((err) => {
    console.error("Fatal:", err);
    process.exit(1);
});
//# sourceMappingURL=index.js.map