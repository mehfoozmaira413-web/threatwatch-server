const { GoogleGenAI } = require("@google/genai");

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

const GEMINI_MODEL = "gemini-3.6-flash";

// =====================================================
// CLEAN JSON
// =====================================================

function cleanJSON(text) {
  if (!text) {
    throw new Error(
      "Report Generation Agent returned an empty response."
    );
  }

  let cleaned = String(text)
    .trim()
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch (error) {
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");

    if (
      start !== -1 &&
      end !== -1 &&
      end > start
    ) {
      try {
        return JSON.parse(
          cleaned.substring(
            start,
            end + 1
          )
        );
      } catch (jsonError) {
        throw new Error(
          "Report Generation Agent returned invalid JSON."
        );
      }
    }

    throw new Error(
      "Report Generation Agent returned invalid JSON."
    );
  }
}

// =====================================================
// NORMALIZE EVIDENCE
// =====================================================

function normalizeEvidence(
  evidence
) {
  if (!Array.isArray(evidence)) {
    return [];
  }

  return evidence
    .filter(
      (item) =>
        item &&
        typeof item === "object"
    )
    .map((item) => ({
      claim: String(
        item.claim || ""
      ),

      finding: String(
        item.finding || ""
      ),

      sourceTitle: String(
        item.sourceTitle || ""
      ),

      sourceUrl: String(
        item.sourceUrl || ""
      ),

      sourceType: String(
        item.sourceType || "WEB"
      ),

      supportsClaim:
        Boolean(
          item.supportsClaim
        ),
    }));
}

// =====================================================
// NORMALIZE SOURCES
// =====================================================

function normalizeSources(
  sources
) {
  if (!Array.isArray(sources)) {
    return [];
  }

  return sources
    .filter(
      (source) =>
        source &&
        typeof source === "object"
    )
    .map((source) => ({
      title: String(
        source.title || ""
      ),

      url: String(
        source.url || ""
      ),

      publisher: String(
        source.publisher || ""
      ),

      publishedAt: String(
        source.publishedAt || ""
      ),
    }))
    .filter(
      (source) => source.url
    );
}

// =====================================================
// AGENT 4 — REPORT GENERATION
// =====================================================

async function generateReport({
  claims = [],
  evidence = [],
  sources = [],
  analysis = {},
}) {
  console.log("");
  console.log(
    "========================================"
  );
  console.log(
    "📄 AGENT 4 — REPORT GENERATION"
  );
  console.log(
    "========================================"
  );

  const prompt = `
You are Agent 4 of ThreatWatch AI.

ROLE:
Verification Report Generation Agent.

Create the final verification report using
ONLY the information supplied by Agents 1, 2
and 3.

CLAIMS:
${JSON.stringify(
  claims,
  null,
  2
)}

EVIDENCE:
${JSON.stringify(
  evidence,
  null,
  2
)}

SOURCES:
${JSON.stringify(
  sources,
  null,
  2
)}

ANALYSIS:
${JSON.stringify(
  analysis,
  null,
  2
)}

RULES:

1. Do not invent facts.
2. Do not invent evidence.
3. Do not invent URLs.
4. Do not invent sources.
5. Do not perform additional web research.
6. Keep the report clear and understandable.
7. Mention uncertainty when evidence is insufficient.
8. Base the final report on the supplied analysis.
9. Return ONLY valid JSON.

Return exactly:

{
  "summary": "",
  "report": "",
  "evidence": [],
  "sources": []
}

The evidence and sources arrays should preserve
the supplied evidence and sources where appropriate.
Do not create new sources.
`;

  try {
    const result =
      await ai.models.generateContent({
        model: GEMINI_MODEL,
        contents: prompt,
        config: {
          responseMimeType:
            "application/json",
        },
      });

    const data =
      cleanJSON(result.text);

    const finalEvidence =
      Array.isArray(data.evidence) &&
      data.evidence.length > 0
        ? normalizeEvidence(
            data.evidence
          )
        : normalizeEvidence(
            evidence
          );

    const finalSources =
      Array.isArray(data.sources) &&
      data.sources.length > 0
        ? normalizeSources(
            data.sources
          )
        : normalizeSources(
            sources
          );

    const summary =
      typeof data.summary ===
      "string" &&
      data.summary.trim()
        ? data.summary.trim()
        : "Verification completed.";

    const report =
      typeof data.report ===
      "string" &&
      data.report.trim()
        ? data.report.trim()
        : analysis.analysis ||
          "No detailed report was generated.";

    console.log(
      "✅ Final report generated."
    );

    return {
      summary,
      report,
      evidence: finalEvidence,
      sources: finalSources,
    };
  } catch (error) {
    console.error(
      "❌ REPORT GENERATION ERROR:",
      error.message
    );

    throw new Error(
      `Report Generation Agent failed: ${error.message}`
    );
  }
}

module.exports = {
  generateReport,
};