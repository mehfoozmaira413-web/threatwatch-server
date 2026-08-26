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
      "Analysis Agent returned an empty response."
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
          "Analysis Agent returned invalid JSON."
        );
      }
    }

    throw new Error(
      "Analysis Agent returned invalid JSON."
    );
  }
}

// =====================================================
// AGENT 3 — ANALYSIS
// =====================================================

async function analyzeClaims(
  claims,
  evidence = []
) {
  if (
    !Array.isArray(claims) ||
    claims.length === 0
  ) {
    return {
      riskScore: 0,
      confidenceScore: 0,
      verdict: "UNCERTAIN",
      threats: [],
      analysis:
        "No claims were available for analysis.",
    };
  }

  console.log("");
  console.log(
    "========================================"
  );
  console.log(
    "⚖️ AGENT 3 — EVIDENCE ANALYSIS"
  );
  console.log(
    "========================================"
  );

  const prompt = `
You are Agent 3 of ThreatWatch AI.

ROLE:
Evidence Analysis Agent.

Your job is to compare factual claims against
the research evidence supplied by Agent 2.

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

RULES:

1. Use ONLY the supplied claims and evidence.
2. Do not invent evidence.
3. Do not invent sources.
4. Do not perform additional web research.
5. If evidence is insufficient, use UNCERTAIN.
6. Do not automatically mark a claim false
   merely because evidence is missing.
7. Explain the reasoning clearly.
8. Return ONLY valid JSON.

Allowed verdicts:

SAFE
THREAT
LIKELY_TRUE
LIKELY_FALSE
UNCERTAIN

Return exactly:

{
  "riskScore": 0,
  "confidenceScore": 0,
  "verdict": "UNCERTAIN",
  "threats": [],
  "analysis": ""
}

riskScore:
0-100

confidenceScore:
0-100
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

    const riskScore = Math.min(
      100,
      Math.max(
        0,
        Number(data.riskScore) || 0
      )
    );

    const confidenceScore =
      Math.min(
        100,
        Math.max(
          0,
          Number(
            data.confidenceScore
          ) || 0
        )
      );

    const allowedVerdicts = [
      "SAFE",
      "THREAT",
      "LIKELY_TRUE",
      "LIKELY_FALSE",
      "UNCERTAIN",
    ];

    const verdict =
      allowedVerdicts.includes(
        data.verdict
      )
        ? data.verdict
        : "UNCERTAIN";

    const threats =
      Array.isArray(data.threats)
        ? data.threats
            .filter(
              (item) =>
                item !== null &&
                item !== undefined
            )
            .map(String)
        : [];

    const analysis =
      typeof data.analysis ===
      "string"
        ? data.analysis
        : "";

    console.log(
      "✅ Analysis completed."
    );

    console.log(
      "Risk:",
      riskScore
    );

    console.log(
      "Confidence:",
      confidenceScore
    );

    console.log(
      "Verdict:",
      verdict
    );

    return {
      riskScore,
      confidenceScore,
      verdict,
      threats,
      analysis,
    };
  } catch (error) {
    console.error(
      "❌ ANALYSIS AGENT ERROR:",
      error.message
    );

    throw new Error(
      `Analysis Agent failed: ${error.message}`
    );
  }
}

module.exports = {
  analyzeClaims,
};