require("dotenv").config();

const { GoogleGenAI } = require("@google/genai");

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

// Quota-efficient model for Agent 1
const GEMINI_MODEL = "gemini-3.1-flash-lite";

// =====================================================
// CLEAN JSON
// =====================================================

function cleanJSON(text) {
  if (!text) {
    throw new Error(
      "Claim Extraction Agent returned an empty response."
    );
  }

  let cleaned = String(text)
    .trim()
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();

  // First attempt
  try {
    return JSON.parse(cleaned);
  } catch (error) {
    // Try extracting JSON object
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");

    if (start !== -1 && end !== -1 && end > start) {
      const jsonPart = cleaned.substring(start, end + 1);

      try {
        return JSON.parse(jsonPart);
      } catch (jsonError) {
        throw new Error(
          "Claim Extraction Agent returned invalid JSON."
        );
      }
    }

    throw new Error(
      "Claim Extraction Agent returned invalid JSON."
    );
  }
}

// =====================================================
// NORMALIZE CLAIMS
// =====================================================

function normalizeClaims(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .filter(
      (claim) =>
        claim !== null &&
        claim !== undefined
    )
    .map((claim) => String(claim).trim())
    .filter(Boolean);
}

// =====================================================
// AGENT 1 — CLAIM EXTRACTION
// =====================================================

async function extractClaims(content) {
  if (
    content === null ||
    content === undefined ||
    !String(content).trim()
  ) {
    return {
      claims: [],
      summary: "No content was provided.",
    };
  }

  const cleanContent = String(content).trim();

  console.log("");
  console.log(
    "========================================"
  );
  console.log(
    "🤖 AGENT 1 — CLAIM EXTRACTION"
  );
  console.log(
    "========================================"
  );

  const prompt = `
You are Agent 1 of ThreatWatch AI.

ROLE:
Claim Extraction Agent.

TASK:
Extract factual or potentially verifiable claims
from the submitted content.

IMPORTANT:
- Only extract claims actually present in the content.
- Do NOT verify the claims.
- Do NOT decide whether claims are true or false.
- Do NOT invent information.
- Do NOT add outside information.
- Ignore greetings.
- Ignore questions.
- Ignore personal opinions.
- Ignore vague statements.
- Keep claims short and clear.
- A claim should be something that could potentially
  be checked against reliable evidence.

CONTENT:
"""
${cleanContent}
"""

Return ONLY valid JSON.

Use exactly this structure:

{
  "claims": [
    "claim 1",
    "claim 2"
  ],
  "summary": "Brief description of extracted claims."
}

If there are no factual or verifiable claims, return:

{
  "claims": [],
  "summary": "No clearly verifiable factual claims were found."
}
`;

  try {
    console.log(
      `Model: ${GEMINI_MODEL}`
    );

    const result =
      await ai.models.generateContent({
        model: GEMINI_MODEL,
        contents: prompt,
        config: {
          responseMimeType:
            "application/json",
        },
      });

    const data = cleanJSON(result.text);

    const claims = normalizeClaims(
      data.claims
    );

    const summary =
      typeof data.summary === "string"
        ? data.summary.trim()
        : "";

    console.log(
      "✅ Agent 1 completed."
    );

    console.log(
      "📌 Claims found:",
      claims.length
    );

    return {
      claims,
      summary:
        summary ||
        (
          claims.length > 0
            ? "Factual claims extracted successfully."
            : "No clearly verifiable factual claims were found."
        ),
    };
  } catch (error) {
    console.error(
      "❌ Claim Extraction Agent Error:",
      error.message
    );

    // Handle Gemini quota error clearly
    if (
      error.message &&
      (
        error.message.includes("429") ||
        error.message.includes("RESOURCE_EXHAUSTED") ||
        error.message.toLowerCase().includes("quota")
      )
    ) {
      throw new Error(
        "Gemini API quota exceeded for Claim Extraction Agent. Please wait for the quota reset or use another available Gemini API project/key."
      );
    }

    throw new Error(
      `Claim Extraction Agent failed: ${error.message}`
    );
  }
}

// =====================================================
// EXPORT
// =====================================================

module.exports = {
  extractClaims,
};