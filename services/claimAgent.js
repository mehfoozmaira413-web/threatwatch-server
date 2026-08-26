require("dotenv").config();

const { GoogleGenAI } = require("@google/genai");

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

const CLAIM_MODEL = "gemini-3.1-flash-lite";

function cleanJSON(text) {
  if (!text) {
    throw new Error("Claim Agent returned an empty response.");
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

    if (start !== -1 && end !== -1 && end > start) {
      try {
        return JSON.parse(
          cleaned.substring(start, end + 1)
        );
      } catch (jsonError) {
        throw new Error(
          "Claim Agent returned invalid JSON."
        );
      }
    }

    throw new Error(
      "Claim Agent returned invalid JSON."
    );
  }
}

async function extractClaims(text) {
  if (
    !text ||
    typeof text !== "string" ||
    !text.trim()
  ) {
    throw new Error(
      "Text is required for claim extraction."
    );
  }

  const prompt = `
You are Agent 1 — Claim Extraction Agent
of ThreatWatch AI.

Your job is ONLY to extract factual or
potentially verifiable claims.

CONTENT:
"""
${text.trim()}
"""

RULES:

1. Extract factual claims only.
2. Claims must be potentially verifiable.
3. Do not extract opinions.
4. Do not extract questions.
5. Do not extract greetings.
6. Do not decide whether a claim is true or false.
7. Do not invent information.
8. Keep claims short and clear.
9. Return an empty array if there are no factual claims.
10. Return ONLY valid JSON.

EXACT FORMAT:

{
  "claims": [
    "claim 1",
    "claim 2"
  ]
}
`;

  try {
    console.log(
      "🤖 Agent 1: Claim Extraction"
    );

    const result =
      await ai.models.generateContent({
        model: CLAIM_MODEL,
        contents: prompt,
        config: {
          responseMimeType: "application/json",
        },
      });

    const data =
      cleanJSON(result.text);

    const claims =
      Array.isArray(data.claims)
        ? data.claims
            .map((claim) =>
              String(claim).trim()
            )
            .filter(Boolean)
        : [];

    console.log(
      "✅ Agent 1 claims:",
      claims
    );

    return {
      claims,
    };
  } catch (error) {
    console.error(
      "❌ Claim Agent Error:",
      error.message
    );

    throw error;
  }
}

module.exports = {
  extractClaims,
};