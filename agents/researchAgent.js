require("dotenv").config();
const { GoogleGenAI } = require("@google/genai");

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
const GEMINI_MODEL = "gemini-3.6-flash";

async function researchClaims(claims) {
  console.log("");
  console.log("========================================");
  console.log("🌐 AGENT 2 — RESEARCH STARTED");
  console.log("========================================");

  const evidence = [];

  for (const claim of claims) {
    try {
      console.log(`🔎 Checking: "${claim}"`);
      
      const prompt = `You are a fact checker.
      
Claim: "${claim}"

Is this TRUE or FALSE? Give 1 short sentence reason.
Reply ONLY in JSON:
{"isTrue": true, "reason": "your reason here"}`;

      const result = await ai.models.generateContent({
        model: GEMINI_MODEL,
        contents: prompt,
      });

      let text = result.text.trim();
      text = text.replace(/```json|```/g, "").trim();
      const data = JSON.parse(text);
      
      evidence.push({
        claim: claim,
        finding: data.reason,
        sourceTitle: "Gemini AI",
        sourceUrl: "",
        sourceType: "AI",
        supportsClaim: data.isTrue === true
      });

      console.log(`✅ Result: ${data.isTrue ? "TRUE" : "FALSE"}`);

    } catch (error) {
      console.error(`❌ Agent 2 Error: ${error.message}`);
      // اگر Gemini فیل بھی ہو جائے تب بھی خالی نہیں بھیجیں گے
      evidence.push({
        claim: claim,
        finding: "Could not verify automatically. Marked as uncertain.",
        sourceTitle: "System",
        sourceUrl: "",
        sourceType: "AI",
        supportsClaim: false
      });
    }
  }

  console.log("📚 Total Evidence Created:", evidence.length);
  console.log("========================================");

  return {
    evidence: evidence,
    sources: [],
    researchSummary: `Verified ${evidence.length} claim(s)`
  };
}

module.exports = { researchClaims };