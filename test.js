require('dotenv').config();
const { GoogleGenAI } = require('@google/genai');

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

async function listModels() {
  const models = await ai.models.list();
  console.log("TUMHARI KEY PE YE MODELS AVAILABLE HAIN:");
  for (const model of models) {
    console.log(model.name, "-", model.supportedActions);
  }
}
listModels();