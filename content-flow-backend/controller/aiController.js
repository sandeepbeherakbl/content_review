import Groq from "groq-sdk";

const client = new Groq({
    apiKey: process.env.GROQ_API_KEY,
});

export const generateContentStream = async (req, res) => {
    try {
        const { topic } = req.method === 'POST' ? req.body : req.query;

        if (!topic) {
            return res.status(400).json({ message: "Topic is required" });
        }

        const completion = await client.chat.completions.create({
            model: "llama-3.1-8b-instant",
            messages: [
                {
                    role: "system",
                    content: "You are a professional content writer. Always ensure your response is a complete piece of writing with a proper conclusion. Never cut off mid-sentence.",
                },
                {
                    role: "user",
                    content: `Write a clear and engaging article about "${topic}" in approximately 200-300 words. Make sure to complete all thoughts and sentences within this limit.`,
                },
            ],
            temperature: 0.7,
            max_tokens: 1024,
            stream: false,
        });

        const text = completion.choices[0]?.message?.content || "";
        res.status(200).json({ text });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};