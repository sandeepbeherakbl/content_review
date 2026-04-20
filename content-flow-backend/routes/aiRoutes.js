import express from "express";
import {
    generateContentStream,
} from "../controller/aiController.js";

const router = express.Router();

/**
 * @swagger
 * /api/ai/generate-stream:
 *   post:
 *     summary: Generate content using AI (streaming)
 *     tags: [AI]
 *     description: Generates content based on a topic using AI in a streaming fashion.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               topic:
 *                 type: string
 *     responses:
 *       200:
 *         description: Content generation stream
 *         content:
 *           text/event-stream:
 *             schema:
 *               type: string
 *               example: "data: Some content\n\n"
 *       400:
 *         description: Invalid request
 */

router.post("/generate-stream", generateContentStream);

export default router;