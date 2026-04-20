import express from "express";
import {
    createContent,
    getAllContent,
    getContentById,
    updateContent,
    submitContent,
} from "../controller/contentController.js";

import { authenticate, authorize } from "../middleware/authMiddleware.js";

const router = express.Router();

/**
 * @swagger
 * /api/content:
 *   post:
 *     summary: Create content
 *     tags: [Content]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title: { type: string }
 *               body: { type: string }
 *     responses:
 *       201:
 *         description: Content created
 */

router.post("/", authenticate, authorize("creator", "admin"), createContent);

/**
 * @swagger
 * /api/content:
 *   get:
 *     summary: Get all content
 *     tags: [Content]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Success
 */
router.get("/", authenticate, getAllContent);

/**
 * @swagger
 * /api/content/{id}:
 *   get:
 *     summary: Get content by ID
 *     tags: [Content]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Success
 */
router.get("/:id", authenticate, getContentById);

/**
 * @swagger
 * /api/content/{id}:
 *   put:
 *     summary: Update content
 *     tags: [Content]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title: { type: string }
 *               body: { type: string }
 *     responses:
 *       200:
 *         description: Content updated
 */
router.put("/:id", authenticate, authorize("creator", "admin"), updateContent);

/**
 * @swagger
 * /api/content/{id}/submit:
 *   post:
 *     summary: Submit content for review
 *     tags: [Content]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Content submitted for review
 */
router.post("/:id/submit", authenticate, authorize("creator", "admin"), submitContent);

export default router;