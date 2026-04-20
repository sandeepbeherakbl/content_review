import express from "express";
import {
    createSubContent,
    getSubContentByParent,
} from "../controller/subContentController.js";

import { authenticate, authorize } from "../middleware/authMiddleware.js";

const router = express.Router();

/**
 * @swagger
 * /api/sub-content:
 *   post:
 *     summary: Create sub-content
 *     tags: [Sub-Content]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               parentId:
 *                 type: string
 *               title:
 *                 type: string
 *               body:
 *                 type: string
 *     responses:
 *       201:
 *         description: Sub-content created
 */
router.post("/", authenticate, createSubContent);

/**
 * @swagger
 * /api/sub-content/{parentId}:
 *   get:
 *     summary: Get sub-content by parent
 *     tags: [Sub-Content]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: parentId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Success
 */
router.get("/:parentId", authenticate, getSubContentByParent);

export default router;