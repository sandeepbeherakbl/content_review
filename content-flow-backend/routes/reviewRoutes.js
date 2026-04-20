import express from "express";
import {
    approveContent,
    rejectContent,
    getReviewHistory,
} from "../controller/reviewController.js";

import { authenticate, authorize } from "../middleware/authMiddleware.js";

const router = express.Router();

/**
 * @swagger
 * /api/review/{contentId}/approve:
 *   post:
 *     summary: Approve content
 *     tags: [Review]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: contentId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Content approved
 */
router.post("/:contentId/approve", authenticate, authorize("reviewer_l1", "reviewer_l2"), approveContent);

/**
 * @swagger
 * /api/review/{contentId}/reject:
 *   post:
 *     summary: Reject content
 *     tags: [Review]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: contentId
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
 *               comment:
 *                 type: string
 *     responses:
 *       200:
 *         description: Content rejected
 */
router.post("/:contentId/reject", authenticate, authorize("reviewer_l1", "reviewer_l2"), rejectContent);

/**
 * @swagger
 * /api/review/{contentId}/history:
 *   get:
 *     summary: Get review history
 *     tags: [Review]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: contentId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Success
 */
router.get("/:contentId/history", authenticate, getReviewHistory);

export default router;