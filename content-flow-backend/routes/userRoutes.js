import express from "express";
import { getAllUsers } from "../controller/userController.js";
import { authenticate } from "../middleware/authMiddleware.js";

const router = express.Router();

/**
 * @swagger
 * /api/users:
 *   get:
 *     summary: Get all users
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Success
 */
router.get("/", authenticate, getAllUsers);

export default router;