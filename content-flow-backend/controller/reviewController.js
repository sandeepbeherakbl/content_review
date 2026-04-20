import pool from "../config/db.js";

export const approveContent = async (req, res) => {
    try {
        const { contentId } = req.params;
        const userId = req.user.id;
        const role = req.user.role;

        const [rows] = await pool.query(
            "SELECT * FROM content WHERE id = ?",
            [contentId]
        );

        const content = rows[0];

        if (!content) {
            return res.status(404).json({ message: "Content not found" });
        }

        if (content.status !== "pending_review") {
            return res.status(400).json({ message: "Content not in review stage" });
        }

        if (content.current_stage === 1 && role !== "reviewer_l1") {
            return res.status(403).json({ message: "Only L1 reviewer can approve" });
        }

        if (content.current_stage === 2 && role !== "reviewer_l2") {
            return res.status(403).json({ message: "Only L2 reviewer can approve" });
        }

        let newStatus = content.status;
        let newStage = content.current_stage;

        if (content.current_stage === 1) {
            newStage = 2;
        } else if (content.current_stage === 2) {
            newStatus = "approved";
        }

        const stageMapping = {
            1: "a1000000-0000-0000-0000-000000000001",
            2: "a1000000-0000-0000-0000-000000000002",
        };

        await pool.query(
            `INSERT INTO review_actions 
       (id, content_id, reviewer_id, stage_id, decision, content_version, acted_at)
       VALUES (?, ?, ?, ?, 'approved', ?, NOW())`,
            [
                "r" + Date.now(),
                contentId,
                userId,
                stageMapping[content.current_stage],
                content.version,
            ]
        );

        await pool.query(
            `UPDATE content 
       SET status = ?, current_stage = ?, updated_at = NOW()
       WHERE id = ?`,
            [newStatus, newStage, contentId]
        );

        res.json({ message: "Content approved" });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};


export const rejectContent = async (req, res) => {
    try {
        const { contentId } = req.params;
        const { comment } = req.body;
        const userId = req.user.id;
        const role = req.user.role;

        const [rows] = await pool.query(
            "SELECT * FROM content WHERE id = ?",
            [contentId]
        );

        const content = rows[0];

        if (!content) {
            return res.status(404).json({ message: "Content not found" });
        }

        if (content.status !== "pending_review") {
            return res.status(400).json({ message: "Content not in review stage" });
        }

        if (
            (content.current_stage === 1 && role !== "reviewer_l1") ||
            (content.current_stage === 2 && role !== "reviewer_l2")
        ) {
            return res.status(403).json({ message: "Not authorized" });
        }

        const stageMapping = {
            1: "a1000000-0000-0000-0000-000000000001",
            2: "a1000000-0000-0000-0000-000000000002",
        };

        await pool.query(
            `INSERT INTO review_actions 
       (id, content_id, reviewer_id, stage_id, decision, comment, content_version, acted_at)
       VALUES (?, ?, ?, ?, 'rejected', ?, ?, NOW())`,
            [
                "r" + Date.now(),
                contentId,
                userId,
                stageMapping[content.current_stage],
                comment,
                content.version,
            ]
        );

        await pool.query(
            `UPDATE content 
       SET status = 'rejected', current_stage = 1, version = version + 1, updated_at = NOW()
       WHERE id = ?`,
            [contentId]
        );

        res.json({ message: "Content rejected and sent for edit" });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};


export const getReviewHistory = async (req, res) => {
    try {
        const { contentId } = req.params;

        const [rows] = await pool.query(
            `SELECT r.*, u.name as reviewer_name 
       FROM review_actions r
       JOIN users u ON r.reviewer_id = u.id
       WHERE r.content_id = ?
       ORDER BY r.acted_at ASC`,
            [contentId]
        );

        res.json(rows);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

