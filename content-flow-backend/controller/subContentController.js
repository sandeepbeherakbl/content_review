import pool from "../config/db.js";

export const createSubContent = async (req, res) => {
    try {
        const { parentId, title, body } = req.body;
        const userId = req.user.id;

        const [parent] = await pool.query(
            "SELECT * FROM content WHERE id = ?",
            [parentId]
        );

        if (parent.length === 0) {
            return res.status(404).json({ message: "Parent content not found" });
        }

        const id = "sc" + Date.now();

        await pool.query(
            `INSERT INTO sub_content 
       (id, parent_id, creator_id, title, body, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 'pending_review', NOW(), NOW())`,
            [id, parentId, userId, title, body]
        );

        res.status(201).json({ message: "Sub-content created", id });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getSubContentByParent = async (req, res) => {
    try {
        const { parentId } = req.params;

        const [rows] = await pool.query(
            `SELECT * FROM sub_content WHERE parent_id = ?`,
            [parentId]
        );

        res.json(rows);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};