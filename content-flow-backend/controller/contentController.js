import pool from "../config/db.js";

export const createContent = async (req, res) => {
    try {
        const { title, body } = req.body;
        const userId = req.user.id;

        const id = "c" + Date.now();

        await pool.query(
            `INSERT INTO content (id, creator_id, title, body, status, current_stage, version, updated_at)
       VALUES (?, ?, ?, ?, 'pending_review', 1, 1, NOW())`,
            [id, userId, title, body]
        );

        await pool.query(
            `INSERT INTO edit_cycles (id, content_id, editor_id, version, body_snapshot, edited_at)
             VALUES (?, ?, ?, 1, ?, NOW())`,
            ["ec" + Date.now(), id, userId, body]
        );

        res.status(201).json({ message: "Content created", id });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getAllContent = async (req, res) => {
    try {
        const { status } = req.query;

        let query = "SELECT * FROM content";
        let values = [];

        if (status) {
            query += " WHERE status = ?";
            values.push(status);
        }

        const [rows] = await pool.query(query, values);

        res.json(rows);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getContentById = async (req, res) => {
    try {
        const { id } = req.params;

        const [contents] = await pool.query(
            `SELECT c.*, u.username as creator_name 
             FROM content c 
             JOIN users u ON c.creator_id = u.id 
             WHERE c.id = ?`,
            [id]
        );

        if (contents.length === 0) {
            return res.status(404).json({ message: "Content not found" });
        }

        const [history] = await pool.query(
            `SELECT ra.*, u.username as reviewer_name 
             FROM review_actions ra 
             JOIN users u ON ra.reviewer_id = u.id 
             WHERE ra.content_id = ? 
             ORDER BY ra.acted_at ASC`,
            [id]
        );

        const [subContent] = await pool.query(
            "SELECT * FROM sub_content WHERE parent_id = ?",
            [id]
        );

        res.json({
            content: contents[0],
            history: history,
            subContent: subContent,
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const updateContent = async (req, res) => {
    try {
        const { id } = req.params;
        const { title, body } = req.body;

        const [rows] = await pool.query(
            "SELECT * FROM content WHERE id = ?",
            [id]
        );

        const content = rows[0];

        if (!content) {
            return res.status(404).json({ message: "Content not found" });
        }

        if (!["draft", "rejected"].includes(content.status)) {
            return res.status(400).json({ message: "Cannot edit this content" });
        }

        const newVersion = content.version + 1;

        await pool.query(
            `UPDATE content 
             SET title = ?, body = ?, status = 'pending_review', current_stage = 1, version = ?, updated_at = NOW() 
             WHERE id = ?`,
            [title, body, newVersion, id]
        );

        await pool.query(
            `INSERT INTO edit_cycles (id, content_id, editor_id, version, body_snapshot, edited_at)
             VALUES (?, ?, ?, ?, ?, NOW())`,
            ["ec" + Date.now(), id, req.user.id, newVersion, body]
        );

        res.json({ message: "Content updated and resubmitted for review" });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const submitContent = async (req, res) => {
    try {
        const { id } = req.params;

        const [rows] = await pool.query(
            "SELECT * FROM content WHERE id = ?",
            [id]
        );

        const content = rows[0];

        if (!content) {
            return res.status(404).json({ message: "Content not found" });
        }

        if (!["draft", "rejected"].includes(content.status)) {
            return res.status(400).json({ message: "Already submitted" });
        }

        await pool.query(
            `UPDATE content 
       SET status = 'pending_review', current_stage = 1, updated_at = NOW() 
       WHERE id = ?`,
            [id]
        );

        res.json({ message: "Content submitted for review" });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

