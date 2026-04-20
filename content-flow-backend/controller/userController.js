import pool from "../config/db.js";

export const getAllUsers = async (req, res) => {
    try {
        const [users] = await pool.query(
            `SELECT id, name, username, role, created_at FROM users`
        );

        res.json(users);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

