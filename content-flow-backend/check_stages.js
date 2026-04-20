import mysql from "mysql2/promise";
import dotenv from "dotenv";
dotenv.config({ path: "d:/Context review/content-flow-backend/.env" });

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

async function run() {
    try {
        const [rows] = await pool.query("SHOW COLUMNS FROM review_actions");
        console.log("Review Actions Columns:", rows);
    } catch (e) {
        console.error("Error:", e.message);
    } finally {
        process.exit();
    }
}
run();
