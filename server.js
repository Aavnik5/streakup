const express = require('express');
const cors = require('cors');
const { createClient } = require('@libsql/client');

const app = express();
app.use(cors());
app.use(express.json());

// ================= DATABASE CONNECTION (TURSO) =================
const db = createClient({
    url: "libsql://streak-db-aavnik-kumar.aws-ap-south-1.turso.io",
    authToken: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3NzE5OTkxNjYsImlkIjoiMDE5YzkzNjAtY2UwMS03MTU1LTg3NjAtYjdjMGUzNjRkZTY3IiwicmlkIjoiOTAwYzViYjQtYjFmOS00M2JjLTgyMDgtMTNkZTQ3MTY5NTIwIn0.21PgSH8zToHiEb-PDOaRmxeu1jRWOLsJKDvpg69gFVQwhST2lgbLQE6UgKo8imuJVpVoeMCdwJvzzA_hN4kjAw"
});

// Database Initialize (Table Banana)
async function initDB() {
    try {
        await db.execute(`
            CREATE TABLE IF NOT EXISTS habits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                logs TEXT DEFAULT '[]',
                currentStreak INTEGER DEFAULT 0,
                longestStreak INTEGER DEFAULT 0
            )
        `);
        console.log("Turso Database Connected & Table Ready! ✅");
    } catch (err) {
        console.log("Turso DB Error: ❌", err);
    }
}
initDB();

// ================= API ROUTES =================

// 1. Get All Habits
app.get('/api/habits', async (req, res) => {
    try {
        const result = await db.execute("SELECT * FROM habits");
        // SQL me array ko text (JSON) banakar save karte hain, wapas bhejte time parse karna padta hai
        const habits = result.rows.map(row => ({
            ...row,
            logs: JSON.parse(row.logs)
        }));
        res.json(habits);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. Create a New Habit
app.post('/api/habits', async (req, res) => {
    try {
        const { name } = req.body;
        const result = await db.execute({
            sql: "INSERT INTO habits (name, logs, currentStreak, longestStreak) VALUES (?, '[]', 0, 0) RETURNING *",
            args: [name]
        });
        
        const newHabit = result.rows[0];
        newHabit.logs = JSON.parse(newHabit.logs);
        res.json(newHabit);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. Mark Habit as Done (STREAK LOGIC)
app.post('/api/habits/:id/mark', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await db.execute({ sql: "SELECT * FROM habits WHERE id = ?", args: [id] });
        
        if (result.rows.length === 0) return res.status(404).json({ error: "Habit not found" });

        let habit = result.rows[0];
        let logs = JSON.parse(habit.logs);
        let { currentStreak, longestStreak } = habit;

        // Date Logic (YYYY-MM-DD)
        const today = new Date().toISOString().split('T')[0];
        const yesterdayDate = new Date();
        yesterdayDate.setDate(yesterdayDate.getDate() - 1);
        const yesterday = yesterdayDate.toISOString().split('T')[0];

        // Agar aaj already mark kar diya hai
        if (logs.includes(today)) {
            return res.json({ message: "Already marked for today!", habit: { ...habit, logs } });
        }

        // Streak Check
        if (logs.includes(yesterday)) {
            currentStreak += 1;
        } else {
            currentStreak = 1; // Miss ho gaya, wapas 1 se shuru
        }

        if (currentStreak > longestStreak) {
            longestStreak = currentStreak;
        }

        logs.push(today);
        const logsString = JSON.stringify(logs);

        // Update Database
        await db.execute({
            sql: "UPDATE habits SET logs = ?, currentStreak = ?, longestStreak = ? WHERE id = ?",
            args: [logsString, currentStreak, longestStreak, id]
        });

        res.json({ message: "Marked successfully!", currentStreak, longestStreak });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ================= SERVER START =================
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT} 🚀`);
});