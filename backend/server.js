const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = 8000;
const JWT_SECRET = 'old_money_secret_key_change_in_production';

// Middleware
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json());

// Подключение к БД
const db = new sqlite3.Database('./database.sqlite');

// Инициализация таблиц
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        registration_date TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        price REAL NOT NULL,
        acquisition_date TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS wishlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        price REAL NOT NULL,
        acquisition_date TEXT NOT NULL,
        added_at TEXT DEFAULT CURRENT_TIMESTAMP,
        original_item_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);
});

// Middleware аутентификации
function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Недействительный токен' });
    }
}

// Вспомогательная функция: получить пользователя по ID
function getUserById(id, callback) {
    db.get('SELECT id, username, registration_date FROM users WHERE id = ?', [id], callback);
}

// ------------------- РЕГИСТРАЦИЯ -------------------
app.post('/api/register/', 
    body('username').isLength({ min: 3 }).withMessage('Логин минимум 3 символа'),
    body('password').isLength({ min: 4 }).withMessage('Пароль минимум 4 символа'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }
        const { username, password } = req.body;
        try {
            db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
                if (err) return res.status(500).json({ error: 'Ошибка БД' });
                if (row) return res.status(400).json({ error: 'Пользователь уже существует' });

                const hashedPassword = await bcrypt.hash(password, 10);
                db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                    [username, hashedPassword],
                    function(err) {
                        if (err) return res.status(500).json({ error: 'Ошибка при создании пользователя' });
                        res.status(201).json({ message: 'Регистрация успешна' });
                    });
            });
        } catch (err) {
            res.status(500).json({ error: 'Внутренняя ошибка сервера' });
        }
    }
);

// ------------------- ЛОГИН -------------------
app.post('/api/login/', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Заполните все поля' });
    }
    db.get('SELECT id, username, password_hash FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка БД' });
        if (!user) return res.status(401).json({ error: 'Неверный логин или пароль' });

        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(401).json({ error: 'Неверный логин или пароль' });

        const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({
            user_id: user.id,
            username: user.username,
            token: token
        });
    });
});

// ------------------- ПОЛУЧИТЬ ВСЕХ ПОЛЬЗОВАТЕЛЕЙ (для поиска) -------------------
app.get('/api/users/', (req, res) => {
    db.all(`SELECT id, username, registration_date,
            (SELECT COUNT(*) FROM items WHERE items.user_id = users.id) AS total_items
            FROM users`, (err, rows) => {
        if (err) return res.status(500).json({ error: 'Ошибка БД' });
        res.json(rows);
    });
});

// ------------------- ПОЛУЧИТЬ КОНКРЕТНОГО ПОЛЬЗОВАТЕЛЯ -------------------
app.get('/api/users/:userId/', (req, res) => {
    const userId = req.params.userId;
    getUserById(userId, (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка БД' });
        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
        res.json(user);
    });
});

// ------------------- ПОЛУЧИТЬ ПРЕДМЕТЫ ПОЛЬЗОВАТЕЛЯ -------------------
app.get('/api/users/:userId/items/', (req, res) => {
    const userId = req.params.userId;
    db.all('SELECT id, name, category, price, acquisition_date FROM items WHERE user_id = ? ORDER BY id DESC',
        [userId], (err, rows) => {
            if (err) return res.status(500).json({ error: 'Ошибка БД' });
            res.json(rows);
        });
});

// ------------------- ДОБАВИТЬ ЧУЖОЙ ПРЕДМЕТ В ЖЕЛАЕМОЕ -------------------
app.post('/api/users/:userId/items/:itemId/wishlist/', authenticate, (req, res) => {
    const targetUserId = req.params.userId;
    const itemId = req.params.itemId;
    const currentUserId = req.userId;

    db.get('SELECT name, category, price, acquisition_date FROM items WHERE id = ? AND user_id = ?',
        [itemId, targetUserId], (err, item) => {
            if (err) return res.status(500).json({ error: 'Ошибка БД' });
            if (!item) return res.status(404).json({ error: 'Предмет не найден или не принадлежит указанному пользователю' });

            db.get('SELECT id FROM wishlist WHERE user_id = ? AND original_item_id = ?',
                [currentUserId, itemId], (err, existing) => {
                    if (err) return res.status(500).json({ error: 'Ошибка БД' });
                    if (existing) {
                        return res.status(400).json({ error: 'Предмет уже в желаемом' });
                    }
                    db.run(`INSERT INTO wishlist (user_id, name, category, price, acquisition_date, original_item_id)
                            VALUES (?, ?, ?, ?, ?, ?)`,
                        [currentUserId, item.name, item.category, item.price, item.acquisition_date, itemId],
                        function(err) {
                            if (err) return res.status(500).json({ error: 'Ошибка добавления в желаемое' });
                            res.status(201).json({ message: 'Предмет добавлен в желаемое', wishlist_id: this.lastID });
                        });
                });
        });
});

// ------------------- ПОЛУЧИТЬ СПИСОК ЖЕЛАЕМОГО (текущего пользователя) -------------------
app.get('/api/wishlist/', authenticate, (req, res) => {
    db.all('SELECT id, name, category, price, acquisition_date FROM wishlist WHERE user_id = ? ORDER BY added_at DESC',
        [req.userId], (err, rows) => {
            if (err) return res.status(500).json({ error: 'Ошибка БД' });
            res.json(rows);
        });
});

// ------------------- УДАЛИТЬ ИЗ ЖЕЛАЕМОГО -------------------
app.delete('/api/wishlist/:id/', authenticate, (req, res) => {
    const wishlistId = req.params.id;
    db.run('DELETE FROM wishlist WHERE id = ? AND user_id = ?', [wishlistId, req.userId], function(err) {
        if (err) return res.status(500).json({ error: 'Ошибка БД' });
        if (this.changes === 0) return res.status(404).json({ error: 'Запись не найдена или не принадлежит вам' });
        res.status(204).send();
    });
});

// ------------------- ПОЛУЧИТЬ ВСЕ ПРЕДМЕТЫ ТЕКУЩЕГО ПОЛЬЗОВАТЕЛЯ -------------------
app.get('/api/items/', authenticate, (req, res) => {
    db.all('SELECT id, name, category, price, acquisition_date FROM items WHERE user_id = ? ORDER BY id DESC',
        [req.userId], (err, rows) => {
            if (err) return res.status(500).json({ error: 'Ошибка БД' });
            res.json(rows);
        });
});

// ------------------- СОЗДАТЬ НОВЫЙ ПРЕДМЕТ -------------------
app.post('/api/items/create/', authenticate, (req, res) => {
    const { name, category, price, acquisitionDate } = req.body;
    if (!name || !category || price === undefined || !acquisitionDate) {
        return res.status(400).json({ error: 'Не все поля заполнены' });
    }
    // Проверка на положительную стоимость
    if (isNaN(price) || price <= 0) {
        return res.status(400).json({ error: 'Стоимость должна быть положительным числом' });
    }
    db.run('INSERT INTO items (user_id, name, category, price, acquisition_date) VALUES (?, ?, ?, ?, ?)',
        [req.userId, name, category, price, acquisitionDate], function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка БД' });
            res.status(201).json({ id: this.lastID, message: 'Предмет добавлен' });
        });
});

// ------------------- УДАЛИТЬ ПРЕДМЕТ -------------------
app.delete('/api/items/:id/delete/', authenticate, (req, res) => {
    const itemId = req.params.id;
    db.run('DELETE FROM items WHERE id = ? AND user_id = ?', [itemId, req.userId], function(err) {
        if (err) return res.status(500).json({ error: 'Ошибка БД' });
        if (this.changes === 0) return res.status(404).json({ error: 'Предмет не найден или не принадлежит вам' });
        res.status(204).send();
    });
});

// ------------------- СТАТИСТИКА -------------------
app.get('/api/stats/', authenticate, (req, res) => {
    db.get('SELECT COUNT(*) as total_items, SUM(price) as total_value FROM items WHERE user_id = ?',
        [req.userId], (err, row) => {
            if (err) return res.status(500).json({ error: 'Ошибка БД' });
            res.json({
                total_items: row.total_items || 0,
                total_value: row.total_value || 0
            });
        });
});

// ------------------- СПИСОК КАТЕГОРИЙ ПОЛЬЗОВАТЕЛЯ -------------------
app.get('/api/categories/', authenticate, (req, res) => {
    db.all('SELECT DISTINCT category FROM items WHERE user_id = ? ORDER BY category', [req.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Ошибка БД' });
        const categories = rows.map(row => row.category);
        res.json(categories);
    });
});

// ------------------- ЭКСПОРТ ОТЧЁТА -------------------
app.get('/api/export/', authenticate, (req, res) => {
    const { format, sort, category, from, to } = req.query;
    let sql = 'SELECT name, category, price, acquisition_date FROM items WHERE user_id = ?';
    const params = [req.userId];

    if (category && category !== 'all') {
        sql += ' AND category = ?';
        params.push(category);
    }
    if (from) {
        sql += ' AND acquisition_date >= ?';
        params.push(from);
    }
    if (to) {
        sql += ' AND acquisition_date <= ?';
        params.push(to);
    }

    switch (sort) {
        case 'date-asc': sql += ' ORDER BY acquisition_date ASC'; break;
        case 'price-desc': sql += ' ORDER BY price DESC'; break;
        case 'price-asc': sql += ' ORDER BY price ASC'; break;
        case 'name-asc': sql += ' ORDER BY name ASC'; break;
        default: sql += ' ORDER BY acquisition_date DESC'; break;
    }

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: 'Ошибка БД' });

        if (format === 'csv') {
            let csv = 'Название,Категория,Цена (₽),Дата получения\n';
            rows.forEach(row => {
                csv += `"${row.name}","${row.category}",${row.price},"${row.acquisition_date}"\n`;
            });
            res.setHeader('Content-Type', 'text/csv; charset=utf-8');
            res.setHeader('Content-Disposition', `attachment; filename="old_money_export_${Date.now()}.csv"`);
            return res.send(csv);
        } else {
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', `attachment; filename="old_money_export_${Date.now()}.json"`);
            return res.json(rows);
        }
    });
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`Backend запущен на http://127.0.0.1:${PORT}`);
});