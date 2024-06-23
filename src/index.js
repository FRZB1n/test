const express = require("express");
const app = express();
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const BP = require("body-parser");
const cors = require("cors");

const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;

app.use(BP.urlencoded({ extended: true }));
app.use(BP.json());
app.use(cors());

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

const SECRET_KEY = "your_secret_key";

// Регистрация
app.post("/auth/register", async (req, res) => {
  const { email, password } = req.body;
  console.log(email, password);
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });
    res.status(201).json(user);
  } catch (error) {
    res.status(400).json({ error: "User already exists" });
  }
});

// Логин
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({
    where: { email },
  });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const token = jwt.sign({ userId: user.id }, SECRET_KEY);
  res.json({ token });
});

const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: "Forbidden" });
    req.user = user;
    next();
  });
};

// Создание задачи
app.post("/tasks", authenticateToken, async (req, res) => {
  const { title, description } = req.body;
  const task = await prisma.task.create({
    data: {
      title,
      description,
      userId: req.user.userId,
    },
  });
  res.status(201).json(task);
});

// Получение всех задач
app.get("/tasks", authenticateToken, async (req, res) => {
  const tasks = await prisma.task.findMany({
    where: { userId: req.user.userId },
  });
  res.json(tasks);
});

// Получение конкретной задачи
app.get("/tasks/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const task = await prisma.task.findUnique({
    where: { id: parseInt(id), userId: req.user.userId },
  });
  if (!task) return res.status(404).json({ error: "Task not found" });
  res.json(task);
});

// Обновление задачи
app.put("/tasks/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { title, description, stat } = req.body;
  const status = stat == "true" || "1" ? true : false;

  try {
    const task = await prisma.task.updateMany({
      where: { id: parseInt(id), userId: req.user.userId },

      data: { title, description, status },
    });
    if (task.count === 0)
      return res.status(404).json({ error: "Task not found" });
    res.json({ message: "Task updated" });
  } catch (error) {
    console.log(error);
    res.status(400).json({ error: "Failed to update task" });
  }
});

// Удаление задачи
app.delete("/tasks/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const task = await prisma.task.deleteMany({
      where: { id: parseInt(id), userId: req.user.userId },
    });
    if (task.count === 0)
      return res.status(404).json({ error: "Task not found" });
    res.json({ message: "Task deleted" });
  } catch (error) {
    res.status(400).json({ error: "Failed to delete task" });
  }
});
