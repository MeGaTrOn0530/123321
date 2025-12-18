require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production";

// Middleware
app.use(cors({
  origin: process.env.CLIENT_URL || '*',
  credentials: true
}));
app.use(express.json());
app.use("/uploads", express.static("uploads"));

// Serve static HTML files
app.use(express.static('.'));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || "mongodb+srv://azizbekavalov132_db_user:sBWMy34g2NGFaoNO@tyutor.gpmrpqd.mongodb.net/?appName=tyutor", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✅ MongoDB ga ulandi"))
.catch(err => {
  console.error("❌ MongoDB ulanish xatosi:", err);
  process.exit(1);
});

// User Schema
const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  login: { type: String, unique: true },
  password: String,
  profileImage: String,
  role: { type: String, enum: ["admin", "user"], default: "user" },
  createdAt: { type: Date, default: Date.now },
});

// File Schema
const fileSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  section: Number,
  direction: Number,
  description: String,
  filename: String,
  filepath: String,
  status: {
    type: String,
    enum: ["new", "viewed", "accepted", "rejected"],
    default: "new",
  },
  rejectionReason: String,
  uploadedAt: { type: Date, default: Date.now },
  viewedAt: Date,
  processedAt: Date,
  reminderSent: { type: Boolean, default: false },
});

const User = mongoose.model("User", userSchema);
const File = mongoose.model("File", fileSchema);

// Multer Storage Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = "uploads/";
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + "-" + Math.round(Math.random() * 1e9) + path.extname(file.originalname);
    cb(null, uniqueName);
  },
});

const upload = multer({ storage: storage });

// Auth Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Token mavjud emas" });

    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    next();
  } catch (error) {
    res.status(401).json({ error: "Noto'g'ri token" });
  }
};

// Admin Middleware
const adminMiddleware = (req, res, next) => {
  if (req.userRole !== "admin") {
    return res.status(403).json({ error: "Kirish taqiqlangan" });
  }
  next();
};

// Config endpoint for frontend
app.get('/api/config', (req, res) => {
  res.json({
    serverUrl: process.env.SERVER_URL || `http://localhost:${PORT}`
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// ==================== AUTH ROUTES ====================

// Admin Login
app.post("/api/admin/login", async (req, res) => {
  try {
    const { login, password } = req.body;
    const user = await User.findOne({ login, role: "admin" });

    if (!user) {
      return res.status(401).json({ error: "Login yoki parol xato" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Login yoki parol xato" });
    }

    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET);
    res.json({ token, user: { id: user._id, firstName: user.firstName, lastName: user.lastName, role: user.role } });
  } catch (error) {
    console.error("Admin login xatosi:", error);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// User Login
app.post("/api/user/login", async (req, res) => {
  try {
    const { login, password } = req.body;
    const user = await User.findOne({ login, role: "user" });

    if (!user) {
      return res.status(401).json({ error: "Login yoki parol xato" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Login yoki parol xato" });
    }

    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET);
    res.json({
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        profileImage: user.profileImage,
      },
    });
  } catch (error) {
    console.error("User login xatosi:", error);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// ==================== ADMIN ROUTES ====================

// Create User (Admin only)
app.post("/api/admin/users", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { firstName, lastName, login, password } = req.body;

    const existingUser = await User.findOne({ login });
    if (existingUser) {
      return res.status(400).json({ error: "Bu login band" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      firstName,
      lastName,
      login,
      password: hashedPassword,
      role: "user",
    });

    await user.save();
    res.json({ message: "Foydalanuvchi yaratildi", userId: user._id });
  } catch (error) {
    console.error("User yaratish xatosi:", error);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Get All Users (Admin only)
app.get("/api/admin/users", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.find({ role: "user" }).select("-password");

    const usersWithStats = await Promise.all(
      users.map(async (user) => {
        const newFilesCount = await File.countDocuments({ userId: user._id, status: "new" });
        return {
          ...user.toObject(),
          newFilesCount,
        };
      }),
    );

    res.json(usersWithStats);
  } catch (error) {
    console.error("Userlarni olish xatosi:", error);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Get User Files (Admin only)
app.get("/api/admin/users/:userId/files", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const files = await File.find({ userId: req.params.userId }).sort({ uploadedAt: -1 });
    res.json(files);
  } catch (error) {
    console.error("Fayllarni olish xatosi:", error);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// View File (Admin only)
app.post("/api/admin/files/:fileId/view", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);
    if (!file) {
      return res.status(404).json({ error: "Fayl topilmadi" });
    }

    if (file.status === "new") {
      file.status = "viewed";
      file.viewedAt = new Date();
      await file.save();
    }

    res.json(file);
  } catch (error) {
    console.error("Faylni ko'rish xatosi:", error);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Accept File (Admin only)
app.post("/api/admin/files/:fileId/accept", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const file = await File.findByIdAndUpdate(
      req.params.fileId,
      { status: "accepted", processedAt: new Date() },
      { new: true },
    );

    if (!file) {
      return res.status(404).json({ error: "Fayl topilmadi" });
    }

    res.json(file);
  } catch (error) {
    console.error("Faylni qabul qilish xatosi:", error);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Reject File (Admin only)
app.post("/api/admin/files/:fileId/reject", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { reason } = req.body;
    const file = await File.findByIdAndUpdate(
      req.params.fileId,
      {
        status: "rejected",
        rejectionReason: reason,
        processedAt: new Date(),
      },
      { new: true },
    );

    if (!file) {
      return res.status(404).json({ error: "Fayl topilmadi" });
    }

    res.json(file);
  } catch (error) {
    console.error("Faylni rad etish xatosi:", error);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// ==================== USER ROUTES ====================

// Get User Profile
app.get("/api/user/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) {
      return res.status(404).json({ error: "Foydalanuvchi topilmadi" });
    }
    res.json(user);
  } catch (error) {
    console.error("Profil olish xatosi:", error);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Update User Profile
app.put("/api/user/profile", authMiddleware, upload.single("profileImage"), async (req, res) => {
  try {
    const { firstName, lastName } = req.body;
    const updateData = { firstName, lastName };

    if (req.file) {
      updateData.profileImage = "/uploads/" + req.file.filename;
    }

    const user = await User.findByIdAndUpdate(req.userId, updateData, { new: true }).select("-password");

    res.json(user);
  } catch (error) {
    console.error("Profil yangilash xatosi:", error);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Upload File
app.post("/api/user/files", authMiddleware, upload.single("file"), async (req, res) => {
  try {
    const { section, direction, description } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: "Fayl tanlanmagan" });
    }

    const file = new File({
      userId: req.userId,
      section: Number.parseInt(section),
      direction: Number.parseInt(direction),
      description,
      filename: req.file.originalname,
      filepath: "/uploads/" + req.file.filename,
    });

    await file.save();
    res.json(file);
  } catch (error) {
    console.error("Fayl yuklash xatosi:", error);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Get User Files
app.get("/api/user/files", authMiddleware, async (req, res) => {
  try {
    const files = await File.find({ userId: req.userId }).sort({ uploadedAt: -1 });
    res.json(files);
  } catch (error) {
    console.error("Fayllarni olish xatosi:", error);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Delete File
app.delete("/api/user/files/:fileId", authMiddleware, async (req, res) => {
  try {
    const file = await File.findOne({ _id: req.params.fileId, userId: req.userId });

    if (!file) {
      return res.status(404).json({ error: "Fayl topilmadi yoki sizga tegishli emas" });
    }

    if (file.status !== "new") {
      return res.status(403).json({ error: "Faqat yangi fayllarni o'chirish mumkin" });
    }

    const fullPath = path.join(__dirname, file.filepath);
    if (fs.existsSync(fullPath)) {
      fs.unlinkSync(fullPath);
    }

    await File.findByIdAndDelete(req.params.fileId);
    res.json({ message: "Fayl o'chirildi" });
  } catch (error) {
    console.error("Fayl o'chirish xatosi:", error);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Update File
app.put("/api/user/files/:fileId", authMiddleware, upload.single("file"), async (req, res) => {
  try {
    const { description } = req.body;
    const file = await File.findOne({ _id: req.params.fileId, userId: req.userId });

    if (!file) {
      return res.status(404).json({ error: "Fayl topilmadi yoki sizga tegishli emas" });
    }

    if (file.status !== "new") {
      return res.status(403).json({ error: "Faqat yangi fayllarni tahrirlash mumkin" });
    }

    file.description = description;

    if (req.file) {
      const oldPath = path.join(__dirname, file.filepath);
      if (fs.existsSync(oldPath)) {
        fs.unlinkSync(oldPath);
      }

      file.filename = req.file.originalname;
      file.filepath = "/uploads/" + req.file.filename;
    }

    await file.save();
    res.json(file);
  } catch (error) {
    console.error("Fayl tahrirlash xatosi:", error);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// ==================== REMINDER SYSTEM ====================

setInterval(
  async () => {
    try {
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

      const filesToRemind = await File.find({
        status: "viewed",
        viewedAt: { $lt: oneHourAgo },
        reminderSent: false,
      });

      for (const file of filesToRemind) {
        file.reminderSent = true;
        await file.save();
        console.log(`⏰ Eslatma: Fayl ${file._id} 1 soatdan ortiq kutmoqda`);
      }
    } catch (error) {
      console.error("⚠️ Eslatma xatosi:", error);
    }
  },
  5 * 60 * 1000,
);

// ==================== INITIAL ADMIN CREATION ====================

async function createInitialAdmin() {
  try {
    const adminLogin = process.env.ADMIN_LOGIN || "admin";
    const adminPassword = process.env.ADMIN_PASSWORD || "SamISI123com";
    
    const adminExists = await User.findOne({ role: "admin", login: adminLogin });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      const admin = new User({
        firstName: "Admin",
        lastName: "Administrator",
        login: adminLogin,
        password: hashedPassword,
        role: "admin",
      });
      await admin.save();
      console.log(`✅ Boshlang'ich admin yaratildi: login=${adminLogin}`);
    } else {
      console.log("ℹ️  Admin allaqachon mavjud");
    }
  } catch (error) {
    console.error("❌ Admin yaratishda xato:", error);
  }
}

// ==================== SERVER START ====================

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔════════════════════════════════════════════╗
║   🎓 TYUTOR SYSTEM - SERVER ISHGA TUSHDI  ║
╚════════════════════════════════════════════╝
  
  ✅ Server: http://172.17.10.56:${PORT}
  ✅ Admin: http://172.17.10.56:${PORT}/admin.html
  ✅ User:  http://172.17.10.56:${PORT}/user.html
  
  📊 Environment: ${process.env.NODE_ENV || 'development'}
  🔒 JWT Secret: ${JWT_SECRET ? '✓ Configured' : '✗ Not configured'}
  💾 MongoDB: Ulanmoqda...
  
  `);

  mongoose.connection.once("open", () => {
    console.log("✅ MongoDB ga ulandi");
    createInitialAdmin();
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('⚠️  SIGTERM signal qabul qilindi. Server yopilmoqda...');
  server.close(() => {
    console.log('✅ Server yopildi');
    mongoose.connection.close(false, () => {
      console.log('✅ MongoDB ulanish yopildi');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('⚠️  SIGINT signal qabul qilindi. Server yopilmoqda...');
  server.close(() => {
    console.log('✅ Server yopildi');
    mongoose.connection.close(false, () => {
      console.log('✅ MongoDB ulanish yopildi');
      process.exit(0);
    });
  });
});