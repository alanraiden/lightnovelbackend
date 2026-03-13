const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors({
  origin: function(origin, callback) { callback(null, true); },
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// ── Cloudinary (optional) ─────────────────────────────────────────────────────
const cloudinaryConfigured = !!(
  process.env.CLOUDINARY_CLOUD_NAME &&
  process.env.CLOUDINARY_API_KEY &&
  process.env.CLOUDINARY_API_SECRET
);

if (cloudinaryConfigured) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key:    process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });
  console.log('Cloudinary configured');
} else {
  console.warn('Cloudinary NOT configured - cover uploads disabled');
}

let upload;
if (cloudinaryConfigured) {
  const coverStorage = new CloudinaryStorage({
    cloudinary,
    params: { folder: 'novasphere/covers', allowed_formats: ['jpg','jpeg','png','webp'] },
  });
  upload = multer({ storage: coverStorage });
} else {
  upload = multer({ storage: multer.memoryStorage() });
}

// Wrap multer to catch upload errors
function handleUpload(req, res, next) {
  upload.single('cover')(req, res, function(err) {
    if (err) {
      console.error('Upload error:', err);
      return res.status(400).json({ error: 'Upload failed: ' + err.message });
    }
    // If Cloudinary not configured, clear the file so cover stays empty
    if (!cloudinaryConfigured) req.file = null;
    next();
  });
}

// ── MongoDB ───────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err.message));

// ── Schemas ───────────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  googleId: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  name:     { type: String, required: true },
  avatar:   { type: String, default: '' },
  role:     { type: String, enum: ['reader','author','admin'], default: 'author' },
}, { timestamps: true });

const novelSchema = new mongoose.Schema({
  title:         { type: String, required: true },
  author:        { type: String, required: true },
  authorId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  cover:         { type: String, default: '' },
  coverPublicId: { type: String, default: '' },
  description:   { type: String, default: '' },
  genres:        [String],
  tags:          [String],
  status:        { type: String, enum: ['ongoing','completed'], default: 'ongoing' },
  rating:        { type: Number, default: 0 },
  ratingCount:   { type: Number, default: 0 },
  views:         { type: Number, default: 0 },
  chapterCount:  { type: Number, default: 0 },
}, { timestamps: true });

const chapterSchema = new mongoose.Schema({
  novelId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Novel', required: true },
  authorId:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  number:    { type: Number, required: true },
  title:     { type: String, required: true },
  content:   { type: String, required: true },
  views:     { type: Number, default: 0 },
  wordCount: { type: Number, default: 0 },
}, { timestamps: true });

const User    = mongoose.model('User', userSchema);
const Novel   = mongoose.model('Novel', novelSchema);
const Chapter = mongoose.model('Chapter', chapterSchema);

// ── Auth helpers ──────────────────────────────────────────────────────────────
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

function signToken(user) {
  return jwt.sign(
    { id: user._id, email: user.email, name: user.name, avatar: user.avatar, role: user.role },
    process.env.JWT_SECRET || 'fallback_secret_change_this',
    { expiresIn: '7d' }
  );
}

async function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    req.user = jwt.verify(header.split(' ')[1], process.env.JWT_SECRET || 'fallback_secret_change_this');
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

async function requireAdmin(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    req.user = jwt.verify(header.split(' ')[1], process.env.JWT_SECRET || 'fallback_secret_change_this');
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only the site owner can perform this action.' });
    }
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

async function requireOwner(req, res, next) {
  try {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ error: 'Not authenticated' });
    req.user = jwt.verify(header.split(' ')[1], process.env.JWT_SECRET || 'fallback_secret_change_this');
    // Only admin can write
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only the site owner can upload, edit or delete content.' });
    }
    const novel = await Novel.findById(req.params.id);
    if (!novel) return res.status(404).json({ error: 'Novel not found' });
    req.novel = novel;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Auth error: ' + e.message });
  }
}

// ── Auth routes ───────────────────────────────────────────────────────────────
app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'No credential provided' });
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const { sub: googleId, email, name, picture } = ticket.getPayload();
    const ownerEmail = process.env.OWNER_EMAIL || '';
    const isOwner = ownerEmail && email.toLowerCase() === ownerEmail.toLowerCase();
    let user = await User.findOne({ googleId });
    if (!user) {
      user = await User.create({ googleId, email, name, avatar: picture, role: isOwner ? 'admin' : 'reader' });
    } else if (isOwner && user.role !== 'admin') {
      user.role = 'admin';
      await user.save();
    }
    const token = signToken(user);
    res.json({ token, user: { id: user._id, email, name, avatar: picture, role: user.role } });
  } catch (err) {
    console.error('Google auth error:', err.message);
    res.status(401).json({ error: 'Google auth failed: ' + err.message });
  }
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-googleId');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Novel routes ──────────────────────────────────────────────────────────────
app.get('/api/novels', async (req, res) => {
  try {
    const { genre, status, sort='rating', search, limit=20, page=1, authorId } = req.query;
    const query = {};
    if (genre)    query.genres   = genre;
    if (status)   query.status   = status;
    if (authorId) query.authorId = authorId;
    if (search)   query.$or = [
      { title:  { $regex: search, $options: 'i' } },
      { author: { $regex: search, $options: 'i' } },
      { tags:   { $regex: search, $options: 'i' } },
    ];
    const sortMap = { rating:{rating:-1}, views:{views:-1}, new:{createdAt:-1}, chapters:{chapterCount:-1} };
    const novels = await Novel.find(query)
      .sort(sortMap[sort] || { rating: -1 })
      .limit(Number(limit))
      .skip((Number(page)-1) * Number(limit));
    const total = await Novel.countDocuments(query);
    res.json({ novels, total, pages: Math.ceil(total / limit) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/novels/:id', async (req, res) => {
  try {
    const novel = await Novel.findById(req.params.id);
    if (!novel) return res.status(404).json({ error: 'Novel not found' });
    novel.views += 1;
    await novel.save();
    res.json(novel);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/novels', requireAdmin, handleUpload, async (req, res) => {
  try {
    const { title, description, genres, tags, status } = req.body;
    if (!title) return res.status(400).json({ error: 'Title is required' });
    const novel = new Novel({
      title,
      author:        process.env.AUTHOR_NAME || 'idenwebstudio',
      authorId:      req.user.id,
      description:   description || '',
      status:        status || 'ongoing',
      genres:        JSON.parse(genres || '[]'),
      tags:          JSON.parse(tags   || '[]'),
      cover:         req.file?.path     || '',
      coverPublicId: req.file?.filename || '',
    });
    await novel.save();
    res.status(201).json(novel);
  } catch (err) {
    console.error('Create novel error:', err);
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/novels/:id', requireOwner, handleUpload, async (req, res) => {
  try {
    const { title, description, genres, tags, status } = req.body;
    const updates = {};
    if (title)       updates.title       = title;
    if (description) updates.description = description;
    if (status)      updates.status      = status;
    if (genres)      updates.genres      = JSON.parse(genres);
    if (tags)        updates.tags        = JSON.parse(tags);
    if (req.file && cloudinaryConfigured) {
      if (req.novel.coverPublicId) await cloudinary.uploader.destroy(req.novel.coverPublicId);
      updates.cover         = req.file.path;
      updates.coverPublicId = req.file.filename;
    }
    const novel = await Novel.findByIdAndUpdate(req.params.id, updates, { new: true });
    res.json(novel);
  } catch (err) {
    console.error('Update novel error:', err);
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/novels/:id', requireOwner, async (req, res) => {
  try {
    if (cloudinaryConfigured && req.novel.coverPublicId) {
      await cloudinary.uploader.destroy(req.novel.coverPublicId);
    }
    await Novel.findByIdAndDelete(req.params.id);
    await Chapter.deleteMany({ novelId: req.params.id });
    res.json({ message: 'Novel and all chapters deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Chapter routes ────────────────────────────────────────────────────────────
app.get('/api/novels/:id/chapters', async (req, res) => {
  try {
    const chapters = await Chapter.find({ novelId: req.params.id }).sort({ number: 1 }).select('-content');
    res.json(chapters);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/novels/:id/chapters/:num', async (req, res) => {
  try {
    const chapter = await Chapter.findOne({ novelId: req.params.id, number: Number(req.params.num) });
    if (!chapter) return res.status(404).json({ error: 'Chapter not found' });
    chapter.views += 1;
    await chapter.save();
    res.json(chapter);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/novels/:id/chapters', requireOwner, async (req, res) => {
  try {
    const { number, title, content } = req.body;
    if (!number || !title || !content) return res.status(400).json({ error: 'number, title and content are required' });
    const existing = await Chapter.findOne({ novelId: req.params.id, number });
    if (existing) return res.status(400).json({ error: 'Chapter number already exists' });
    const wordCount = content.split(/\s+/).filter(Boolean).length;
    const chapter = new Chapter({ novelId: req.params.id, authorId: req.user.id, number, title, content, wordCount });
    await chapter.save();
    await Novel.findByIdAndUpdate(req.params.id, { $inc: { chapterCount: 1 } });
    res.status(201).json(chapter);
  } catch (err) {
    console.error('Create chapter error:', err);
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/novels/:id/chapters/:num', requireOwner, async (req, res) => {
  try {
    const { title, content } = req.body;
    const wordCount = content?.split(/\s+/).filter(Boolean).length || 0;
    const chapter = await Chapter.findOneAndUpdate(
      { novelId: req.params.id, number: Number(req.params.num) },
      { title, content, wordCount }, { new: true }
    );
    if (!chapter) return res.status(404).json({ error: 'Chapter not found' });
    res.json(chapter);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/novels/:id/chapters/:num', requireOwner, async (req, res) => {
  try {
    const chapter = await Chapter.findOneAndDelete({ novelId: req.params.id, number: Number(req.params.num) });
    if (!chapter) return res.status(404).json({ error: 'Chapter not found' });
    await Novel.findByIdAndUpdate(req.params.id, { $inc: { chapterCount: -1 } });
    res.json({ message: 'Chapter deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/novels/:id/rate', requireAuth, async (req, res) => {
  try {
    const { rating } = req.body;
    const novel = await Novel.findById(req.params.id);
    if (!novel) return res.status(404).json({ error: 'Novel not found' });
    novel.rating = Math.round((((novel.rating * novel.ratingCount) + rating) / (novel.ratingCount + 1)) * 10) / 10;
    novel.ratingCount += 1;
    await novel.save();
    res.json({ rating: novel.rating, ratingCount: novel.ratingCount });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

app.get('/api/health', (_, res) => res.json({ status: 'ok', cloudinary: cloudinaryConfigured }));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log('idenwebstudio API running on port ' + PORT));
