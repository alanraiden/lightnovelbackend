const express   = require('express');
const mongoose  = require('mongoose');
const cors      = require('cors');
const bcrypt    = require('bcryptjs');
const cloudinary = require('cloudinary').v2;
const multer    = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const { OAuth2Client } = require('google-auth-library');
const jwt       = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// ── Slug helper ───────────────────────────────────────────────────────────────
function makeSlug(title) {
  return title
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, '')   // remove special chars
    .replace(/\s+/g, '-')            // spaces to hyphens
    .replace(/-+/g, '-')             // collapse multiple hyphens
    .replace(/^-|-$/g, '');          // trim hyphens
}

async function uniqueSlug(title, excludeId = null) {
  let slug = makeSlug(title);
  let exists = await Novel.findOne({ slug, _id: { $ne: excludeId } });
  let i = 2;
  while (exists) {
    slug = makeSlug(title) + '-' + i;
    exists = await Novel.findOne({ slug, _id: { $ne: excludeId } });
    i++;
  }
  return slug;
}
app.use(cors({ origin: function(o, cb) { cb(null, true); }, credentials: true }));
app.use(express.json({ limit: '10mb' }));

// ── Cloudinary ────────────────────────────────────────────────────────────────
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
function handleUpload(req, res, next) {
  upload.single('cover')(req, res, function(err) {
    if (err) return res.status(400).json({ error: 'Upload failed: ' + err.message });
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
  googleId:     { type: String, default: null, sparse: true },
  email:        { type: String, required: true, unique: true, lowercase: true, trim: true },
  name:         { type: String, required: true, trim: true },
  password:     { type: String, default: null },   // null for Google-only users
  avatar:       { type: String, default: '' },
  role:         { type: String, enum: ['reader','admin'], default: 'reader' },
  authProvider: { type: String, enum: ['google','email','both'], default: 'email' },
}, { timestamps: true });

const novelSchema = new mongoose.Schema({
  title:         { type: String, required: true },
  slug:          { type: String, unique: true, sparse: true },  // e.g. 'shadow-slave'
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

const commentSchema = new mongoose.Schema({
  novelId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Novel', required: true },
  chapterNum: { type: Number, default: null }, // null = novel-level comment
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  userName:  { type: String, required: true },
  userAvatar:{ type: String, default: '' },
  text:      { type: String, required: true, maxlength: 1000 },
  likes:     [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
}, { timestamps: true });

const User    = mongoose.model('User', userSchema);
const Novel   = mongoose.model('Novel', novelSchema);
const Comment = mongoose.model('Comment', commentSchema);
const Chapter = mongoose.model('Chapter', chapterSchema);

// ── Auth helpers ──────────────────────────────────────────────────────────────
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const JWT_SECRET   = process.env.JWT_SECRET || 'fallback_secret_change_this';

function signToken(user) {
  return jwt.sign(
    { id: user._id, email: user.email, name: user.name, avatar: user.avatar, role: user.role },
    JWT_SECRET, { expiresIn: '7d' }
  );
}

function userResponse(user, token) {
  return { token, user: { id: user._id, email: user.email, name: user.name, avatar: user.avatar, role: user.role, authProvider: user.authProvider } };
}

async function requireAuth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Not authenticated' });
  try { req.user = jwt.verify(h.split(' ')[1], JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

async function requireAdmin(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(h.split(' ')[1], JWT_SECRET);
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Only the site owner can perform this action.' });
    next();
  } catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

async function requireOwner(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(h.split(' ')[1], JWT_SECRET);
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Only the site owner can perform this action.' });
    const novel = await Novel.findById(req.params.id);
    if (!novel) return res.status(404).json({ error: 'Novel not found' });
    req.novel = novel;
    next();
  } catch (e) { res.status(401).json({ error: 'Auth error: ' + e.message }); }
}

// ── Auth routes ───────────────────────────────────────────────────────────────

// Google Sign-In / Sign-Up
app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'No credential provided' });
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const { sub: googleId, email, name, picture } = ticket.getPayload();
    const ownerEmail = process.env.OWNER_EMAIL || '';
    const isOwner    = ownerEmail && email.toLowerCase() === ownerEmail.toLowerCase();

    let user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      // New user — sign up via Google
      user = await User.create({
        googleId, email, name, avatar: picture,
        role:         isOwner ? 'admin' : 'reader',
        authProvider: 'google',
      });
    } else {
      // Existing user — link Google if not already linked
      let changed = false;
      if (!user.googleId) { user.googleId = googleId; user.authProvider = user.password ? 'both' : 'google'; changed = true; }
      if (!user.avatar && picture) { user.avatar = picture; changed = true; }
      if (isOwner && user.role !== 'admin') { user.role = 'admin'; changed = true; }
      if (changed) await user.save();
    }
    res.json(userResponse(user, signToken(user)));
  } catch (err) {
    console.error('Google auth error:', err.message);
    res.status(401).json({ error: 'Google auth failed: ' + err.message });
  }
});

// Email Sign-Up
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(400).json({ error: 'An account with this email already exists' });

    const ownerEmail = process.env.OWNER_EMAIL || '';
    const isOwner    = ownerEmail && email.toLowerCase() === ownerEmail.toLowerCase();
    const hashed     = await bcrypt.hash(password, 12);

    const user = await User.create({
      name: name.trim(),
      email: email.toLowerCase(),
      password: hashed,
      role: isOwner ? 'admin' : 'reader',
      authProvider: 'email',
    });
    res.status(201).json(userResponse(user, signToken(user)));
  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

// Email Sign-In
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'No account found with this email' });
    if (!user.password) return res.status(401).json({ error: 'This account uses Google Sign-In. Please sign in with Google.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Incorrect password' });

    res.json(userResponse(user, signToken(user)));
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

// Get current user
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -googleId');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Novel routes ──────────────────────────────────────────────────────────────
app.get('/api/novels', async (req, res) => {
  try {
    const { genre, status, sort='rating', search, limit=20, page=1, authorId, since } = req.query;
    const query = {};
    if (genre)    query.genres   = genre;
    if (status)   query.status   = status;
    if (authorId) query.authorId = authorId;
    if (search)   query.$or = [
      { title:  { $regex: search, $options: 'i' } },
      { author: { $regex: search, $options: 'i' } },
      { tags:   { $regex: search, $options: 'i' } },
    ];
    // since: filter novels updated within a time period (for trending tabs)
    if (since) {
      const days = Number(since);
      if (!isNaN(days) && days > 0) {
        const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
        query.updatedAt = { $gte: cutoff };
      }
    }
    const sortMap = { rating:{rating:-1}, views:{views:-1}, new:{updatedAt:-1}, added:{createdAt:-1}, chapters:{chapterCount:-1} };
    const novels  = await Novel.find(query).sort(sortMap[sort]||{rating:-1}).limit(Number(limit)).skip((Number(page)-1)*Number(limit));
    const total   = await Novel.countDocuments(query);
    res.json({ novels, total, pages: Math.ceil(total/limit) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET novel by slug (for clean URLs)
app.get('/api/novels/slug/:slug', async (req, res) => {
  try {
    const novel = await Novel.findOne({ slug: req.params.slug });
    if (!novel) return res.status(404).json({ error: 'Novel not found' });
    novel.views += 1;
    await novel.save();
    res.json(novel);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/novels/:id', async (req, res) => {
  try {
    const novel = await Novel.findById(req.params.id);
    if (!novel) return res.status(404).json({ error: 'Novel not found' });
    novel.views += 1; await novel.save();
    res.json(novel);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/novels', requireAdmin, handleUpload, async (req, res) => {
  try {
    const { title, description, genres, tags, status } = req.body;
    if (!title) return res.status(400).json({ error: 'Title is required' });
    const slug = await uniqueSlug(title);
    const novel = new Novel({
      title, slug, description: description||'', status: status||'ongoing',
      author:        process.env.AUTHOR_NAME || 'idenwebstudio',
      authorId:      req.user.id,
      genres: JSON.parse(genres||'[]'), tags: JSON.parse(tags||'[]'),
      cover:         req.file?.path     || '',
      coverPublicId: req.file?.filename || '',
    });
    await novel.save();
    res.status(201).json(novel);
  } catch (err) { console.error('Create novel error:', err); res.status(400).json({ error: err.message }); }
});

app.put('/api/novels/:id', requireOwner, handleUpload, async (req, res) => {
  try {
    const { title, description, genres, tags, status } = req.body;
    const updates = {};
    if (title) {
      updates.title = title;
      updates.slug  = await uniqueSlug(title, req.params.id);
    }
    if (description !== undefined) updates.description = description;
    if (status)      updates.status      = status;
    if (genres)      updates.genres      = JSON.parse(genres);
    if (tags)        updates.tags        = JSON.parse(tags);
    if (req.file && cloudinaryConfigured) {
      if (req.novel.coverPublicId) await cloudinary.uploader.destroy(req.novel.coverPublicId);
      updates.cover = req.file.path; updates.coverPublicId = req.file.filename;
    }
    const novel = await Novel.findByIdAndUpdate(req.params.id, updates, { new: true });
    res.json(novel);
  } catch (err) { console.error('Update novel error:', err); res.status(400).json({ error: err.message }); }
});

app.delete('/api/novels/:id', requireOwner, async (req, res) => {
  try {
    if (cloudinaryConfigured && req.novel.coverPublicId) await cloudinary.uploader.destroy(req.novel.coverPublicId);
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
    chapter.views += 1; await chapter.save();
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
    const chapter   = new Chapter({ novelId: req.params.id, authorId: req.user.id, number, title, content, wordCount });
    await chapter.save();
    await Novel.findByIdAndUpdate(req.params.id, { $inc: { chapterCount: 1 }, $set: { updatedAt: new Date() } });
    res.status(201).json(chapter);
  } catch (err) { console.error('Create chapter error:', err); res.status(400).json({ error: err.message }); }
});

// ── Bulk chapter import ───────────────────────────────────────────────────────
// POST /api/novels/:id/chapters/bulk
// Body: { chapters: [{ number, title, content }, ...], skipDuplicates: true }
app.post('/api/novels/:id/chapters/bulk', requireOwner, async (req, res) => {
  try {
    const { chapters, skipDuplicates = true } = req.body;
    if (!Array.isArray(chapters) || chapters.length === 0)
      return res.status(400).json({ error: 'chapters array is required and must not be empty' });

    const results  = { created: 0, skipped: 0, errors: [] };
    const novelId  = req.params.id;
    const authorId = req.user.id;

    for (const ch of chapters) {
      const { number, title, content } = ch;
      if (!number || !title || !content) {
        results.errors.push({ number, reason: 'Missing number, title, or content' });
        continue;
      }
      try {
        const existing = await Chapter.findOne({ novelId, number: Number(number) });
        if (existing) {
          if (skipDuplicates) { results.skipped++; continue; }
          // overwrite mode
          const wordCount = content.split(/\s+/).filter(Boolean).length;
          await Chapter.findOneAndUpdate({ novelId, number: Number(number) }, { title, content, wordCount });
          results.created++;
        } else {
          const wordCount = content.split(/\s+/).filter(Boolean).length;
          await Chapter.create({ novelId, authorId, number: Number(number), title, content, wordCount });
          results.created++;
        }
      } catch (e) {
        results.errors.push({ number, reason: e.message });
      }
    }

    // Update novel chapterCount + updatedAt
    const chapterCount = await Chapter.countDocuments({ novelId });
    await Novel.findByIdAndUpdate(novelId, { chapterCount, updatedAt: new Date() });

    res.status(201).json({
      message: `Import complete: ${results.created} created, ${results.skipped} skipped, ${results.errors.length} errors`,
      ...results,
    });
  } catch (err) {
    console.error('Bulk import error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/novels/:id/chapters/:num', requireOwner, async (req, res) => {
  try {
    const { title, content } = req.body;
    const wordCount = content?.split(/\s+/).filter(Boolean).length || 0;
    const chapter   = await Chapter.findOneAndUpdate(
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
    await Novel.findByIdAndUpdate(req.params.id, { $inc: { chapterCount: -1 }, $set: { updatedAt: new Date() } });
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

// ── Comment routes ───────────────────────────────────────────────────────────

// GET comments for a novel
app.get('/api/novels/:id/comments', async (req, res) => {
  try {
    const { page = 1, limit = 20, chapterNum } = req.query;
    const query = { novelId: req.params.id };
    if (chapterNum !== undefined) {
      query.chapterNum = chapterNum === 'null' || chapterNum === '' ? null : Number(chapterNum);
    }
    const comments = await Comment.find(query)
      .sort({ createdAt: -1 })
      .limit(Number(limit))
      .skip((Number(page) - 1) * Number(limit));
    const total = await Comment.countDocuments(query);
    res.json({ comments, total, pages: Math.ceil(total / limit) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST add comment
app.post('/api/novels/:id/comments', requireAuth, async (req, res) => {
  try {
    const { text, chapterNum } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });
    if (text.length > 1000) return res.status(400).json({ error: 'Comment too long (max 1000 chars)' });
    const comment = await Comment.create({
      novelId:    req.params.id,
      chapterNum: chapterNum != null ? Number(chapterNum) : null,
      userId:     req.user.id,
      userName:   req.user.name,
      userAvatar: req.user.avatar || '',
      text:       text.trim(),
    });
    res.status(201).json(comment);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// DELETE comment (admin or own comment)
app.delete('/api/novels/:id/comments/:commentId', requireAuth, async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.commentId);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });
    const isOwner = comment.userId.toString() === req.user.id;
    const isAdmin = req.user.role === 'admin';
    if (!isOwner && !isAdmin) return res.status(403).json({ error: 'Not allowed' });
    await Comment.findByIdAndDelete(req.params.commentId);
    res.json({ message: 'Comment deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST like/unlike comment
app.post('/api/novels/:id/comments/:commentId/like', requireAuth, async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.commentId);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });
    const idx = comment.likes.indexOf(req.user.id);
    if (idx === -1) { comment.likes.push(req.user.id); }
    else { comment.likes.splice(idx, 1); }
    await comment.save();
    res.json({ likes: comment.likes.length, liked: idx === -1 });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});


// ── Sitemap ───────────────────────────────────────────────────────────────────
app.get('/sitemap.xml', async (req, res) => {
  try {
    const siteUrl = process.env.CLIENT_URL || 'https://www.idenwebstudio.online';
    const novels  = await Novel.find({}).select('_id slug updatedAt');
    const chapters = await Chapter.find({}).select('novelId number updatedAt');

    const staticPages = ['', '/browse', '/rankings', '/genres', '/updates'];

    let urls = staticPages.map(p => `
  <url>
    <loc>${siteUrl}${p}</loc>
    <changefreq>daily</changefreq>
    <priority>${p === '' ? '1.0' : '0.8'}</priority>
  </url>`).join('');

    urls += novels.map(n => `
  <url>
    <loc>${siteUrl}/novel/s/${n.slug || n._id}</loc>
    <lastmod>${new Date(n.updatedAt).toISOString().split('T')[0]}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>`).join('');

    urls += chapters.map(ch => {
      const novel = novels.find(n => n._id.toString() === ch.novelId.toString());
      const novelSlug = novel?.slug || ch.novelId;
      return `
  <url>
    <loc>${siteUrl}/read/s/${novelSlug}/chapter-${ch.number}</loc>
    <lastmod>${new Date(ch.updatedAt).toISOString().split('T')[0]}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>`;
    }).join('');

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>`;

    res.header('Content-Type', 'application/xml');
    res.send(xml);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/health', (_, res) => res.json({ status: 'ok', cloudinary: cloudinaryConfigured }));

app.get('/robots.txt', (req, res) => {
  const siteUrl = process.env.CLIENT_URL || 'https://www.idenwebstudio.online';
  res.header('Content-Type', 'text/plain');
  res.send(`User-agent: *\nAllow: /\nSitemap: ${siteUrl}/sitemap.xml\n`);
});

// One-time migration — visit /api/migrate-slugs ONCE after deploying
app.get('/api/migrate-slugs', async (req, res) => {
  try {
    const novels = await Novel.find({ slug: { $in: [null, '', undefined] } });
    if (novels.length === 0) return res.json({ message: 'All novels already have slugs', updated: 0 });
    const results = [];
    for (const novel of novels) {
      const slug = await uniqueSlug(novel.title, novel._id);
      await Novel.updateOne({ _id: novel._id }, { $set: { slug } });
      results.push({ title: novel.title, slug });
    }
    res.json({ message: 'Migration complete', updated: results.length, results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log('idenwebstudio API running on port ' + PORT));
