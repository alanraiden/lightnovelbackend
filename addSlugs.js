// Run once: node addSlugs.js
// Adds slugs to all existing novels that don't have one
require('dotenv').config();
const mongoose = require('mongoose');

function makeSlug(title) {
  return title.toLowerCase().trim()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

mongoose.connect(process.env.MONGODB_URI).then(async () => {
  const Novel = mongoose.model('Novel', new mongoose.Schema({
    title: String, slug: String
  }));

  const novels = await Novel.find({ slug: { $in: [null, '', undefined] } });
  console.log('Found', novels.length, 'novels without slugs');

  for (const novel of novels) {
    let slug = makeSlug(novel.title);
    // Check for duplicates
    let existing = await Novel.findOne({ slug, _id: { $ne: novel._id } });
    let i = 2;
    while (existing) {
      slug = makeSlug(novel.title) + '-' + i;
      existing = await Novel.findOne({ slug, _id: { $ne: novel._id } });
      i++;
    }
    await Novel.updateOne({ _id: novel._id }, { $set: { slug } });
    console.log(`  ${novel.title}  →  ${slug}`);
  }

  console.log('Done!');
  process.exit(0);
}).catch(err => { console.error(err); process.exit(1); });
