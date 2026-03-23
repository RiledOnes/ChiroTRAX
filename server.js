require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();

// ============================================
// SECURITY MIDDLEWARE
// ============================================

// Helmet — security headers (relaxed CSP for inline scripts/styles)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      scriptSrcAttr: null  // allow inline event handlers (onclick, onsubmit, etc.)
    }
  }
}));

// CORS — restrict to same origin (Vercel serves frontend + API from same domain)
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || false,
  credentials: true
}));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', apiLimiter);

// Stricter rate limit on auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many login attempts, please try again later.' }
});
app.use('/api/auth/', authLimiter);

app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// ============================================
// SESSION MANAGEMENT (DB-backed for serverless)
// ============================================
const SESSION_TTL = 8 * 60 * 60 * 1000; // 8 hours

async function createSession(email, role) {
  const token = crypto.randomBytes(32).toString('hex');
  await supabase.from('sessions').insert([{ token, email, role }]);
  return token;
}

async function getSession(token) {
  const { data, error } = await supabase
    .from('sessions')
    .select('*')
    .eq('token', token)
    .single();
  if (error || !data) return null;
  if (Date.now() - new Date(data.created_at).getTime() > SESSION_TTL) {
    await supabase.from('sessions').delete().eq('token', token);
    return null;
  }
  return data;
}

async function deleteSession(token) {
  await supabase.from('sessions').delete().eq('token', token);
}

// ============================================
// AUTH MIDDLEWARE
// ============================================
async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: 'Invalid or expired session' });

  req.user = session;
  next();
}

// ============================================
// AUTH ROUTES (public)
// ============================================
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || typeof email !== 'string') {
    return res.status(400).json({ error: 'Valid email required' });
  }

  const trimmed = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  const { data, error } = await supabase
    .from('approved_users')
    .select('email, role, password_hash')
    .eq('email', trimmed)
    .single();

  if (error || !data) {
    return res.status(403).json({ error: 'Invalid email or password' });
  }

  // First-time user — no password set yet
  if (!data.password_hash) {
    return res.status(200).json({ needsPassword: true, email: data.email });
  }

  if (!password) {
    return res.status(400).json({ error: 'Password required' });
  }

  const valid = await bcrypt.compare(password, data.password_hash);
  if (!valid) {
    return res.status(403).json({ error: 'Invalid email or password' });
  }

  const token = await createSession(data.email, data.role);

  res.json({ token, email: data.email, role: data.role });
});

// Set password (first-time setup)
app.post('/api/auth/set-password', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const trimmed = email.trim().toLowerCase();
  const { data, error } = await supabase
    .from('approved_users')
    .select('email, role, password_hash')
    .eq('email', trimmed)
    .single();

  if (error || !data) {
    return res.status(403).json({ error: 'Not an approved user' });
  }
  if (data.password_hash) {
    return res.status(400).json({ error: 'Password already set. Use forgot password to reset.' });
  }

  const hash = await bcrypt.hash(password, 12);
  const { error: updateErr } = await supabase
    .from('approved_users')
    .update({ password_hash: hash })
    .eq('email', trimmed);

  if (updateErr) return res.status(500).json({ error: 'Failed to set password' });

  const token = await createSession(data.email, data.role);

  res.json({ token, email: data.email, role: data.role });
});

// Request password reset (generates a token)
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const trimmed = email.trim().toLowerCase();
  const { data } = await supabase
    .from('approved_users')
    .select('email')
    .eq('email', trimmed)
    .single();

  // Always return success to avoid email enumeration
  if (!data) return res.json({ ok: true });

  const resetToken = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

  await supabase.from('password_resets').insert([{
    email: trimmed,
    token: resetToken,
    expires_at: expiresAt.toISOString()
  }]);

  // Log the reset token (in production, you'd email this)
  console.log(`Password reset token for ${trimmed}: ${resetToken}`);

  res.json({ ok: true });
});

// Reset password with token
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) {
    return res.status(400).json({ error: 'Token and new password required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const { data: reset, error } = await supabase
    .from('password_resets')
    .select('*')
    .eq('token', token)
    .eq('used', false)
    .single();

  if (error || !reset) {
    return res.status(400).json({ error: 'Invalid or expired reset link' });
  }

  if (new Date(reset.expires_at) < new Date()) {
    return res.status(400).json({ error: 'Reset link has expired' });
  }

  const hash = await bcrypt.hash(password, 12);
  const { error: updateErr } = await supabase
    .from('approved_users')
    .update({ password_hash: hash })
    .eq('email', reset.email);

  if (updateErr) return res.status(500).json({ error: 'Failed to reset password' });

  // Mark token as used
  await supabase.from('password_resets').update({ used: true }).eq('id', reset.id);

  res.json({ ok: true });
});

app.post('/api/auth/logout', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) await deleteSession(token);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ email: req.user.email, role: req.user.role });
});

// ============================================
// PROTECT ALL OTHER API ROUTES
// ============================================
app.use('/api', requireAuth);

// ============================================
// HELPER: sanitize Supabase errors
// ============================================
function dbError(res, error) {
  console.error('DB error:', error.message);
  return res.status(400).json({ error: 'A database error occurred. Please try again.' });
}

// ============================================
// PATIENTS
// ============================================

// Get all patients
app.get('/api/patients', async (req, res) => {
  const { data, error } = await supabase
    .from('patients')
    .select('*')
    .order('last_name');
  if (error) return dbError(res, error);
  res.json(data);
});

// Get single patient
app.get('/api/patients/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('patients')
    .select('*, visits(*), diagnoses(*)')
    .eq('id', req.params.id)
    .single();
  if (error) return dbError(res, error);
  res.json(data);
});

// Create patient
app.post('/api/patients', async (req, res) => {
  const { data, error } = await supabase
    .from('patients')
    .insert([req.body])
    .select()
    .single();
  if (error) return dbError(res, error);
  res.json(data);
});

// Update patient
app.put('/api/patients/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('patients')
    .update(req.body)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return dbError(res, error);
  res.json(data);
});

// ============================================
// VISITS (Daily Intake)
// ============================================

// Get all visits (optionally filter by date)
app.get('/api/visits', async (req, res) => {
  let query = supabase
    .from('visits')
    .select('*, patients(patient_code, first_name, last_name)')
    .order('visit_date', { ascending: false });

  if (req.query.date) {
    query = query.eq('visit_date', req.query.date);
  }
  if (req.query.patient_id) {
    query = query.eq('patient_id', req.query.patient_id);
  }

  const { data, error } = await query;
  if (error) return dbError(res, error);
  res.json(data);
});

// Create visit
app.post('/api/visits', async (req, res) => {
  const { data, error } = await supabase
    .from('visits')
    .insert([req.body])
    .select('*, patients(patient_code, first_name, last_name)')
    .single();
  if (error) return dbError(res, error);
  res.json(data);
});

// Update visit
app.put('/api/visits/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('visits')
    .update(req.body)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return dbError(res, error);
  res.json(data);
});

// ============================================
// DIAGNOSES
// ============================================

// Get diagnoses for a patient
app.get('/api/diagnoses/:patient_id', async (req, res) => {
  const { data, error } = await supabase
    .from('diagnoses')
    .select('*')
    .eq('patient_id', req.params.patient_id)
    .order('diagnosed_date', { ascending: false });
  if (error) return dbError(res, error);
  res.json(data);
});

// Create diagnosis
app.post('/api/diagnoses', async (req, res) => {
  const { data, error } = await supabase
    .from('diagnoses')
    .insert([req.body])
    .select()
    .single();
  if (error) return dbError(res, error);
  res.json(data);
});

// Update diagnosis
app.put('/api/diagnoses/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('diagnoses')
    .update(req.body)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return dbError(res, error);
  res.json(data);
});

// ============================================
// CLAIMS
// ============================================

// Get all claims
app.get('/api/claims', async (req, res) => {
  let query = supabase
    .from('claims')
    .select('*, patients(patient_code, first_name, last_name), visits(visit_date)')
    .order('claim_date', { ascending: false });

  if (req.query.status) {
    query = query.eq('claim_status', req.query.status);
  }

  const { data, error } = await query;
  if (error) return dbError(res, error);
  res.json(data);
});

// Create claim from visit
app.post('/api/claims', async (req, res) => {
  const { data, error } = await supabase
    .from('claims')
    .insert([req.body])
    .select()
    .single();
  if (error) return dbError(res, error);
  res.json(data);
});

// Update claim status
app.put('/api/claims/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('claims')
    .update(req.body)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return dbError(res, error);
  res.json(data);
});

// ============================================
// INTAKE RECORDS (Bulk Upload + Workflow)
// ============================================

// Get all intake records (optionally filter by workflow_status or batch_id)
app.get('/api/intake', async (req, res) => {
  let query = supabase
    .from('intake_records')
    .select('*')
    .order('service_date', { ascending: false })
    .order('intake_id', { ascending: true });

  if (req.query.workflow_status) {
    query = query.eq('workflow_status', req.query.workflow_status);
  }
  if (req.query.batch_id) {
    query = query.eq('batch_id', req.query.batch_id);
  }

  const { data, error } = await query;
  if (error) return dbError(res, error);
  res.json(data);
});

// Get workflow counts (how many records at each stage)
app.get('/api/intake/workflow-counts', async (req, res) => {
  const stages = ['intake', 'entered_ebs', 'claim_created', 'submitted', 'processed'];
  const counts = {};
  for (const stage of stages) {
    const { count, error } = await supabase
      .from('intake_records')
      .select('*', { count: 'exact', head: true })
      .eq('workflow_status', stage);
    if (error) return dbError(res, error);
    counts[stage] = count;
  }
  res.json(counts);
});

// Bulk upload intake records
app.post('/api/intake/bulk', async (req, res) => {
  const { records, batch_id } = req.body;
  if (!records || !Array.isArray(records) || records.length === 0) {
    return res.status(400).json({ error: 'No records provided' });
  }

  if (records.length > 500) {
    return res.status(400).json({ error: 'Maximum 500 records per upload' });
  }

  // Check for existing intake_ids to prevent duplicates
  const incomingIds = records.map(r => r.intake_id);
  const { data: existing, error: checkErr } = await supabase
    .from('intake_records')
    .select('intake_id')
    .in('intake_id', incomingIds);

  if (checkErr) return dbError(res, checkErr);

  const existingIds = new Set((existing || []).map(e => e.intake_id));
  const newRecords = records.filter(r => !existingIds.has(r.intake_id));
  const duplicates = records.filter(r => existingIds.has(r.intake_id));

  if (newRecords.length === 0) {
    return res.json({
      inserted: 0,
      duplicates: duplicates.length,
      duplicate_ids: duplicates.map(d => d.intake_id),
      message: 'All records already exist — nothing imported.'
    });
  }

  // Try to match patient_code to existing patients
  for (const rec of newRecords) {
    if (rec.patient_code) {
      const { data: pat } = await supabase
        .from('patients')
        .select('id')
        .eq('patient_code', rec.patient_code)
        .single();
      if (pat) rec.patient_id = pat.id;
    }
    rec.batch_id = batch_id || null;
  }

  const { data, error } = await supabase
    .from('intake_records')
    .insert(newRecords)
    .select();

  if (error) return dbError(res, error);

  res.json({
    inserted: data.length,
    duplicates: duplicates.length,
    duplicate_ids: duplicates.map(d => d.intake_id),
    data
  });
});

// Update single intake record
app.put('/api/intake/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('intake_records')
    .update(req.body)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return dbError(res, error);
  res.json(data);
});

// Batch advance workflow status
app.put('/api/intake/batch-advance', async (req, res) => {
  const { ids, new_status } = req.body;
  if (!ids || !Array.isArray(ids) || !new_status) {
    return res.status(400).json({ error: 'ids array and new_status are required' });
  }
  const validStatuses = ['intake', 'entered_ebs', 'claim_created', 'submitted', 'processed'];
  if (!validStatuses.includes(new_status)) {
    return res.status(400).json({ error: 'Invalid workflow status' });
  }
  const { data, error } = await supabase
    .from('intake_records')
    .update({ workflow_status: new_status })
    .in('id', ids)
    .select();
  if (error) return dbError(res, error);
  res.json({ updated: data.length, data });
});

// SPA fallback — serve index.html for non-API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================
// START SERVER
// ============================================
const PORT = process.env.PORT || 3000;
if (process.env.VERCEL !== '1') {
  app.listen(PORT, () => {
    console.log(`ChiroTrax running on http://localhost:${PORT}`);
  });
}

module.exports = app;
