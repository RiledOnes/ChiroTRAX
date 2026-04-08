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
      imgSrc: ["'self'", "data:", "blob:"],
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
  max: 100,
  message: { error: 'Too many login attempts, please try again later.' }
});
app.use('/api/auth/', authLimiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Supabase client — use service_role key for server-side (bypasses RLS)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY
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

  console.log('LOGIN ATTEMPT:', trimmed, 'found:', !!data, 'error:', error?.message, 'has_hash:', !!data?.password_hash, 'hash_len:', data?.password_hash?.length);

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
  console.log('LOGIN BCRYPT:', 'password_len:', password.length, 'valid:', valid);
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

// Request access (public — no auth required)
app.post('/api/auth/request-access', async (req, res) => {
  const { name, email } = req.body;
  if (!email || !name) return res.status(400).json({ error: 'Name and email required' });

  const trimmed = email.trim().toLowerCase();

  // Check if already approved
  const { data: existing } = await supabase
    .from('approved_users')
    .select('email')
    .eq('email', trimmed)
    .single();
  if (existing) return res.status(400).json({ error: 'This email already has access. Try signing in.' });

  // Check if already requested
  const { data: pending } = await supabase
    .from('access_requests')
    .select('id')
    .eq('email', trimmed)
    .eq('status', 'pending')
    .single();
  if (pending) return res.status(400).json({ error: 'Access request already pending. Please wait for approval.' });

  // Create request
  const { error } = await supabase
    .from('access_requests')
    .insert([{ name: name.trim(), email: trimmed, status: 'pending' }]);
  if (error) return res.status(500).json({ error: 'Failed to submit request' });

  // TODO: Send email notification to admin
  console.log(`ACCESS REQUEST: ${name.trim()} (${trimmed}) — needs approval`);

  res.json({ ok: true });
});

// Get pending access requests (admin only)
app.get('/api/auth/access-requests', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('access_requests')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });
  res.json(data || []);
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
// ADMIN: Approve/deny access requests (protected)
// ============================================
app.post('/api/auth/approve-access', async (req, res) => {
  const { request_id, action } = req.body;
  if (!request_id || !action) return res.status(400).json({ error: 'request_id and action required' });

  const { data: request, error: fetchErr } = await supabase
    .from('access_requests')
    .select('*')
    .eq('id', request_id)
    .single();
  if (fetchErr || !request) return res.status(404).json({ error: 'Request not found' });

  if (action === 'approve') {
    // Create approved_users entry
    const { error: insertErr } = await supabase
      .from('approved_users')
      .insert([{ email: request.email, role: 'staff' }]);
    if (insertErr) return res.status(500).json({ error: 'Failed to create user' });

    await supabase.from('access_requests')
      .update({ status: 'approved', reviewed_at: new Date().toISOString() })
      .eq('id', request_id);

    res.json({ ok: true, message: `${request.email} approved` });
  } else if (action === 'deny') {
    await supabase.from('access_requests')
      .update({ status: 'denied', reviewed_at: new Date().toISOString() })
      .eq('id', request_id);
    res.json({ ok: true, message: `${request.email} denied` });
  } else {
    res.status(400).json({ error: 'action must be approve or deny' });
  }
});

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
    .select('*, intake_records(*), diagnoses(*)')
    .eq('id', req.params.id)
    .single();
  if (error) return dbError(res, error);
  // Map intake_records to visits for frontend compatibility
  data.visits = (data.intake_records || []).map(r => ({
    ...r,
    visit_date: r.service_date,
    patient_status: r.visit_status,
    diagnosis_codes: Array.isArray(r.diagnosis_codes) ? r.diagnosis_codes.join(', ') : r.diagnosis_codes,
    office_visit: r.cpt_office_visit
  }));
  delete data.intake_records;
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
// VISITS (Daily Intake) — reads from intake_records
// ============================================

// Get all visits (optionally filter by date, patient, workflow_status, batch_id)
app.get('/api/visits', async (req, res) => {
  let query = supabase
    .from('intake_records')
    .select('*, patients(patient_code, first_name, last_name)')
    .order('service_date', { ascending: false })
    .order('created_at', { ascending: true });

  if (req.query.date) {
    // Show records where the sheet_date (intake day) OR service_date matches
    query = query.or(`sheet_date.eq.${req.query.date},service_date.eq.${req.query.date}`);
  }
  if (req.query.patient_id) {
    query = query.eq('patient_id', req.query.patient_id);
  }
  if (req.query.workflow_status) {
    query = query.eq('workflow_status', req.query.workflow_status);
  }
  if (req.query.batch_id) {
    query = query.eq('batch_id', req.query.batch_id);
  }

  const { data, error } = await query;
  if (error) return dbError(res, error);
  // Map intake_records fields to match frontend expectations
  const mapped = (data || []).map(r => ({
    ...r,
    visit_date: r.service_date,
    patient_status: r.visit_status,
    diagnosis_codes: Array.isArray(r.diagnosis_codes) ? r.diagnosis_codes.join(', ') : r.diagnosis_codes,
    office_visit: r.cpt_office_visit
  }));
  res.json(mapped);
});

// Create visit
app.post('/api/visits', async (req, res) => {
  // Map incoming frontend fields to intake_records columns
  const body = { ...req.body };
  if (body.visit_date) { body.service_date = body.visit_date; delete body.visit_date; }
  if (body.patient_status) { body.visit_status = body.patient_status; delete body.patient_status; }
  if (body.office_visit) { body.cpt_office_visit = body.office_visit; delete body.office_visit; }
  // Auto-generate intake_id if not provided (MMDDYY_NN format based on sheet_date or service_date)
  if (!body.intake_id) {
    const idDate = body.sheet_date || body.service_date;
    if (idDate) {
      const d = new Date(idDate + 'T12:00:00');
      const prefix = String(d.getMonth()+1).padStart(2,'0') + String(d.getDate()).padStart(2,'0') + String(d.getFullYear()).slice(-2);
      const { count } = await supabase.from('intake_records').select('*', { count: 'exact', head: true }).eq('sheet_date', idDate);
      body.intake_id = `${prefix}_${String((count || 0) + 1).padStart(2, '0')}`;
    }
  }
  if (!body.patient_name && body.patient_id) {
    // Look up patient name for intake_records
    const { data: pat } = await supabase.from('patients').select('first_name, last_name').eq('id', body.patient_id).single();
    if (pat) body.patient_name = `${pat.first_name} ${pat.last_name}`.trim();
  }
  if (!body.patient_name) body.patient_name = 'Unknown';
  // Convert diagnosis_codes string to array if needed
  if (body.diagnosis_codes && typeof body.diagnosis_codes === 'string') {
    body.diagnosis_codes = body.diagnosis_codes.split(',').map(s => s.trim()).filter(Boolean);
  }
  // Strip fields that don't exist in intake_records
  delete body.insurance_provider;
  delete body.amount_billed;

  const { data, error } = await supabase
    .from('intake_records')
    .insert([body])
    .select('*, patients(patient_code, first_name, last_name)')
    .single();
  if (error) return dbError(res, error);
  // Map back
  data.visit_date = data.service_date;
  data.patient_status = data.visit_status;
  data.office_visit = data.cpt_office_visit;
  if (Array.isArray(data.diagnosis_codes)) data.diagnosis_codes = data.diagnosis_codes.join(', ');
  res.json(data);
});

// Update visit
app.put('/api/visits/:id', async (req, res) => {
  const body = { ...req.body };
  const changedBy = body.changed_by || req.user?.email || 'system';
  delete body.changed_by;
  if (body.visit_date) { body.service_date = body.visit_date; delete body.visit_date; }
  if (body.patient_status) { body.visit_status = body.patient_status; delete body.patient_status; }
  if (body.office_visit) { body.cpt_office_visit = body.office_visit; delete body.office_visit; }
  // Convert diagnosis_codes string to array if needed
  if (body.diagnosis_codes && typeof body.diagnosis_codes === 'string') {
    body.diagnosis_codes = body.diagnosis_codes.split(',').map(s => s.trim()).filter(Boolean);
  }
  // Strip fields that don't exist in intake_records
  delete body.insurance_provider;
  delete body.amount_billed;

  const { data, error } = await supabase
    .from('intake_records')
    .update(body)
    .eq('id', req.params.id)
    .select()
    .single();

  // Update changed_by on status history entries that don't have it set
  if (!error && data) {
    await supabase.from('intake_status_history')
      .update({ changed_by: changedBy })
      .eq('intake_record_id', req.params.id)
      .is('changed_by', null);
  }
  if (error) return dbError(res, error);
  data.visit_date = data.service_date;
  data.patient_status = data.visit_status;
  data.office_visit = data.cpt_office_visit;
  if (Array.isArray(data.diagnosis_codes)) data.diagnosis_codes = data.diagnosis_codes.join(', ');
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
    .select('*, patients(patient_code, first_name, last_name)')
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
// STATUS HISTORY
// ============================================

app.get('/api/intake/:id/status-history', async (req, res) => {
  const { data, error } = await supabase
    .from('intake_status_history')
    .select('*')
    .eq('intake_record_id', req.params.id)
    .order('changed_at', { ascending: false });
  if (error) return dbError(res, error);
  res.json(data || []);
});

// ============================================
// BILLING REPORTS
// ============================================

app.get('/api/billing-reports', async (req, res) => {
  let query = supabase
    .from('billing_reports')
    .select('*')
    .order('service_date', { ascending: false });

  if (req.query.period) query = query.eq('report_period', req.query.period);
  if (req.query.patient_id) query = query.eq('patient_id', req.query.patient_id);

  const { data, error } = await query;
  if (error) return dbError(res, error);
  res.json(data);
});

app.get('/api/billing-reports/periods', async (req, res) => {
  const { data, error } = await supabase.from('billing_reports').select('report_period');
  if (error) return dbError(res, error);
  const periods = [...new Set((data || []).map(d => d.report_period).filter(Boolean))].sort().reverse();
  res.json(periods);
});

app.post('/api/billing-reports/upload', async (req, res) => {
  const { records, report_period } = req.body;
  if (!records || !Array.isArray(records) || records.length === 0) {
    return res.status(400).json({ error: 'No records provided' });
  }

  // Try to match patients by name
  for (const rec of records) {
    if (!rec.patient_id && rec.patient_last_name && rec.patient_first_name) {
      const { data: pat } = await supabase
        .from('patients')
        .select('id')
        .ilike('last_name', rec.patient_last_name.trim())
        .ilike('first_name', rec.patient_first_name.trim())
        .single();
      if (pat) rec.patient_id = pat.id;
    }
    if (report_period) rec.report_period = report_period;
  }

  const { data, error } = await supabase
    .from('billing_reports')
    .insert(records)
    .select();
  if (error) return dbError(res, error);

  // Auto-update intake_records with claim_number where possible
  for (const br of (data || [])) {
    if (br.claim_number && br.patient_id && br.service_date) {
      await supabase.from('intake_records')
        .update({ claim_number: br.claim_number })
        .eq('patient_id', br.patient_id)
        .eq('service_date', br.service_date)
        .is('claim_number', null);
    }
  }

  res.json({ inserted: (data || []).length, data });
});

// ============================================
// VISITS — BULK UPLOAD + WORKFLOW
// ============================================

// Get workflow counts (how many records at each stage)
app.get('/api/visits/workflow-counts', async (req, res) => {
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

// Bulk upload intake records from CSV
app.post('/api/visits/bulk', async (req, res) => {
  const { records, batch_id } = req.body;
  if (!records || !Array.isArray(records) || records.length === 0) {
    return res.status(400).json({ error: 'No records provided' });
  }

  if (records.length > 500) {
    return res.status(400).json({ error: 'Maximum 500 records per upload' });
  }

  // Check for existing intake_ids to prevent duplicates
  const incomingIds = records.map(r => r.intake_id).filter(Boolean);
  let existingIds = new Set();
  if (incomingIds.length > 0) {
    const { data: existing, error: checkErr } = await supabase
      .from('intake_records')
      .select('intake_id')
      .in('intake_id', incomingIds);
    if (checkErr) return dbError(res, checkErr);
    existingIds = new Set((existing || []).map(e => e.intake_id));
  }

  const newRecords = records.filter(r => !r.intake_id || !existingIds.has(r.intake_id));
  const duplicates = records.filter(r => r.intake_id && existingIds.has(r.intake_id));

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
        .select('id, first_name, last_name')
        .eq('patient_code', rec.patient_code)
        .single();
      if (pat) {
        rec.patient_id = pat.id;
        if (!rec.patient_name) rec.patient_name = `${pat.first_name} ${pat.last_name}`.trim();
      }
    }
    // Map visit_date → service_date if provided
    if (rec.visit_date) {
      rec.service_date = rec.visit_date;
      delete rec.visit_date;
    }
    // Ensure patient_name is set (required column)
    if (!rec.patient_name) rec.patient_name = 'Unknown';
    rec.batch_id = batch_id || null;
  }

  const { data, error } = await supabase
    .from('intake_records')
    .insert(newRecords)
    .select('*, patients(patient_code, first_name, last_name)');

  if (error) return dbError(res, error);

  // Map back for frontend
  const mapped = (data || []).map(r => ({
    ...r,
    visit_date: r.service_date,
    patient_status: r.visit_status,
    diagnosis_codes: Array.isArray(r.diagnosis_codes) ? r.diagnosis_codes.join(', ') : r.diagnosis_codes,
    office_visit: r.cpt_office_visit
  }));

  res.json({
    inserted: mapped.length,
    duplicates: duplicates.length,
    duplicate_ids: duplicates.map(d => d.intake_id),
    data: mapped
  });
});

// Batch advance workflow status
app.put('/api/visits/batch-advance', async (req, res) => {
  const { ids, new_status, changed_by } = req.body;
  if (!ids || !Array.isArray(ids) || !new_status) {
    return res.status(400).json({ error: 'ids array and new_status are required' });
  }
  const validStatuses = ['intake', 'entered_ebs', 'claim_created', 'submitted', 'processed', 'payment_received', 'payment_partial', 'denied', 'denied_resubmitted', 'closed', 'already_entered'];
  if (!validStatuses.includes(new_status)) {
    return res.status(400).json({ error: 'Invalid workflow status' });
  }
  const { data, error } = await supabase
    .from('intake_records')
    .update({ workflow_status: new_status })
    .in('id', ids)
    .select();
  if (error) return dbError(res, error);

  // Tag status history with changed_by
  const user = changed_by || req.user?.email || 'system';
  for (const id of ids) {
    await supabase.from('intake_status_history')
      .update({ changed_by: user })
      .eq('intake_record_id', id)
      .is('changed_by', null);
  }

  res.json({ updated: data.length, data });
});

// ============================================
// DAILY INTAKE IMAGES
// ============================================

// Get images for a business date
app.get('/api/intake-images', async (req, res) => {
  let query = supabase
    .from('daily_intake_images')
    .select('id, business_date, file_name, image_tag, notes, uploaded_by, created_at')
    .order('business_date', { ascending: false })
    .order('created_at', { ascending: true });

  if (req.query.date) {
    query = query.eq('business_date', req.query.date);
  }
  if (req.query.from && req.query.to) {
    query = query.gte('business_date', req.query.from).lte('business_date', req.query.to);
  }

  const { data, error } = await query;
  if (error) return dbError(res, error);
  res.json(data);
});

// Get dates that have images (must be before :id route)
app.get('/api/intake-images/dates/list', async (req, res) => {
  const { data, error } = await supabase
    .from('daily_intake_images')
    .select('business_date');
  if (error) return dbError(res, error);
  const dates = [...new Set(data.map(d => d.business_date))].sort().reverse();
  res.json(dates);
});

// Get single image with data
app.get('/api/intake-images/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('daily_intake_images')
    .select('*')
    .eq('id', req.params.id)
    .single();
  if (error) return dbError(res, error);
  res.json(data);
});

// Upload images for a business date
app.post('/api/intake-images', async (req, res) => {
  const { business_date, images } = req.body;
  if (!business_date || !images || !Array.isArray(images) || images.length === 0) {
    return res.status(400).json({ error: 'business_date and images array required' });
  }
  if (images.length > 20) {
    return res.status(400).json({ error: 'Maximum 20 images per upload' });
  }

  const records = images.map(img => ({
    business_date,
    file_name: img.file_name || 'intake.jpg',
    image_data: img.image_data,
    image_tag: img.image_tag || 'intake_form',
    notes: img.notes || null,
    uploaded_by: req.user.email
  }));

  const { data, error } = await supabase
    .from('daily_intake_images')
    .insert(records)
    .select('id, business_date, file_name, image_tag, notes, uploaded_by, created_at');
  if (error) return dbError(res, error);
  res.json({ inserted: data.length, data });
});

// Update image tag
app.patch('/api/intake-images/:id', async (req, res) => {
  const updates = {};
  if (req.body.image_tag) updates.image_tag = req.body.image_tag;
  if (req.body.notes !== undefined) updates.notes = req.body.notes;
  if (!Object.keys(updates).length) return res.status(400).json({ error: 'Nothing to update' });

  const { data, error } = await supabase
    .from('daily_intake_images')
    .update(updates)
    .eq('id', req.params.id)
    .select('id, image_tag, notes')
    .single();
  if (error) return dbError(res, error);
  res.json(data);
});

// Delete an image
app.delete('/api/intake-images/:id', async (req, res) => {
  const { error } = await supabase
    .from('daily_intake_images')
    .delete()
    .eq('id', req.params.id);
  if (error) return dbError(res, error);
  res.json({ ok: true });
});


// ============================================
// TASKS
// ============================================

// Get all tasks (optionally filter by status)
app.get('/api/tasks', async (req, res) => {
  let query = supabase
    .from('tasks')
    .select('*')
    .order('status', { ascending: true })
    .order('priority', { ascending: true })
    .order('due_date', { ascending: true, nullsFirst: false })
    .order('created_at', { ascending: false });

  if (req.query.status) {
    query = query.eq('status', req.query.status);
  }

  const { data, error } = await query;
  if (error) return dbError(res, error);
  res.json(data);
});

// Create task
app.post('/api/tasks', async (req, res) => {
  const { title, description, assigned_by, assigned_to, priority, due_date } = req.body;
  if (!title || !title.trim()) {
    return res.status(400).json({ error: 'Task title is required' });
  }
  const record = {
    title: title.trim(),
    description: description?.trim() || null,
    assigned_by: assigned_by?.trim() || null,
    assigned_to: assigned_to?.trim() || null,
    priority: priority || 'normal',
    due_date: due_date || null,
    status: 'todo',
    created_by: req.user.email
  };
  const { data, error } = await supabase
    .from('tasks')
    .insert([record])
    .select()
    .single();
  if (error) return dbError(res, error);
  res.json(data);
});

// Update task
app.put('/api/tasks/:id', async (req, res) => {
  const updates = { ...req.body };
  // Auto-set completed_at when marking done
  if (updates.status === 'done' && !updates.completed_at) {
    updates.completed_at = new Date().toISOString();
  }
  if (updates.status && updates.status !== 'done') {
    updates.completed_at = null;
  }
  const { data, error } = await supabase
    .from('tasks')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return dbError(res, error);
  res.json(data);
});

// Delete task
app.delete('/api/tasks/:id', async (req, res) => {
  const { error } = await supabase
    .from('tasks')
    .delete()
    .eq('id', req.params.id);
  if (error) return dbError(res, error);
  res.json({ ok: true });
});

// ============================================
// REPORTS
// ============================================

app.get('/api/reports/summary', async (req, res) => {
  const from = req.query.from || new Date(new Date().setDate(new Date().getDate() - 30)).toISOString().split('T')[0];
  const to = req.query.to || new Date().toISOString().split('T')[0];

  try {
    let visitQuery = supabase.from('intake_records').select('id, service_date, sheet_date, visit_status, manipulation_type, therapeutic_exercises, patient_id, patient_name, patient_code, is_backdated, new_patient, returning_patient, no_fault, workflow_status, diagnosis_category, cpt_manipulation, cpt_te').gte('service_date', from).lte('service_date', to);
    if (req.query.patient_id) {
      visitQuery = visitQuery.eq('patient_id', req.query.patient_id);
    }
    const [visits, patients, claims, intakeImages] = await Promise.all([
      visitQuery,
      supabase.from('patients').select('id, patient_code, first_name, last_name, payment_type, created_at'),
      supabase.from('claims').select('id, claim_status, payment_type, amount_billed, amount_paid, claim_date').gte('claim_date', from).lte('claim_date', to),
      supabase.from('daily_intake_images').select('id, business_date').gte('business_date', from).lte('business_date', to)
    ]);

    const v = visits.data || [];
    const p = patients.data || [];
    const c = claims.data || [];
    const img = intakeImages.data || [];

    // Visit stats
    const totalVisits = v.length;
    const uniquePatientVisits = new Set(v.map(x => x.patient_id)).size;
    const newPatientVisits = v.filter(x => x.new_patient).length;
    const returningVisits = v.filter(x => x.returning_patient).length;
    const e1Count = v.filter(x => x.manipulation_type === 'E1').length;
    const e2Count = v.filter(x => x.manipulation_type === 'E2').length;
    const avgExercises = v.length ? (v.reduce((sum, x) => sum + (x.therapeutic_exercises || 0), 0) / v.length).toFixed(1) : 0;
    const backdatedCount = v.filter(x => x.is_backdated).length;
    const noFaultCount = v.filter(x => x.no_fault).length;

    // Visits by date
    const visitsByDate = {};
    v.forEach(x => { visitsByDate[x.service_date] = (visitsByDate[x.service_date] || 0) + 1; });

    // Workflow pipeline counts
    const workflowCounts = {};
    v.forEach(x => { const s = x.workflow_status || 'intake'; workflowCounts[s] = (workflowCounts[s] || 0) + 1; });

    // Diagnosis category breakdown
    const dxCategories = {};
    v.forEach(x => { const cat = x.diagnosis_category || 'Unset'; dxCategories[cat] = (dxCategories[cat] || 0) + 1; });

    // Top patients by visit count
    const patientVisitMap = {};
    v.forEach(x => {
      const key = x.patient_id || x.patient_name;
      if (!patientVisitMap[key]) patientVisitMap[key] = { name: x.patient_name || '—', code: x.patient_code || '—', visits: 0, e1: 0, e2: 0 };
      patientVisitMap[key].visits++;
      if (x.manipulation_type === 'E1') patientVisitMap[key].e1++;
      if (x.manipulation_type === 'E2') patientVisitMap[key].e2++;
    });
    const topPatients = Object.values(patientVisitMap).sort((a, b) => b.visits - a.visits).slice(0, 15);

    // Visits by sheet_date (intake days)
    const visitsBySheetDate = {};
    v.forEach(x => { if (x.sheet_date) visitsBySheetDate[x.sheet_date] = (visitsBySheetDate[x.sheet_date] || 0) + 1; });

    // Claim stats
    const totalBilled = c.reduce((sum, x) => sum + (parseFloat(x.amount_billed) || 0), 0);
    const totalPaid = c.reduce((sum, x) => sum + (parseFloat(x.amount_paid) || 0), 0);
    const claimsByStatus = {};
    c.forEach(x => { claimsByStatus[x.claim_status] = (claimsByStatus[x.claim_status] || 0) + 1; });

    // Patient stats
    const totalPatients = p.length;
    const insurancePatients = p.filter(x => x.payment_type === 'insurance').length;
    const cashPatients = p.filter(x => x.payment_type === 'cash').length;
    const newPatientsInRange = p.filter(x => x.created_at >= from && x.created_at <= to + 'T23:59:59').length;

    // Images count
    const totalImages = img.length;
    const imageDays = new Set(img.map(x => x.business_date)).size;

    res.json({
      period: { from, to },
      visits: {
        total: totalVisits,
        uniquePatients: uniquePatientVisits,
        newPatients: newPatientVisits,
        returning: returningVisits,
        e1: e1Count,
        e2: e2Count,
        avgExercises: parseFloat(avgExercises),
        backdated: backdatedCount,
        noFault: noFaultCount,
        byDate: visitsByDate,
        bySheetDate: visitsBySheetDate
      },
      workflow: workflowCounts,
      dxCategories,
      topPatients,
      claims: {
        total: c.length,
        totalBilled,
        totalPaid,
        outstanding: totalBilled - totalPaid,
        byStatus: claimsByStatus
      },
      patients: {
        total: totalPatients,
        insurance: insurancePatients,
        cash: cashPatients,
        newInPeriod: newPatientsInRange
      },
      images: {
        total: totalImages,
        daysWithImages: imageDays
      }
    });
  } catch (e) {
    console.error('Report error:', e);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

// ============================================
// REPORTING ENGINE
// ============================================

// Helper: group records by a key and compute subtotals
function groupRecords(records, groupBy, reportType) {
  if (groupBy === 'none' || !groupBy) {
    return [{ label: 'All', subtotals: computeSubtotals(records, reportType), records }];
  }

  const grouped = {};
  for (const rec of records) {
    let key;
    switch (groupBy) {
      case 'patient':
        key = rec.patient_name || (rec.patient_last_name ? `${rec.patient_last_name}, ${rec.patient_first_name}` : null) || rec.patient_id || 'Unknown';
        break;
      case 'service_date':
        key = rec.service_date || 'No date';
        break;
      case 'week': {
        const d = rec.service_date ? new Date(rec.service_date) : null;
        if (d && !isNaN(d)) {
          const day = d.getUTCDay();
          const monday = new Date(d);
          monday.setUTCDate(d.getUTCDate() - ((day + 6) % 7));
          key = monday.toISOString().slice(0, 10);
        } else {
          key = 'No date';
        }
        break;
      }
      case 'month':
        key = rec.service_date ? rec.service_date.slice(0, 7) : 'No date';
        break;
      case 'diagnosis_category':
        key = rec.diagnosis_category || 'Uncategorized';
        break;
      case 'manipulation_type':
        key = rec.manipulation_type || 'None';
        break;
      case 'workflow_status':
        key = rec.workflow_status || 'Unknown';
        break;
      case 'insurance_name':
        key = rec.insurance_name || 'Unknown';
        break;
      default:
        key = 'All';
    }
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(rec);
  }

  return Object.entries(grouped)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([label, recs]) => ({
      label,
      subtotals: computeSubtotals(recs, reportType),
      records: recs
    }));
}

// Helper: compute subtotals for a set of records
function computeSubtotals(records, reportType) {
  const totals = { count: records.length };

  if (reportType === 'payment_summary') {
    totals.total_charge = records.reduce((s, r) => s + (parseFloat(r.charge) || 0), 0);
    totals.total_approved = records.reduce((s, r) => s + (parseFloat(r.approved) || 0), 0);
    totals.total_pri_ins = records.reduce((s, r) => s + (parseFloat(r.pri_ins_received) || 0), 0);
    totals.total_sec_ins = records.reduce((s, r) => s + (parseFloat(r.sec_ins_received) || 0), 0);
    totals.total_patient = records.reduce((s, r) => s + (parseFloat(r.patient_received) || 0), 0);
    totals.total_received = totals.total_pri_ins + totals.total_sec_ins + totals.total_patient;
    totals.total_outstanding = totals.total_charge - totals.total_received;
  } else if (reportType === 'outstanding_claims') {
    const now = new Date();
    totals.aging = { '0-30': 0, '31-60': 0, '61-90': 0, '90+': 0 };
    for (const r of records) {
      const sd = r.service_date ? new Date(r.service_date) : null;
      if (!sd || isNaN(sd)) continue;
      const days = Math.floor((now - sd) / (1000 * 60 * 60 * 24));
      if (days <= 30) totals.aging['0-30']++;
      else if (days <= 60) totals.aging['31-60']++;
      else if (days <= 90) totals.aging['61-90']++;
      else totals.aging['90+']++;
    }
  } else if (reportType === 'reconciliation') {
    totals.total_records = records.length;
    totals.on_intake = records.filter(r => r.on_intake).length;
    totals.in_charge_capture = records.filter(r => r.in_charge_capture).length;
    totals.has_claim = records.filter(r => r.claim_number).length;
    totals.in_billing = records.filter(r => r.in_billing_report).length;
    totals.missing_capture = records.filter(r => !r.in_charge_capture).length;
    totals.missing_claim = records.filter(r => !r.claim_number).length;
    totals.missing_billing = records.filter(r => !r.in_billing_report).length;
    totals.total_billing_amount = records.reduce((s, r) => s + (r.billing_amount || 0), 0);
  } else {
    totals.new_patients = records.filter(r => r.new_patient).length;
    totals.returning_patients = records.filter(r => r.returning_patient).length;
    totals.no_fault = records.filter(r => r.no_fault).length;
    const uniquePatients = new Set(records.map(r => r.patient_id).filter(Boolean));
    totals.unique_patients = uniquePatients.size;
  }
  return totals;
}

// Helper: apply common date and field filters to a supabase query
function applyIntakeFilters(query, filters) {
  if (!filters) return query;
  if (filters.from) query = query.gte('service_date', filters.from);
  if (filters.to) query = query.lte('service_date', filters.to);
  if (filters.patient_id) query = query.eq('patient_id', filters.patient_id);
  if (filters.diagnosis_category) query = query.eq('diagnosis_category', filters.diagnosis_category);
  if (filters.workflow_status) query = query.eq('workflow_status', filters.workflow_status);
  if (filters.manipulation_type) query = query.eq('manipulation_type', filters.manipulation_type);
  return query;
}

// POST /api/reports/run — unified report runner
app.post('/api/reports/run', async (req, res) => {
  try {
    const { report_type, filters = {}, group_by = 'none' } = req.body;
    if (!report_type) return res.status(400).json({ error: 'report_type is required' });

    let records = [];

    switch (report_type) {
      case 'patient_visits': {
        let query = supabase.from('intake_records').select('*').order('service_date', { ascending: false });
        query = applyIntakeFilters(query, filters);
        const { data, error } = await query;
        if (error) return dbError(res, error);
        records = data || [];
        break;
      }

      case 'claims_by_diagnosis': {
        let query = supabase.from('intake_records').select('*').order('service_date', { ascending: false });
        query = applyIntakeFilters(query, filters);
        const { data, error } = await query;
        if (error) return dbError(res, error);
        records = data || [];
        // Default group_by to diagnosis_category if none specified
        if (group_by === 'none') {
          const groups = groupRecords(records, 'diagnosis_category', report_type);
          const summary = computeSubtotals(records, report_type);
          return res.json({ summary, groups });
        }
        break;
      }

      case 'outstanding_claims': {
        let query = supabase.from('intake_records').select('*')
          .not('workflow_status', 'in', '("closed","payment_received")')
          .order('service_date', { ascending: true });
        if (filters.from) query = query.gte('service_date', filters.from);
        if (filters.to) query = query.lte('service_date', filters.to);
        if (filters.patient_id) query = query.eq('patient_id', filters.patient_id);
        if (filters.diagnosis_category) query = query.eq('diagnosis_category', filters.diagnosis_category);
        if (filters.manipulation_type) query = query.eq('manipulation_type', filters.manipulation_type);
        const { data, error } = await query;
        if (error) return dbError(res, error);
        records = data || [];
        break;
      }

      case 'payment_summary': {
        let query = supabase.from('billing_reports').select('*').order('service_date', { ascending: false });
        if (filters.from) query = query.gte('service_date', filters.from);
        if (filters.to) query = query.lte('service_date', filters.to);
        if (filters.patient_id) query = query.eq('patient_id', filters.patient_id);
        const { data, error } = await query;
        if (error) return dbError(res, error);
        records = data || [];
        break;
      }

      case 'daily_intake': {
        let query = supabase.from('intake_records').select('*').order('service_date', { ascending: false });
        query = applyIntakeFilters(query, filters);
        const { data, error } = await query;
        if (error) return dbError(res, error);
        records = data || [];
        // Default group_by to service_date if none specified
        if (group_by === 'none') {
          const groups = groupRecords(records, 'service_date', report_type);
          const summary = computeSubtotals(records, report_type);
          return res.json({ summary, groups });
        }
        break;
      }

      case 'denials': {
        let query = supabase.from('intake_records').select('*')
          .in('workflow_status', ['denied', 'denied_resubmitted'])
          .order('service_date', { ascending: false });
        if (filters.from) query = query.gte('service_date', filters.from);
        if (filters.to) query = query.lte('service_date', filters.to);
        if (filters.patient_id) query = query.eq('patient_id', filters.patient_id);
        if (filters.diagnosis_category) query = query.eq('diagnosis_category', filters.diagnosis_category);
        if (filters.manipulation_type) query = query.eq('manipulation_type', filters.manipulation_type);
        const { data, error } = await query;
        if (error) return dbError(res, error);
        records = data || [];
        break;
      }

      case 'status_activity': {
        let query = supabase.from('intake_status_history')
          .select('*, intake_records(patient_id, patient_name, patient_code, service_date, diagnosis_category, manipulation_type, workflow_status)')
          .order('changed_at', { ascending: false });
        if (filters.from) query = query.gte('changed_at', filters.from);
        if (filters.to) query = query.lte('changed_at', filters.to + 'T23:59:59');
        const { data, error } = await query;
        if (error) return dbError(res, error);
        // Flatten joined data for grouping convenience
        records = (data || []).map(h => ({
          ...h,
          patient_id: h.intake_records?.patient_id || null,
          patient_name: h.intake_records?.patient_name || null,
          patient_code: h.intake_records?.patient_code || null,
          service_date: h.intake_records?.service_date || null,
          diagnosis_category: h.intake_records?.diagnosis_category || null,
          manipulation_type: h.intake_records?.manipulation_type || null
        }));
        break;
      }

      case 'reconciliation': {
        // Read reconciliation fields directly from intake_records
        let irQuery = supabase.from('intake_records')
          .select('id, intake_id, service_date, sheet_date, patient_id, patient_name, patient_code, manipulation_type, diagnosis_category, workflow_status, claim_number, in_charge_capture, in_billing_report, billing_report_period, missing_from_report')
          .order('service_date', { ascending: true });
        irQuery = applyIntakeFilters(irQuery, filters);
        const { data: irData, error: irErr } = await irQuery;
        if (irErr) return dbError(res, irErr);

        // Get billing reports for billing amount lookup
        const { data: brData } = await supabase.from('billing_reports')
          .select('patient_id, service_date, charge, claim_number');
        const brMap = {};
        (brData || []).forEach(br => {
          const key = `${br.patient_id}_${br.service_date}`;
          brMap[key] = br;
        });

        records = (irData || []).map(r => {
          const brKey = `${r.patient_id}_${r.service_date}`;
          const br = brMap[brKey];
          return {
            ...r,
            on_intake: true,
            in_charge_capture: !!r.in_charge_capture,
            in_billing_report: !!r.in_billing_report,
            claim_number: r.claim_number || br?.claim_number || null,
            billing_amount: br ? parseFloat(br.charge) || 0 : null
          };
        });
        break;
      }

      case 'monthly_summary': {
        // Full monthly report: days open, patients, daily breakdown, billing
        const mFrom = filters.from || new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString().split('T')[0];
        const mTo = filters.to || new Date().toISOString().split('T')[0];

        const [irRes, brRes] = await Promise.all([
          supabase.from('intake_records')
            .select('id, intake_id, service_date, patient_id, patient_name, patient_code, manipulation_type, therapeutic_exercises, diagnosis_category, workflow_status, is_backdated, new_patient, no_fault, cpt_manipulation, cpt_te, in_charge_capture, in_billing_report, claim_number')
            .gte('service_date', mFrom).lte('service_date', mTo)
            .order('service_date', { ascending: true }),
          supabase.from('billing_reports')
            .select('patient_id, service_date, charge, approved, pri_ins_received, sec_ins_received, patient_received, claim_number')
            .gte('service_date', mFrom).lte('service_date', mTo)
        ]);

        const ir = irRes.data || [];
        const br = brRes.data || [];

        // Build billing lookup by date
        const brByDate = {};
        br.forEach(b => {
          if (!brByDate[b.service_date]) brByDate[b.service_date] = [];
          brByDate[b.service_date].push(b);
        });

        // Group visits by date
        const byDate = {};
        ir.forEach(r => {
          if (!byDate[r.service_date]) byDate[r.service_date] = [];
          byDate[r.service_date].push(r);
        });

        const uniquePatients = new Set(ir.map(r => r.patient_id).filter(Boolean));
        const totalE1 = ir.filter(r => r.manipulation_type === 'E1').length;
        const totalE2 = ir.filter(r => r.manipulation_type === 'E2').length;
        const totalNew = ir.filter(r => r.new_patient).length;
        const totalBackdated = ir.filter(r => r.is_backdated).length;

        // Billing totals
        const totalCharged = br.reduce((s, b) => s + (parseFloat(b.charge) || 0), 0);
        const totalApproved = br.reduce((s, b) => s + (parseFloat(b.approved) || 0), 0);
        const totalInsReceived = br.reduce((s, b) => s + (parseFloat(b.pri_ins_received) || 0) + (parseFloat(b.sec_ins_received) || 0), 0);
        const totalPtReceived = br.reduce((s, b) => s + (parseFloat(b.patient_received) || 0), 0);

        // Daily breakdown
        const dailyGroups = Object.keys(byDate).sort().map(date => {
          const dayVisits = byDate[date];
          const dayBilling = brByDate[date] || [];
          const dayCharged = dayBilling.reduce((s, b) => s + (parseFloat(b.charge) || 0), 0);
          const dayReceived = dayBilling.reduce((s, b) => s + (parseFloat(b.pri_ins_received) || 0) + (parseFloat(b.sec_ins_received) || 0) + (parseFloat(b.patient_received) || 0), 0);
          return {
            label: date,
            subtotals: {
              count: dayVisits.length,
              unique_patients: new Set(dayVisits.map(v => v.patient_id).filter(Boolean)).size,
              e1: dayVisits.filter(v => v.manipulation_type === 'E1').length,
              e2: dayVisits.filter(v => v.manipulation_type === 'E2').length,
              new_patients: dayVisits.filter(v => v.new_patient).length,
              backdated: dayVisits.filter(v => v.is_backdated).length,
              total_charged: dayCharged,
              total_received: dayReceived,
              outstanding: dayCharged - dayReceived
            },
            records: dayVisits.map(v => ({
              ...v,
              visit_date: v.service_date,
              diagnosis_codes: Array.isArray(v.diagnosis_codes) ? v.diagnosis_codes.join(', ') : v.diagnosis_codes
            }))
          };
        });

        return res.json({
          summary: {
            period: { from: mFrom, to: mTo },
            days_open: Object.keys(byDate).length,
            total_visits: ir.length,
            unique_patients: uniquePatients.size,
            e1: totalE1,
            e2: totalE2,
            new_patients: totalNew,
            backdated: totalBackdated,
            total_charged: totalCharged,
            total_approved: totalApproved,
            total_ins_received: totalInsReceived,
            total_pt_received: totalPtReceived,
            total_received: totalInsReceived + totalPtReceived,
            outstanding: totalCharged - totalInsReceived - totalPtReceived
          },
          groups: dailyGroups
        });
      }

      default:
        return res.status(400).json({ error: `Unknown report_type: ${report_type}` });
    }

    const groups = groupRecords(records, group_by, report_type);
    const summary = computeSubtotals(records, report_type);
    res.json({ summary, groups });
  } catch (e) {
    console.error('Report engine error:', e);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

// GET /api/intake/:id/status-history — status history for a single intake record
app.get('/api/intake/:id/status-history', async (req, res) => {
  const { data, error } = await supabase
    .from('intake_status_history')
    .select('*')
    .eq('intake_record_id', req.params.id)
    .order('changed_at', { ascending: false });
  if (error) return dbError(res, error);
  res.json(data);
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
