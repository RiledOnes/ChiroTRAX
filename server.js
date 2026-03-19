require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// ============================================
// PATIENTS
// ============================================

// Get all patients
app.get('/api/patients', async (req, res) => {
  const { data, error } = await supabase
    .from('patients')
    .select('*')
    .order('last_name');
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// Get single patient
app.get('/api/patients/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('patients')
    .select('*, visits(*), diagnoses(*)')
    .eq('id', req.params.id)
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// Create patient
app.post('/api/patients', async (req, res) => {
  const { data, error } = await supabase
    .from('patients')
    .insert([req.body])
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
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
  if (error) return res.status(400).json({ error: error.message });
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
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// Create visit
app.post('/api/visits', async (req, res) => {
  const { data, error } = await supabase
    .from('visits')
    .insert([req.body])
    .select('*, patients(patient_code, first_name, last_name)')
    .single();
  if (error) return res.status(400).json({ error: error.message });
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
  if (error) return res.status(400).json({ error: error.message });
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
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// Create diagnosis
app.post('/api/diagnoses', async (req, res) => {
  const { data, error } = await supabase
    .from('diagnoses')
    .insert([req.body])
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
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
  if (error) return res.status(400).json({ error: error.message });
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
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// Create claim from visit
app.post('/api/claims', async (req, res) => {
  const { data, error } = await supabase
    .from('claims')
    .insert([req.body])
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
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
  if (error) return res.status(400).json({ error: error.message });
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
  if (error) return res.status(400).json({ error: error.message });
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
    if (error) return res.status(400).json({ error: error.message });
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

  // Check for existing intake_ids to prevent duplicates
  const incomingIds = records.map(r => r.intake_id);
  const { data: existing, error: checkErr } = await supabase
    .from('intake_records')
    .select('intake_id')
    .in('intake_id', incomingIds);

  if (checkErr) return res.status(400).json({ error: checkErr.message });

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

  if (error) return res.status(400).json({ error: error.message });

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
  if (error) return res.status(400).json({ error: error.message });
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
  if (error) return res.status(400).json({ error: error.message });
  res.json({ updated: data.length, data });
});

// ============================================
// AUTH CHECK (approved users only)
// ============================================
app.post('/api/auth/check-approved', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const { data, error } = await supabase
    .from('approved_users')
    .select('*')
    .eq('email', email.toLowerCase())
    .single();
  if (error || !data) return res.json({ approved: false });
  res.json({ approved: true, user: data });
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
