require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

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
// START SERVER
// ============================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Chiro Office Manager running on http://localhost:${PORT}`);
});
