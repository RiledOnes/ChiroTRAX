-- ============================================
-- CHIROPRACTIC OFFICE MANAGEMENT SYSTEM
-- Supabase Schema
-- ============================================

-- PATIENTS TABLE
create table patients (
  id uuid default gen_random_uuid() primary key,
  patient_code text unique not null, -- e.g. "001-01"
  first_name text not null,
  last_name text not null,
  date_of_birth date,
  phone text,
  email text,
  insurance_provider text,
  insurance_id text,
  payment_type text check (payment_type in ('insurance', 'cash')),
  created_at timestamp with time zone default now()
);

-- VISITS TABLE (daily intake)
create table visits (
  id uuid default gen_random_uuid() primary key,
  patient_id uuid references patients(id) on delete cascade,
  visit_date date not null default current_date,
  patient_status text check (patient_status in ('new', 'existing', null)),
  manipulation_type text check (manipulation_type in ('E1', 'E2', null)),
  therapeutic_exercises int check (therapeutic_exercises between 0 and 10),
  notes text,
  created_at timestamp with time zone default now()
);

-- DIAGNOSES TABLE
create table diagnoses (
  id uuid default gen_random_uuid() primary key,
  patient_id uuid references patients(id) on delete cascade,
  visit_id uuid references visits(id) on delete set null,
  diagnosis_code text,        -- e.g. ICD-10 code
  diagnosis_description text not null,
  is_active boolean default true,
  diagnosed_date date default current_date,
  created_at timestamp with time zone default now()
);

-- CLAIMS TABLE
create table claims (
  id uuid default gen_random_uuid() primary key,
  visit_id uuid references visits(id) on delete cascade,
  patient_id uuid references patients(id) on delete cascade,
  claim_date date default current_date,
  payment_type text check (payment_type in ('insurance', 'cash')),
  insurance_provider text,
  claim_status text default 'pending' check (claim_status in ('pending', 'submitted', 'approved', 'denied', 'paid')),
  amount_billed numeric(10,2),
  amount_paid numeric(10,2),
  notes text,
  created_at timestamp with time zone default now()
);

-- ============================================
-- INDEXES for performance
-- ============================================
create index on visits(visit_date);
create index on visits(patient_id);
create index on diagnoses(patient_id);
create index on claims(patient_id);
create index on claims(claim_status);

-- ============================================
-- ROW LEVEL SECURITY (enable when ready)
-- ============================================
-- alter table patients enable row level security;
-- alter table visits enable row level security;
-- alter table diagnoses enable row level security;
-- alter table claims enable row level security;
