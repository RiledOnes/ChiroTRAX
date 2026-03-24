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

-- INTAKE RECORDS TABLE (Bulk Upload + Workflow)
create table intake_records (
  id uuid default gen_random_uuid() primary key,
  intake_id text unique not null,           -- unique ID from uploaded data (prevents duplicates)
  patient_code text,                        -- maps to patients.patient_code
  patient_id uuid references patients(id) on delete set null,
  patient_name text,                        -- denormalized name from upload
  service_date date,
  manipulation_type text,
  therapeutic_exercises int,
  diagnosis_codes text,                     -- comma-separated ICD-10 codes
  insurance_provider text,
  amount_billed numeric(10,2),
  notes text,
  workflow_status text default 'intake' check (workflow_status in ('intake', 'entered_ebs', 'claim_created', 'submitted', 'processed')),
  batch_id text,                            -- groups records from same upload
  created_at timestamp with time zone default now()
);

-- APPROVED USERS TABLE (Auth)
create table approved_users (
  id uuid default gen_random_uuid() primary key,
  email text unique not null,
  role text default 'staff',
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
create index on intake_records(workflow_status);
create index on intake_records(batch_id);
create index on intake_records(patient_code);
create index on intake_records(service_date);

-- DAILY INTAKE IMAGES TABLE
create table daily_intake_images (
  id uuid default gen_random_uuid() primary key,
  business_date date not null,
  file_name text not null,
  image_data text not null,              -- base64 data URL
  notes text,
  uploaded_by text,
  created_at timestamptz default now()
);

create index on daily_intake_images(business_date);

-- TASKS TABLE
create table tasks (
  id uuid default gen_random_uuid() primary key,
  title text not null,
  description text,
  assigned_by text,                        -- e.g. "Dina"
  assigned_to text,
  priority text default 'normal' check (priority in ('low', 'normal', 'high', 'urgent')),
  status text default 'todo' check (status in ('todo', 'in_progress', 'done')),
  due_date date,
  completed_at timestamptz,
  created_by text,
  created_at timestamptz default now()
);

create index on tasks(status);
create index on tasks(due_date);
create index on tasks(priority);

-- ============================================
-- ROW LEVEL SECURITY (enable when ready)
-- ============================================
-- alter table patients enable row level security;
-- alter table visits enable row level security;
-- alter table diagnoses enable row level security;
-- alter table claims enable row level security;
