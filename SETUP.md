# ChiroTrax — Setup Instructions
## Follow these steps exactly, one at a time.

---

## STEP 1: Install Node.js (if you haven't already)
Go to https://nodejs.org and download the **LTS** version. Install it like a normal app.

To confirm it worked, open Terminal and type:
```
node -v
```
You should see something like `v20.x.x`. If so, move to Step 2.

---

## STEP 2: Set up your Supabase database

1. Go to https://supabase.com and sign in (or create a free account)
2. Click **"New Project"** — name it `chirotrax`
3. Set a database password (save it somewhere safe)
4. Wait ~2 minutes for it to finish setting up
5. Once ready, click **"SQL Editor"** in the left sidebar
6. Copy the entire contents of **`supabase_schema.sql`** and paste it into the editor
7. Click **"Run"** — you should see success messages
8. Go to **Settings → API** in your Supabase project
9. Copy your **Project URL** and **anon/public key** — you need these next

---

## STEP 3: Add your Supabase credentials

1. Inside the `ChiroTrax` folder, find the file called `.env.example`
2. Make a copy and rename it `.env`
3. Open `.env` in any text editor and fill in your values:

```
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_ANON_KEY=your_anon_key_here
PORT=3000
```

Save the file.

---

## STEP 4: Open Terminal and go to your project folder

On **Mac**: Open Terminal (Spotlight → "Terminal")
On **Windows**: Open Command Prompt or PowerShell

```
cd ~/Desktop/ChiroTrax
```

---

## STEP 5: Install dependencies

```
npm install
```

Wait for it to finish. Lots of text is normal.

---

## STEP 6: Start the app

```
npm start
```

You should see:
```
✅ Chiro Office Manager running on http://localhost:3000
```

---

## STEP 7: Open the app

Go to your browser and visit:
```
http://localhost:3000
```

🎉 ChiroTrax is running!

---

## To stop: press Ctrl + C in Terminal
## To restart: navigate to ChiroTrax folder and run `npm start`

---

## Folder structure
- `public/index.html` — the frontend (what you see)
- `server.js` — the backend server
- `supabase_schema.sql` — run this in Supabase once to set up tables
- `.env` — your secret credentials (never share this file)
- `package.json` — project config

---

Questions? Come back to Claude and ask!
