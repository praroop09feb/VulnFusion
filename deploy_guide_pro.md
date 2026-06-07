# 🚀 VulnFusion: Pro Deployment Guide (Zero-Cost Architecture)

Follow these steps in order to deploy your high-performance, real-time security scanner.

### 1. Supabase Setup (Database & Realtime)
1.  Create a free project at [Supabase](https://supabase.com/).
2.  Open the **SQL Editor** in the Supabase sidebar.
3.  Copy the contents of `supabase_schema.sql` from your project root and run it. This creates the tables and enables **Realtime**.
4.  Go to **Project Settings -> API** and copy:
    - `URL` (Save to `NEXT_PUBLIC_SUPABASE_URL`)
    - `anon public` key (Save to `NEXT_PUBLIC_SUPABASE_ANON_KEY`)
    - `service_role` key (Save to `SUPABASE_SERVICE_ROLE_KEY`)

### 2. GitHub Setup (Scanning Worker)
1.  Create a **GitHub Personal Access Token (Classic)**:
    - Go to your GitHub Settings -> Developer settings -> Personal access tokens.
    - Click **Generate new token (classic)**.
    - Scope: Check `repo` (all).
    - Copy this token (Save to `GITHUB_PAT`).
2.  Create a **Public Repository** on GitHub and push your code there.
3.  Add **Secrets** to your GitHub Repo:
    - Go to your Repo -> **Settings -> Secrets and variables -> Actions**.
    - Add New Repository Secret:
        - `SUPABASE_URL`: Your Supabase Project URL.
        - `SUPABASE_KEY`: Your Supabase `service_role` key.

### 3. Vercel Setup (UI)
1.  Connect your GitHub repo to **Vercel**.
2.  Add the following **Environment Variables** in Vercel settings:
    - `NEXT_PUBLIC_SUPABASE_URL`
    - `NEXT_PUBLIC_SUPABASE_ANON_KEY`
    - `SUPABASE_SERVICE_ROLE_KEY`
    - `GITHUB_PAT`
    - `GITHUB_REPO_OWNER` (Your GitHub username)
    - `GITHUB_REPO_NAME` (Your repo name, e.g., `VulnFusion`)
3.  Deploy.

### 🧪 How to Test
1.  Go to your Vercel URL.
2.  Enter a target URL (e.g., `https://example.com`) and click **Execute**.
3.  You will be redirected to the scan page. 
4.  Click **Live Execution Logs**—you should see the environment initializing as the GitHub Action spins up!

### 🛠️ Troubleshooting
- **Logs not showing?** Make sure you ran the `ALTER PUBLICATION` lines in the Supabase SQL editor.
- **Scan stuck on PENDING?** Check your GitHub Repo's **Actions** tab to see if the workflow is failing.
