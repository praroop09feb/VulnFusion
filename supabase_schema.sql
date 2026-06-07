-- 1. Create the scans table
CREATE TABLE scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING',
  error TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- 2. Create the findings table
CREATE TABLE findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  tool TEXT NOT NULL,
  severity TEXT NOT NULL,
  data JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- 3. Create the scan_logs table
CREATE TABLE scan_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- 4. Enable Realtime for all tables
ALTER PUBLICATION supabase_realtime ADD TABLE scans;
ALTER PUBLICATION supabase_realtime ADD TABLE findings;
ALTER PUBLICATION supabase_realtime ADD TABLE scan_logs;

-- 5. Add proper indexes
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_logs_scan_id ON scan_logs(scan_id);
CREATE INDEX idx_scans_status ON scans(status);

-- 6. Enable RLS (Row Level Security)
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_logs ENABLE ROW LEVEL SECURITY;

-- 7. Create permissive policies for public reading (using Anon Key)
CREATE POLICY "Public Read Scans" ON scans FOR SELECT USING (true);
CREATE POLICY "Public Read Findings" ON findings FOR SELECT USING (true);
CREATE POLICY "Public Read Logs" ON scan_logs FOR SELECT USING (true);

-- 8. Create policies for writing (Service Role can bypass RLS, but we add these for safety)
CREATE POLICY "Service Role Write Scans" ON scans FOR ALL USING (true);
CREATE POLICY "Service Role Write Findings" ON findings FOR ALL USING (true);
CREATE POLICY "Service Role Write Logs" ON scan_logs FOR ALL USING (true);
