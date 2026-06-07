import { createClient } from '@supabase/supabase-js';
import { spawn } from 'child_process';
import os from 'os';
import path from 'path';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const scanUrl = process.env.SCAN_URL;
const scanId = process.env.SCAN_ID;

console.log('--- SCANNER WORKER STARTING ---');
console.log('Target URL:', scanUrl);
console.log('Scan ID:', scanId);

if (!supabaseUrl || !supabaseKey || !scanUrl || !scanId) {
  console.error("Missing required environment variables");
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// Helper for cross-platform paths
const isWin = os.platform() === 'win32';
const IS_CI = process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true';
const BIN_EXT = isWin ? '.exe' : '';
const PYTHON_CMD = isWin ? 'python' : 'python3';
const PERL_CMD = isWin ? 'C:\\Strawberry\\perl\\bin\\perl.exe' : 'perl';
// Cross-platform binary path: uses ./ on Linux, .\  on Windows
const getBin = (name) => path.join('bin', `${name}${BIN_EXT}`);

async function log(message) {
  const timestamp = new Date().toLocaleTimeString();
  console.log(`[${timestamp}] ${message}`);
  const { error } = await supabase.from('scan_logs').insert([{
    scan_id: scanId,
    message: message
  }]);
  if (error) console.error(`[SUPABASE ERROR] Failed to log message:`, error.message);
}

async function saveFinding(tool, severity, data) {
  const { error } = await supabase.from('findings').insert([{
    scan_id: scanId,
    tool,
    severity,
    data
  }]);
  if (error) console.error(`[SUPABASE ERROR] Failed to save finding for ${tool}:`, error.message);
}

function runCommand(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    // 5-minute timeout (300000ms) for all commands so they never hang the workflow
    const proc = spawn(cmd, args, { shell: isWin, windowsHide: true, cwd: opts.cwd || undefined, timeout: 300000 });
    let stdout = "";
    let stderr = "";

    proc.on('error', (err) => {
      console.error(`[COMMAND ERROR] Failed to start ${cmd}:`, err.message);
      resolve({ code: 1, stdout: "", stderr: err.message });
    });

    proc.stdout.on('data', (data) => {
      const line = data.toString();
      stdout += line;
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

async function main() {
  try {
    // Normalize URL — default to HTTPS (not HTTP) since virtually all modern sites use HTTPS
    let targetUrl = scanUrl.startsWith('http') ? scanUrl : `https://${scanUrl}`;
    // Robust domain extraction using URL API
    const domain = new URL(targetUrl).hostname;
    const isHttps = targetUrl.startsWith('https://');
    const isLocalhost = domain === 'localhost' || domain === '127.0.0.1' || domain.endsWith('.local');

    await supabase.from('scans').update({ status: 'RUNNING' }).eq('id', scanId);
    await log(`Starting scan sequence for ${targetUrl}`);

    // --- PHASE 0: Subfinder (fire and forget, doesn't block anything) ---
    const runSubfinder = async () => {
      if (isLocalhost) return; // skip subdomain scan for local targets
      await log("Phase 0: Scanning for subdomains...");
      const { stdout: sfOut } = await runCommand(getBin('subfinder'), ['-d', domain, '-silent']);
      const subdomains = sfOut.split('\n').filter(Boolean);
      if (subdomains.length > 0) {
        await saveFinding("Subfinder", "Info", { name: "Subdomains Discovered", description: "Identified related subdomains.", subdomains });
        await log(`Discovered ${subdomains.length} subdomains.`);
      } else {
        await log("Subfinder: No subdomains found.");
      }
    };

    // --- NUCLEI: Tech fingerprint then smart sweep (sequential internally, parallel with everything else) ---
    const runNuclei = async () => {
      await log("Phase 1: Initializing Technology Fingerprinting...");
      const detectedTech = [];
      const nucleiTech = spawn(getBin('nuclei'), ['-u', targetUrl, '-t', 'technologies', '-json', '-silent'], { shell: isWin, windowsHide: true, timeout: 60000 });
      nucleiTech.stdout.on('data', async (data) => {
        for (const line of data.toString().split('\n').filter(Boolean)) {
          try {
            const vuln = JSON.parse(line);
            await saveFinding("Nuclei-Tech", "Info", vuln);
            if (vuln['template-id']) detectedTech.push(vuln['template-id']);
          } catch (e) {}
        }
      });
      await new Promise((res) => {
        nucleiTech.on('close', res);
        nucleiTech.on('error', () => { log("Nuclei Tech execution failed."); res(); });
      });
      await log(`Fingerprinting complete. Detected: ${detectedTech.join(', ') || 'Standard'}`);

      // Smart sweep after tech detection — include ssl templates for HTTPS targets
      await log("Phase 2: Engaging Smart Nuclei Sweep...");
      const nucleiArgs = ['-u', targetUrl, '-json', '-silent', '-rl', '30',
        '-t', 'vulnerabilities', '-t', 'misconfigurations', '-t', 'exposures'];
      if (isHttps) nucleiArgs.push('-t', 'ssl'); // SSL/TLS misconfiguration templates
      const smartNuclei = spawn(getBin('nuclei'), nucleiArgs, { shell: isWin, windowsHide: true, timeout: 300000 });
      smartNuclei.stdout.on('data', async (data) => {
        for (const line of data.toString().split('\n').filter(Boolean)) {
          try {
            const vuln = JSON.parse(line);
            const sev = vuln.info?.severity || "info";
            await saveFinding("Nuclei-Smart", sev.charAt(0).toUpperCase() + sev.slice(1), vuln);
          } catch (e) {}
        }
      });
      await new Promise((res) => {
        smartNuclei.on('close', res);
        smartNuclei.on('error', () => { log("Nuclei Smart execution failed."); res(); });
      });
    };

    // --- NIKTO ---
    const runNikto = async () => {
      try {
        await log("Engaging Nikto...");
        if (IS_CI) {
          const niktoDir = path.resolve('bin/nikto-dir/program');
          const isHttps = targetUrl.startsWith('https://');
          const niktoArgs = ['nikto.pl', '-h', targetUrl, '-maxtime', '5m', '-Format', 'txt'];
          if (isHttps) niktoArgs.push('-ssl');  // CRITICAL: without this Nikto scans HTTP and gets nothing on HTTPS targets
          const { stdout, stderr, code } = await runCommand(PERL_CMD, niktoArgs, { cwd: niktoDir });
          console.log('[NIKTO STDERR]', stderr?.slice(0, 300));
          console.log('[NIKTO STDOUT PREVIEW]', stdout?.slice(0, 300));
          if (code !== 0 && !stdout) { await log(`Nikto: Failed (exit ${code}). ${stderr?.slice(0,150)}`); return; }
          const lines = stdout.split('\n').filter(l => l.startsWith('+ '));
          for (const line of lines) {
            const raw = line.replace('+ ', '').trim();
            let severity = 'Info', name = 'Server Anomaly Detected';
            if (raw.includes('X-Frame-Options'))              { severity = 'Medium'; name = 'Missing X-Frame-Options'; }
            else if (raw.includes('X-Content-Type-Options'))  { severity = 'Low';    name = 'Missing X-Content-Type-Options'; }
            else if (raw.includes('X-XSS-Protection'))        { severity = 'Low';    name = 'Missing X-XSS-Protection Header'; }
            else if (raw.includes('Strict-Transport-Security')){ severity = 'Medium'; name = 'Missing HSTS Header'; }
            else if (raw.includes('Content-Security-Policy')) { severity = 'Medium'; name = 'Missing Content-Security-Policy'; }
            else if (raw.includes('Server:'))                 { severity = 'Low';    name = 'Server Banner Disclosure'; }
            else if (raw.includes('x-powered-by') || raw.includes('X-Powered-By')) { severity = 'Low'; name = 'Technology Disclosure via X-Powered-By'; }
            else if (raw.includes('robots.txt'))              { severity = 'Info';   name = 'robots.txt Information Disclosure'; }
            else if (raw.includes('OSVDB'))                   { severity = 'Medium'; name = `Known Vulnerability (${raw.match(/OSVDB-\d+/)?.[0] || 'OSVDB'})`; }
            else if (raw.includes('TRACE') || raw.includes('TRACK')) { severity = 'Medium'; name = 'HTTP TRACE Method Enabled (XST Risk)'; }
            else if (raw.includes('OPTIONS'))                 { severity = 'Low';    name = 'Dangerous HTTP Methods Allowed'; }
            else if (raw.includes('PUT') || raw.includes('DELETE')) { severity = 'High'; name = 'Write HTTP Methods Enabled'; }
            else if (raw.toLowerCase().includes('cookie') && raw.toLowerCase().includes('httponly')) { severity = 'Medium'; name = 'Cookie Missing HttpOnly Flag'; }
            else if (raw.toLowerCase().includes('cookie') && raw.toLowerCase().includes('secure'))   { severity = 'Medium'; name = 'Cookie Missing Secure Flag'; }
            else if (raw.toLowerCase().includes('index of'))  { severity = 'High';   name = 'Directory Listing Enabled'; }
            else if (raw.toLowerCase().includes('/admin'))    { severity = 'Medium'; name = 'Admin Interface Exposed'; }
            else if (raw.toLowerCase().includes('phpinfo'))   { severity = 'High';   name = 'PHP Info Page Exposed'; }
            else if (raw.toLowerCase().includes('backup') || raw.toLowerCase().includes('.bak')) { severity = 'High'; name = 'Backup File Exposed'; }
            else if (raw.toLowerCase().includes('default'))   { severity = 'Low';    name = 'Default Content Detected'; }
            await saveFinding('Nikto', severity, { name, description: raw, raw, tool: 'Nikto', matched: targetUrl });
          }
          if (lines.length === 0) await log('Nikto: No anomalies found.');
          else await log(`Nikto: Scan complete. ${lines.length} anomalies found.`);
        } else {
          // LOCALHOST: Node.js header scanner (Windows Defender blocks nikto.pl)
          const response = await fetch(targetUrl).catch(() => null);
          let found = false;
          if (response) {
            const headers = response.headers;
            const rawDump = Array.from(headers.entries()).map(([k,v]) => `${k}: ${v}`).join('\n');
            if (!headers.get('x-frame-options'))       { await saveFinding('Nikto','Medium',{name:'Missing X-Frame-Options',description:'Target is missing clickjacking protection.',raw:`[Nikto Node Module]\n${rawDump}`,tool:'Nikto',matched:targetUrl}); found=true; }
            if (!headers.get('x-content-type-options')){ await saveFinding('Nikto','Low',  {name:'Missing X-Content-Type-Options',description:'Target is missing MIME sniffing protection.',raw:`[Nikto Node Module]\n${rawDump}`,tool:'Nikto',matched:targetUrl}); found=true; }
            const srv = headers.get('server');
            if (srv) { await saveFinding('Nikto','Low',{name:'Server Banner Disclosure',description:'Target exposed server banner.',raw:`[Nikto Node Module]\n${rawDump}\nServer: ${srv}`,tool:'Nikto',matched:targetUrl}); found=true; }
          }
          if (!found) await log('Nikto: No anomalies found.'); else await log('Nikto: Scan complete. Anomalies found.');
        }
      } catch (e) { await log(`Nikto Error: ${e.message}`); }
    };

    // --- SQLMAP ---
    const runSqlMap = async () => {
      try {
        await log("Checking for injectable forms...");
        const sqlmapArgs = [
          'bin/sqlmap/sqlmap.py', '-u', targetUrl,
          '--forms', '--crawl=2', '--batch', '--level=2', '--risk=1',
          '--threads=4', '--timeout=30', '--retries=1'
        ];
        if (isHttps) sqlmapArgs.push('--force-ssl'); // explicit HTTPS enforcement
        const { stdout } = await runCommand(PYTHON_CMD, sqlmapArgs);
        if (stdout.includes('is vulnerable') || stdout.includes('Payload:')) {
          await saveFinding("SQLMap", "Critical", { name: "SQL Injection Confirmed", description: "SQLMap confirmed SQL injection. Raw terminal trace below.", raw: stdout.trim(), tool: "SQLMap", matched: targetUrl });
        } else { await log("SQLMap: No vulnerabilities found."); }
      } catch (e) { await log(`SQLMap Error: ${e.message}`); }
    };

    // --- XSSTRIKE ---
    const runXSStrike = async () => {
      try {
        await log("Engaging XSStrike...");
        const { stdout } = await runCommand(PYTHON_CMD, [
          'bin/xsstrike/xsstrike.py', '-u', targetUrl, '--crawl', '--skip', '--timeout', '30'
        ]);
        if (stdout.includes('Vulnerable') || stdout.includes('Payload:')) {
          await saveFinding("XSStrike", "High", { name: "Cross-Site Scripting (XSS)", description: "XSStrike confirmed XSS. Raw terminal trace below.", raw: stdout.trim(), tool: "XSStrike", matched: targetUrl });
        } else { await log("XSStrike: No vulnerabilities found."); }
       } catch (e) { await log(`XSStrike Error: ${e.message}`); }
    };
    // --- RUN ALL ENGINES IN PARALLEL ---
    await log("Launching all scan engines in parallel...");
    await Promise.allSettled([
      runSubfinder(),
      runNuclei(),
      runNikto(),
      runSqlMap(),
      runXSStrike(),
    ]);



    await log("Scan sequence complete. Synchronizing final status...");
    await supabase.from('scans').update({ status: 'COMPLETED' }).eq('id', scanId);
    await log("Status locked: COMPLETED");


  } catch (error) {
    console.error("Worker Error:", error);
    await log(`FATAL ERROR: ${error.message}`);
    await supabase.from('scans').update({ status: 'FAILED', error: error.message }).eq('id', scanId);
  } finally {
    setTimeout(() => {
      console.log("--- SCANNER WORKER SHUTDOWN ---");
      process.exit(0);
    }, 2000);
  }
}

main();
