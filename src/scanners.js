const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

function runSemgrep(targetDir, rules = 'p/security-audit') {
  // Check if semgrep is available
  try {
    execSync('semgrep --version', { timeout: 5000, stdio: 'ignore' });
  } catch (e) {
    return { 
      scanner: 'semgrep', 
      target: targetDir, 
      timestamp: new Date().toISOString(),
      findings: [],
      errors: [],
      error: 'Semgrep is not installed or not in PATH. Please run install_semgrep_trivy.sh on the server to install it.'
    };
  }
  const outFile = path.join(__dirname, '..', 'logs', `semgrep-${Date.now()}.json`);
  try {
    execSync(`semgrep --config=${rules} "${targetDir}" --json -o "${outFile}" --quiet`, { timeout: 300000, stdio: 'pipe' });
    const raw = fs.readFileSync(outFile, 'utf8');
    const results = JSON.parse(raw);
    fs.unlinkSync(outFile);
    return {
      scanner: 'semgrep',
      target: targetDir,
      timestamp: new Date().toISOString(),
      findings: (results.results || []).map(r => ({
        path: r.path, line: r.start?.line, message: r.extra?.message,
        severity: r.extra?.metadata?.severity || 'MEDIUM', rule: r.check_id,
      })),
      errors: results.errors || [],
    };
  } catch (err) { return { scanner: 'semgrep', error: err.message, target: targetDir, findings: [] }; }
}

function runTrivy(target, scanType = 'fs') {
  // Check if trivy is available
  try {
    execSync('trivy version', { timeout: 5000, stdio: 'ignore' });
  } catch (e) {
    return { 
      scanner: 'trivy', 
      target, 
      scanType,
      timestamp: new Date().toISOString(),
      findings: [],
      error: 'Trivy is not installed or not in PATH. Please run install_semgrep_trivy.sh on the server to install it.'
    };
  }
  const outFile = path.join(__dirname, '..', 'logs', `trivy-${Date.now()}.json`);
  try {
    execSync(`trivy ${scanType} "${target}" --format json -o "${outFile}" --quiet`, { timeout: 300000, stdio: 'pipe' });
    const raw = fs.readFileSync(outFile, 'utf8');
    const results = JSON.parse(raw);
    fs.unlinkSync(outFile);
    const findings = [];
    (results.Results || []).forEach(result => {
      (result.Vulnerabilities || []).forEach(v => {
        findings.push({ target: result.Target, pkg: v.PkgName, vulnId: v.VulnerabilityID,
          severity: v.Severity, title: v.Title, fixedVersion: v.FixedVersion });
      });
    });
    return { scanner: 'trivy', target, scanType, timestamp: new Date().toISOString(), findings };
  } catch (err) { return { scanner: 'trivy', error: err.message, target, findings: [] }; }
}

module.exports = { runSemgrep, runTrivy };
