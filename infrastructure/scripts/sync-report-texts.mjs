// Copies the dashboard texts the backend needs (PDF reports, alert e-mails) from the Angular
// i18n files into backend resources, so both say the same thing. Run after changing them:
//   node infrastructure/scripts/sync-report-texts.mjs
// FindingTextsTest fails when a finding rule has no text in the copy.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const pick = (j) => ({
  findings: {
    rule: j.findings.rule,
    severity: j.findings.severity,
    status: j.findings.status,
    type: j.findings.type,
  },
  risk: { level: j.risk.level, rating: j.risk.rating },
  scans: { profiles: j.scans.profiles },
  devices: { categories: j.devices.categories },
});
for (const lang of ['it', 'en']) {
  const source = JSON.parse(readFileSync(join(root, 'frontend/angular-dashboard/public/i18n', `${lang}.json`), 'utf8'));
  const target = join(root, 'backend/spring-boot-api/src/main/resources/reports', `texts_${lang}.json`);
  writeFileSync(target, JSON.stringify(pick(source), null, 2) + '\n');
  console.log('written', target);
}
