import { Page, expect, test } from '@playwright/test';
import { mockApi } from './mock-api';

// Dashboard E2E (Milestone 12) on [MOCK] data: overview → risk → CVEs → network map, IT/EN, small screens.

async function open(page: Page, path: string) {
  const errors: string[] = [];
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  page.on('pageerror', (e) => errors.push(e.message));
  const unexpected = await mockApi(page);
  await page.goto(path);
  return { errors, unexpected };
}

/** No horizontal scroll of the whole page (wide tables scroll inside their card). */
async function expectNoHorizontalScroll(page: Page) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
}

test('overview, security score, known vulnerabilities and network map', async ({ page, isMobile }) => {
  const { errors, unexpected } = await open(page, '/');
  await expect(page).toHaveURL(/\/overview$/);
  await expect(page.getByRole('heading', { name: 'Panoramica', level: 1 })).toBeVisible();
  const home = page.getByTestId('home-h1');
  await expect(home.getByTestId('score')).toHaveText('62');
  await expect(home.getByTestId('kev')).toContainText('1 KEV');
  await expect(page.getByTestId('home-h2').getByTestId('no-score')).toBeVisible();
  await expectNoHorizontalScroll(page);

  await home.getByRole('link', { name: 'Punteggio di sicurezza' }).click();
  await expect(page).toHaveURL(/\/homes\/h1\/risk$/);
  await expect(page.getByTestId('score')).toContainText('62');
  await expect(page.getByTestId('deductions')).toContainText('CVE-2099-2001');
  await expectNoHorizontalScroll(page);

  await page.goto('/homes/h1/vulnerabilities');
  const rows = page.getByTestId('cves').locator('tbody tr');
  await expect(rows).toHaveCount(2);
  await expect(rows.first()).toContainText('CVE-2099-2001');
  await expect(rows.first()).toContainText('Sfruttata attivamente');
  await page.getByTestId('kev-only').check();
  await expect(rows).toHaveCount(1);
  await expectNoHorizontalScroll(page);

  await page.goto('/homes/h1/network-map');
  const group = page.getByTestId('group-192.168.60.0/24');
  await expect(group.locator('g.node')).toHaveCount(14);
  await expect(group.locator('path.exposure')).toHaveCount(1);
  const camera = group.getByTestId('node-d2');
  await expect(camera).toHaveClass(/high/);
  await camera.focus();
  await page.keyboard.press('Enter'); // keyboard selection
  await expect(page.getByTestId('details')).toContainText('mock-camera');
  await expect(page.getByTestId('points')).toContainText('29.25');
  const box = await group.locator('svg').boundingBox();
  expect(box!.width).toBeLessThanOrEqual(page.viewportSize()!.width);
  await expectNoHorizontalScroll(page);
  if (isMobile) {
    await page.screenshot({ path: 'test-results/network-map-mobile.png', fullPage: true });
  }

  expect(unexpected).toEqual([]);
  expect(errors).toEqual([]);
});

test('navigation menu collapses on small screens', async ({ page, isMobile }) => {
  await open(page, '/overview');
  const nav = page.locator('#main-nav');
  const toggle = page.getByTestId('menu-toggle');
  if (!isMobile) {
    await expect(toggle).toBeHidden();
    await expect(nav).toBeVisible();
    await expect(nav.getByTestId('unread-count')).toHaveText('2'); // unread alerts next to the menu entry
    return;
  }
  await expect(nav).toBeHidden();
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
  await nav.getByRole('link', { name: 'Abitazioni' }).click();
  await expect(nav).toBeHidden(); // closes after choosing a page
});

test('switches the dashboard to English', async ({ page }) => {
  await open(page, '/overview');
  await page.locator('.lang select').selectOption('en');
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
  await page.goto('/homes/h1/network-map');
  await expect(page.getByRole('heading', { name: 'Network map', level: 1 })).toBeVisible();
  await expect(page.getByTestId('legend')).toContainText('exposed to the Internet');
});
