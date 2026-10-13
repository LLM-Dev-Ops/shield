import { expect, test } from 'playwright/test';

test('browser bundle loads and enforces prompt-injection detection', async ({
  page,
}) => {
  await page.goto('/tests/browser/fixture.html');

  const result = await page.evaluate(async () => {
    const browserWindow = window as typeof window & {
      shieldResult: Promise<{
        constructorType: string;
        safe: boolean;
        blocked: boolean;
        blockedDetections: number;
      }>;
    };

    return browserWindow.shieldResult;
  });

  expect(result.constructorType).toBe('function');
  expect(result.safe).toBe(true);
  expect(result.blocked).toBe(false);
  expect(result.blockedDetections).toBeGreaterThan(0);
});
