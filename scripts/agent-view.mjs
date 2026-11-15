// What an agent's browser tool sees in a page: the
// accessibility snapshot Playwright MCP returns, the page's HTML, and a
// screenshot. Prints them as JSON; the caller checks none holds the password.
// Usage: node scripts/agent-view.mjs BROWSER_URL PAGE_URL SCREENSHOT_PATH
// (with playwright-core resolvable, e.g. NODE_PATH=/path/to/node_modules)
import { createRequire } from 'node:module';

const require = createRequire(process.env.NODE_PATH ? process.env.NODE_PATH + '/' : import.meta.url);
const { chromium } = require('playwright-core');
const [browserUrl, pageUrl, screenshot] = process.argv.slice(2);

const browser = await chromium.connectOverCDP(browserUrl);
const page = browser.contexts().flatMap((c) => c.pages()).find((p) => p.url() === pageUrl);
if (!page) throw new Error(`no page at ${pageUrl}`);
const snapshot = await page.locator('body').ariaSnapshot();
const html = await page.content();
await page.screenshot({ path: screenshot });
const cdp = await page.context().newCDPSession(page);
const { nodes } = await cdp.send('Accessibility.getFullAXTree');
const values = nodes.map((n) => n.value?.value).filter(Boolean);
console.log(JSON.stringify({ snapshot, html, values }));
await browser.close();
