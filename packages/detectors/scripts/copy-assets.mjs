import { mkdir, copyFile } from 'node:fs/promises';

await mkdir(new URL('../dist/', import.meta.url), { recursive: true });
await copyFile(
  new URL('../src/capability-map.json', import.meta.url),
  new URL('../dist/capability-map.json', import.meta.url),
);
