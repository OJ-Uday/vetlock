import { cp, mkdir, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = fileURLToPath(new URL('../', import.meta.url));
const sourceData = path.join(packageRoot, 'src', 'data');
const outputData = path.join(packageRoot, 'dist', 'data');

await mkdir(outputData, { recursive: true });
await cp(
  path.join(packageRoot, 'src', 'capability-map.json'),
  path.join(packageRoot, 'dist', 'capability-map.json'),
);

for (const entry of await readdir(sourceData)) {
  if (entry.endsWith('.json')) {
    await cp(path.join(sourceData, entry), path.join(outputData, entry));
  }
}
