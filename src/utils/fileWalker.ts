import * as fs from 'fs';
import * as path from 'path';

const EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx']);
const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage']);

/**
 * Recursively collects source files under `root` (or returns `[root]` if
 * it's already a single file). Skips node_modules/build output/dotfolders
 * so a scan of a whole agent repo doesn't churn through vendored code.
 */
export function walk(root: string): string[] {
  const stat = fs.statSync(root);
  if (stat.isFile()) {
    return [root];
  }

  const results: string[] = [];

  function recurse(dir: string) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (IGNORE_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
        recurse(path.join(dir, entry.name));
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (entry.name.endsWith('.d.ts')) continue;
        if (EXTENSIONS.has(ext)) {
          results.push(path.join(dir, entry.name));
        }
      }
    }
  }

  recurse(root);
  return results;
}
