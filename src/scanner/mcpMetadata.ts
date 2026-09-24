import * as fs from 'fs';
import * as path from 'path';
import { ToolMetadata } from '../types';

/**
 * Best-effort read of a tool's declared identity: package.json plus an
 * optional MCP manifest (mcp.json / mcp.manifest.json) if present. This is
 * informational only — it is never trusted as a source of truth for
 * capabilities, since a manifest can claim anything. Capabilities always
 * come from the static analyzer, not from what the tool says about itself.
 */
export function readMetadata(root: string): ToolMetadata | null {
  const stat = fs.existsSync(root) ? fs.statSync(root) : null;
  const dir = stat && stat.isDirectory() ? root : path.dirname(root);

  const pkgPath = path.join(dir, 'package.json');
  const mcpPath1 = path.join(dir, 'mcp.json');
  const mcpPath2 = path.join(dir, 'mcp.manifest.json');

  let name: string | undefined;
  let version: string | undefined;
  let description: string | undefined;
  let declaredTools: string[] | undefined;
  let found = false;

  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      name = pkg.name;
      version = pkg.version;
      description = pkg.description;
      found = true;
    } catch {
      // malformed package.json — ignore, not fatal to the scan
    }
  }

  const mcpFile = fs.existsSync(mcpPath1) ? mcpPath1 : fs.existsSync(mcpPath2) ? mcpPath2 : null;
  if (mcpFile) {
    try {
      const mcp = JSON.parse(fs.readFileSync(mcpFile, 'utf-8'));
      if (Array.isArray(mcp.tools)) {
        declaredTools = mcp.tools.map((t: any) => (t && t.name ? String(t.name) : String(t)));
      }
      name = name ?? mcp.name;
      description = description ?? mcp.description;
      found = true;
    } catch {
      // malformed MCP manifest — ignore, not fatal to the scan
    }
  }

  if (!found) return null;

  return { name, version, description, declaredTools, source: dir };
}
