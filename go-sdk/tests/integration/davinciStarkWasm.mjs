import fs from 'node:fs/promises';
import path from 'node:path';

const input = JSON.parse(await new Promise((resolve, reject) => {
  let data = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => data += chunk);
  process.stdin.on('end', () => resolve(data));
  process.stdin.on('error', reject);
}));

const repoRoot = input.repo_root;
const jsPath = path.join(repoRoot, 'pkg', 'davinci_stark.js');
const wasmPath = path.join(repoRoot, 'pkg', 'davinci_stark_bg.wasm');
const mod = await import(pathToFileURL(jsPath));
await mod.default({ module_or_path: await fs.readFile(wasmPath) });

function hexToBytes(hex) {
  const clean = hex.replace(/^0x/, '');
  return Uint8Array.from(Buffer.from(clean, 'hex'));
}

if (input.command === 'generate-keypair') {
  const pk = mod.generate_keypair(hexToBytes(input.sk_hex));
  console.log(JSON.stringify({ pk_hex: Buffer.from(pk).toString('hex') }));
} else if (input.command === 'prove-full') {
  const result = mod.prove_full(
    hexToBytes(input.k_hex),
    hexToBytes(input.fields_le_hex),
    hexToBytes(input.pk_hex),
    hexToBytes(input.process_id_hex),
    hexToBytes(input.address_hex),
    hexToBytes(input.weight_hex),
    hexToBytes(input.ballot_mode_hex),
  );
  console.log(JSON.stringify({ proof_data_hex: Buffer.from(result).toString('hex') }));
} else {
  throw new Error(`unknown command: ${input.command}`);
}

function pathToFileURL(p) {
  const url = new URL('file://');
  url.pathname = path.resolve(p);
  return url.href;
}
