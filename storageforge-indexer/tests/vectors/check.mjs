// Runs capacity.json through the planner's own functions, cut from planner.js. Prints what disagrees; exits 1 if any does.
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const here = new URL('.', import.meta.url);
const planner = readFileSync(new URL('../../storageforge_index/static/planner.js', here), 'utf8');
const start = planner.indexOf('function raidzEff');
const end = planner.indexOf('\n}\n', planner.indexOf('function calcEngine')) + 3;
const context = { MiB: 2 ** 20, GiB: 2 ** 30, sum: (a) => a.reduce((x, y) => x + y, 0), fmtBin: String, fmtDec: String };
vm.createContext(context);
vm.runInContext(planner.slice(start, end) + ';this.calcEngine=calcEngine', context);

const close = (a, b) => Math.abs(a - b) <= Math.max(1, Math.abs(b) * 1e-9);
let bad = 0;
for (const v of JSON.parse(readFileSync(new URL('capacity.json', here), 'utf8'))) {
  const r = context.calcEngine({ layout: `${v.kind}-${v.level}`, sizes: v.sizes, width: v.width, fs: v.fs, reserve: v.reserve ?? true,
    recordsize: v.recordsize ?? 131072, ashift: v.ashift ?? 12, fill: 1, speed: 150, ure: 1e-15 });
  if (!close(r.usable, v.usable) || r.tol !== v.tolerance) {
    bad++;
    console.log(`${v.name}: planner says usable ${r.usable}, tolerance ${r.tol}; expected ${v.usable}, ${v.tolerance}`);
  }
}
process.exit(bad ? 1 : 0);
