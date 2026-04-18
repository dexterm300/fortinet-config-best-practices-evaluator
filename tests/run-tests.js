#!/usr/bin/env node
// Lightweight test runner with zero dependencies.
// Extracts the <script> block from index.html, evaluates the parser + RULES in
// a fake-browser context, then runs assertions against them.

const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
if (!scriptMatch) {
    console.error('Could not locate <script> block in index.html');
    process.exit(1);
}

// Stub the tiny amount of DOM/browser API the script touches at load time.
// The DOMContentLoaded handler contains all the UI wiring, so we stub the
// listener and never fire it.
const sandbox = {
    window: {},
    document: { addEventListener: () => {}, getElementById: () => null, querySelector: () => null, querySelectorAll: () => [] },
    console,
};
sandbox.window.FortiEval = null;

const vm = require('vm');
const ctx = vm.createContext(sandbox);
vm.runInContext(scriptMatch[1], ctx, { filename: 'index.html#script' });

const { parseFortiOSConfig, RULES, getSetting, allEditBlocks } = sandbox.window.FortiEval;

// --- Test harness ---
let passed = 0, failed = 0;
const failures = [];
function test(name, fn) {
    try {
        fn();
        passed++;
        process.stdout.write('.');
    } catch (err) {
        failed++;
        failures.push({ name, err });
        process.stdout.write('F');
    }
}
function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }
function assertEqual(a, b, msg) {
    if (a !== b) throw new Error(`${msg || 'expected equal'}: got ${JSON.stringify(a)} vs ${JSON.stringify(b)}`);
}

// --- Parser tests ---
test('parser: basic section + set', () => {
    const p = parseFortiOSConfig(`config system global\n  set admintimeout 5\nend\n`);
    assertEqual(p.legacy['config system global'].admintimeout, '5');
    assertEqual(p.tree.sections['config system global'].settings.admintimeout, '5');
});

test('parser: strips inline comments', () => {
    const p = parseFortiOSConfig(`config system global\n  set admintimeout 480   # FLAW: too long\nend\n`);
    assertEqual(getSetting(p, 'config system global', 'admintimeout'), '480');
});

test('parser: preserves # inside quoted values', () => {
    const p = parseFortiOSConfig(`config system global\n  set hostname "my#host"\nend\n`);
    assertEqual(getSetting(p, 'config system global', 'hostname'), 'my#host');
});

test('parser: multi-word quoted values', () => {
    const p = parseFortiOSConfig(`config firewall address\n  edit "My Server"\n    set subnet 10.0.0.0 255.0.0.0\n  next\nend\n`);
    const edits = p.tree.sections['config firewall address'].edits;
    assert(edits['My Server'], 'edit block with spaces in name should exist');
    assertEqual(edits['My Server'].settings.subnet, '10.0.0.0 255.0.0.0');
});

test('parser: nested edit blocks', () => {
    const p = parseFortiOSConfig(`config system interface\n  edit "wan1"\n    set ip 1.2.3.4 255.255.255.0\n    set allowaccess ping https\n  next\n  edit "port2"\n    set ip 10.0.0.1 255.255.255.0\n  next\nend\n`);
    const edits = p.tree.sections['config system interface'].edits;
    assertEqual(Object.keys(edits).length, 2);
    assertEqual(edits.wan1.settings.allowaccess, 'ping https');
});

test('parser: CRLF line endings', () => {
    const p = parseFortiOSConfig("config system global\r\n  set admintimeout 5\r\nend\r\n");
    assertEqual(getSetting(p, 'config system global', 'admintimeout'), '5');
});

test('parser: unset removes key', () => {
    const p = parseFortiOSConfig(`config system global\n  set admintimeout 5\n  unset admintimeout\nend\n`);
    assertEqual(getSetting(p, 'config system global', 'admintimeout'), undefined);
});

// --- Rule correctness tests ---
function evalRule(id, text) {
    const rule = RULES.find(r => r.id === id);
    if (!rule) throw new Error(`rule ${id} not found`);
    return !!rule.evaluate(parseFortiOSConfig(text), text);
}

test('rule cis-1.1: admintimeout=5 passes', () => {
    assert(evalRule('cis-1.1', `config system global\n  set admintimeout 5\nend\n`));
});
test('rule cis-1.1: admintimeout=480 fails', () => {
    assert(!evalRule('cis-1.1', `config system global\n  set admintimeout 480\nend\n`));
});

test('rule cis-1.2: trusthost found passes', () => {
    assert(evalRule('cis-1.2', `config system admin\n  edit "admin"\n    set trusthost1 192.168.1.0 255.255.255.0\n  next\nend\n`));
});
test('rule cis-1.2: no trusthost fails', () => {
    assert(!evalRule('cis-1.2', `config system admin\n  edit "admin"\n    set password "abc"\n  next\nend\n`));
});

test('rule cis-1.5: either non-default port is enough (fix for OR bug)', () => {
    // Previously required BOTH to change; now either one suffices.
    assert(evalRule('cis-1.5', `config system global\n  set admin-sport 4443\nend\n`));
    assert(evalRule('cis-1.5', `config system global\n  set admin-port 8080\nend\n`));
    assert(!evalRule('cis-1.5', `config system global\n  set admin-sport 443\n  set admin-port 80\nend\n`));
});

test('rule ftnt-2.1: lockout threshold 0 fails, >0 passes', () => {
    assert(!evalRule('ftnt-2.1', `config system global\n  set admin-lockout-threshold 0\nend\n`));
    assert(evalRule('ftnt-2.1', `config system global\n  set admin-lockout-threshold 3\nend\n`));
});

test('rule ftnt-2.2: ssh-v1 enable fails', () => {
    assert(!evalRule('ftnt-2.2', `config system global\n  set admin-ssh-v1 enable\nend\n`));
    assert(evalRule('ftnt-2.2', `config system global\n  set admin-ssh-v1 disable\nend\n`));
});

test('rule ftnt-3.1: http/telnet on any interface fails', () => {
    assert(!evalRule('ftnt-3.1', `config system interface\n  edit "wan1"\n    set allowaccess ping http telnet\n  next\nend\n`));
    assert(evalRule('ftnt-3.1', `config system interface\n  edit "wan1"\n    set allowaccess ping https ssh\n  next\nend\n`));
});

test('rule ftnt-4.1: all-to-all accept with ALL service fails', () => {
    const bad = `config firewall policy\n  edit 1\n    set srcaddr "all"\n    set dstaddr "all"\n    set service "ALL"\n    set action accept\n  next\nend\n`;
    assert(!evalRule('ftnt-4.1', bad));
    const good = `config firewall policy\n  edit 1\n    set srcaddr "Web_Servers"\n    set dstaddr "App_Servers"\n    set service "HTTPS"\n    set action accept\n  next\nend\n`;
    assert(evalRule('ftnt-4.1', good));
});

test('rule ftnt-4.2: logtraffic disable on accept fails', () => {
    const bad = `config firewall policy\n  edit 1\n    set srcaddr "a"\n    set dstaddr "b"\n    set service "HTTPS"\n    set action accept\n    set logtraffic disable\n  next\nend\n`;
    assert(!evalRule('ftnt-4.2', bad));
});

test('rule ftnt-5.1: fwpolicy-implicit-deny disable fails', () => {
    assert(!evalRule('ftnt-5.1', `config log setting\n  set fwpolicy-implicit-deny disable\nend\n`));
    assert(evalRule('ftnt-5.1', `config log setting\n  set fwpolicy-implicit-deny enable\nend\n`));
});

// --- Integration test against sample file ---
test('integration: sample-very-flawed-config-ftnt.conf trips many rules', () => {
    const raw = fs.readFileSync(path.join(__dirname, '..', 'sample-very-flawed-config-ftnt.conf'), 'utf8');
    const parsed = parseFortiOSConfig(raw);
    const results = RULES.map(r => ({ id: r.id, pass: !!r.evaluate(parsed, raw) }));
    const failCount = results.filter(r => !r.pass).length;
    // The sample is intentionally flawed; at least 10 of the 15 rules should fail.
    assert(failCount >= 10, `expected ≥10 failures, got ${failCount}: ${JSON.stringify(results)}`);
});

// --- Summary ---
console.log(`\n\n${passed} passed, ${failed} failed`);
if (failures.length) {
    for (const f of failures) console.error(`\n✗ ${f.name}\n  ${f.err.message}`);
    process.exit(1);
}
