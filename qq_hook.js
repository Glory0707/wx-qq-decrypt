// qq_hook.js — 定位并 hook QQ NT wrapper.node 中的 sqlite3_key_v2, 捕获数据库 passphrase
'use strict';

function findFuncStartByPdata(mod, leaRva) {
    // 解析 .pdata (RUNTIME_FUNCTION 数组, 每项 12 字节: Start/End/Unwind RVA)
    const sections = mod.enumerateSections();
    const pdata = mod.enumerateSections().find(s => s.name.toLowerCase() === '.pdata');
    if (!pdata) return null;
    const base = pdata.address;
    const size = pdata.size;
    const buf = base.readByteArray(size);
    const dv = new DataView(buf);
    let lo = 0, hi = size / 12 - 1, found = null;
    while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        const start = dv.getUint32(mid * 12, true);
        const end = dv.getUint32(mid * 12 + 4, true);
        if (leaRva < start) hi = mid - 1;
        else if (leaRva >= end) lo = mid + 1;
        else { found = [start, end]; break; }
    }
    return found ? mod.base.add(found[0]) : null;
}

function hookKeyFunctions() {
    const mod = Process.getModuleByName('wrapper.node');
    send({ type: 'info', msg: 'wrapper.node base=' + mod.base + ' size=' + mod.size });

    // 已知 RVA (9.9.35-52892 wrapper.node, 离线 capstone 反汇编确认): 直接秒挂
    const KNOWN_RVA = 0x21B8C80;
    const fn = mod.base.add(KNOWN_RVA);
    send({ type: 'info', msg: 'hooking known sqlite3_key_v2 @ ' + fn });
    Interceptor.attach(fn, {
        onEnter(args) {
            try {
                const pKey = this.context.r8;
                const nKey = this.context.r9.toInt32();
                let zdb = '';
                try { zdb = this.context.rdx.readCString(); } catch (e) { zdb = '?'; }
                if (nKey > 0 && nKey <= 256) {
                    const raw = pKey.readByteArray(nKey);
                    send({ type: 'key', pid: Process.id, len: nKey, db: zdb }, raw);
                }
            } catch (e) {
                send({ type: 'error', msg: 'read err: ' + e });
            }
        }
    });
    send({ type: 'info', msg: 'instant hook installed' });
}

function hookByScan() {

    // 1) 找字符串 "nt_sqlite3_key_v2" (在 .rdata)
    const pattern = '6e 74 5f 73 71 6c 69 74 65 33 5f 6b 65 79 5f 76 32';
    const secs = mod.enumerateSections();
    const hits = [];
    for (const s of secs) {
        const n = s.name.toLowerCase();
        if (n === '.rdata' || n === '.data') {
            try {
                hits.push(...Memory.scanSync(s.address, s.size, pattern));
            } catch (e) {
                send({ type: 'info', msg: 'scan skip ' + s.name + ': ' + e });
            }
        }
    }
    send({ type: 'info', msg: 'string hits: ' + hits.length });

    // 2) 在 .text 中分块找 LEA rip-relative 引用
    const text = mod.enumerateSections().find(s => s.name.toLowerCase() === '.text');
    if (!text) { send({ type: 'error', msg: 'no .text' }); return; }
    const textBase = text.address;
    const textSize = text.size;
    const textRva = textBase.sub(mod.base).toInt32();

    const CHUNK = 8 * 1024 * 1024, OVL = 16;
    const leas = [];  // {insnRva, insnAddr, disp}
    for (let off = 0; off < textSize; off += CHUNK - OVL) {
        const n = Math.min(CHUNK, textSize - off);
        let buf;
        try { buf = textBase.add(off).readByteArray(n); } catch (e) { continue; }
        if (!buf) continue;
        const bytes = new Uint8Array(buf);
        const dv = new DataView(buf);
        for (let i = 0; i + 7 <= bytes.length; i++) {
            if (bytes[i] !== 0x48 || bytes[i + 1] !== 0x8D) continue;
            const modrm = bytes[i + 2];
            if ((modrm & 0xC7) !== 0x05) continue;
            leas.push({ insnRva: textRva + off + i, addr: textBase.add(off + i), disp: dv.getInt32(i + 3, true) });
        }
    }
    send({ type: 'info', msg: 'lea candidates: ' + leas.length });

    const hooked = new Set();
    for (const hit of hits) {
        const target = hit.address;
        for (const lea of leas) {
            const next = lea.addr.add(7);
            if (!next.add(lea.disp).equals(target)) continue;
            const fn = findFuncStartByPdata(mod, lea.insnRva);
            if (!fn) { send({ type: 'info', msg: 'no func for lea @' + lea.insnRva }); continue; }
            const key = fn.toString();
            if (hooked.has(key)) continue;
            hooked.add(key);
            send({ type: 'info', msg: 'hooking sqlite3_key_v2 @ ' + fn });
            Interceptor.attach(fn, {
                onEnter(args) {
                    try {
                        const pKey = this.context.r8;
                        const nKey = this.context.r9.toInt32();
                        if (nKey > 0 && nKey <= 256) {
                            const raw = pKey.readByteArray(nKey);
                            send({ type: 'key', pid: Process.id, len: nKey }, raw);
                        }
                    } catch (e) {
                        send({ type: 'error', msg: 'read err: ' + e });
                    }
                }
            });
        }
    }
    send({ type: 'info', msg: 'hooked functions: ' + hooked.size });
}

// wrapper.node 是延迟加载的, 等它出现
const t0 = Date.now();
const timer = setInterval(() => {
    try {
        const m = Process.findModuleByName('wrapper.node');
        if (m) {
            clearInterval(timer);
            try { hookKeyFunctions(); } catch (e) { send({ type: 'error', msg: 'hook err: ' + e + '\\n' + e.stack }); }
        } else if (Date.now() - t0 > 120000) {
            clearInterval(timer);
            send({ type: 'error', msg: 'wrapper.node not loaded in 120s' });
        }
    } catch (e) { /* 进程早期枚举可能失败, 忽略 */ }
}, 300);
