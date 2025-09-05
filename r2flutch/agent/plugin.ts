/*
# Author : Murphy
# LICENSE: GPL v3
# Copyright (C) 2025 Murphy <me@0xmurphy.me>
*/

/// <reference types="@types/frida-gum" />

import ObjC from "frida-objc-bridge";
import type { DecryptedModule, EncryptionInfo, MachOHeader } from "./r2frida";

const MH_MAGIC_64 = 0xfeedfacf;

const commands = {
    dump: dump,
    "dump*": R2dump,
    getMainBundleName: getMainBundleName,
    getMainBundlePath: getMainBundlePath,
    getPID: getPID
};

r2frida.pluginRegister("r2flutch", function (name) {
    return commands[name];
});

function R2dump (args: string[]): string {
    const mods = dump(args);
    return mods.map(mod => {
        const addr = (parseInt(mod.base.toString(), 16) + parseInt(mod.encryption_info.cryptoff.toString(), 16)).toString(16);
        return `s 0x${addr}; wtf ${mod.name} ${mod.encryption_info.cryptsize}`;
    }).join("\n");
}

function dump (args: string[]): DecryptedModule[] {
    try{
        Process.getModuleByName("Foundation").ensureInitialized();
    } catch(e){
        Module.load("/System/Library/Frameworks/Foundation.framework/Foundation");
    }
    const decrypted_modules: DecryptedModule[] = [];
    const appModules = getAllAppModules(getMainBundlePath());
    for (let i = 0; i < appModules.length; i++) {
        const decrypted_module = getDecryptedRegion(appModules[i].name, appModules[i].path, appModules[i].base, appModules[i].size);
        if (decrypted_module !== null) {
            decrypted_modules.push(decrypted_module);
        }
    }
    return decrypted_modules;
}

function getDecryptedRegion (name: string, path: string, baseAddr: NativePointer, size: number): DecryptedModule | null {
    if (!isMachoHeaderAtOffset(baseAddr)) {
        throw new Error(`[X] Not a valid 64-bit Macho header at ${baseAddr.toString()}`);
    }
    const header = parseMachOHeader(baseAddr);
    if (!header) {
        throw new Error(`[X] Error parsing MachO header at ${baseAddr.toString()}`);
    }
    const LCEncryptionInfo = getEncryptionInfo(baseAddr, header.ncmds);
    if (LCEncryptionInfo !== null && LCEncryptionInfo.cryptid === 1) {
        return {
            name: name,
            base: baseAddr,
            path: path,
            size: size,
            encryption_info: LCEncryptionInfo
        };
    }
    return null;
}

function getMainBundlePath () {
    const MainBundle = ObjC.classes.NSBundle.mainBundle();
    const path = MainBundle.executablePath().toString();
    return path.substr(0, path.lastIndexOf("/"));
}

function getMainBundleName () {
    const MainBundle = ObjC.classes.NSBundle.mainBundle();
    const path = MainBundle.executablePath().toString();
    return path.substr(path.lastIndexOf("/") + 1);
}

function getAllAppModules (appPath: string) {
    const appModules: Array<Module> = [];
    const modules = Process.enumerateModules();
    for (let i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(appPath) !== -1) {
            appModules.push(modules[i]);
        }
    }
    return appModules;
}

function isMachoHeaderAtOffset (offset) {
    const cursor = trunc4k(offset);
    return (cursor.readU32() === MH_MAGIC_64);
}

function trunc4k (x) {
    return x.and(ptr("0xfff").not());
}

function parseMachOHeader (offset: NativePointer): MachOHeader {
    const header = {
        magic: offset.readU32(),
        cputype: offset.add(0x4).readU32(),
        cpusubtype: offset.add(0x8).readU32(),
        filetype: offset.add(0x0c).readU32(),
        ncmds: offset.add(0x10).readU32(),
        sizeofcmds: offset.add(0x14).readU32()
    };
    if (header.cputype !== 0x0100000c) {
        throw new Error("[X] sorry not a 64-bit app");
    }
    return header;
}

function getEncryptionInfo (baseAddr: NativePointer, ncmds: number): EncryptionInfo | null {
    let cursor = baseAddr.add(0x20);
    const LC_ENCRYPTION_INFO_64 = 0x2C;
    while (ncmds-- > 0) {
        const command = cursor.readU32();
        const cmdSize = cursor.add(4).readU32();
        if (command !== LC_ENCRYPTION_INFO_64) {
            cursor = cursor.add(cmdSize);
            continue;
        }
        
        return {
            addr: cursor.sub(baseAddr),
            cryptoff: cursor.add(0x8).readU32(),
            cryptsize: cursor.add(0xc).readU32(),
            cryptid: cursor.add(0x10).readU32()
        };
    }
    console.error(`[X] Unable to get encryption info at ${baseAddr.toString()}`);
    return null;
}

function getPID (): number {
    return Process.id;
}
