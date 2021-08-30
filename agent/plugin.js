'use strict';

const MH_MAGIC_64 = 0xfeedfacf;

const commands = {
  'dump': dump,
  'dump*': R2dump,
  'getMainBundleName': getMainBundleName
};

r2frida.pluginRegister('r2flutch', function (name) {
  return commands[name];
});

async function R2dump (args) {
  const mods = await dump(args);
  return mods.map(mod => {
    let addr = '0x' + (parseInt(mod.base, 16) + parseInt(mod.encryption_info.cryptoff, 10)).toString(16);
    return `s ${addr}; wtf ${mod.name} ${mod.encryption_info.cryptsize}`;
  }).join('\n');
}

function dump (args) {
  Module.ensureInitialized('Foundation');
  const result = [];
  const modules = getAllAppModules(getMainBundlePath());
  let r2cmds = [];
  return new Promise((resolve) => {
    for (let i = 0; i  < modules.length; i++) {
      getDecryptedRegion(modules[i].name, modules[i].path, modules[i].base, modules[i].size, result);
      resolve(result);
    }
  });
}

function getU32(addr) {
  if (typeof addr == "number") {
      addr = ptr(addr);
  }
  return Memory.readU32(addr);
}

function getDecryptedRegion(name, path, baseAddr, size, result) {
  const magic = getU32(baseAddr);
  if (!isMachoHeaderAtOffset(baseAddr)) {
    console.error('[X] Not a valid 64-bit Macho header at ' + baseAddr);
    return; 
  }
  const header = parseMachOHeader(baseAddr);
  if (!header) {
    console.error('[X] Error parsing MachO header at ' + baseAddr);
    return; 
  }
  const lc_encryption_info = getEncryptionInfo(baseAddr, header.ncmds);
  if (lc_encryption_info.cryptid == 1) {
    result.push({
      name: name,
      base: baseAddr,
      path: path,
      size: size,
      encryption_info: lc_encryption_info
    });
  }
  return;
}

function getMainBundlePath() {
  const main_bundle = ObjC.classes.NSBundle.mainBundle();
  const path = main_bundle.executablePath().toString();
  return path.substr(0, path.lastIndexOf("/"));
}

function getMainBundleName() {
  const main_bundle = ObjC.classes.NSBundle.mainBundle();
  const path = main_bundle.executablePath().toString();
  return path.substr(path.lastIndexOf("/") + 1);
}

function getAllAppModules(app_path) {
  let modules = new Array();
  let process_modules = Process.enumerateModulesSync();
  for (let i = 0; i < process_modules.length; i++) {
      if (process_modules[i].path.indexOf(app_path) != -1) {
          modules.push(process_modules[i]);
      }
  }
  return modules;
}

function isMachoHeaderAtOffset(offset) { 
  let cursor = trunc4k(offset);
  if (cursor.readU32() == MH_MAGIC_64) {
    return true;
  }
  return false;
} 

function trunc4k (x) {
  return x.and(ptr('0xfff').not());
}

function parseMachOHeader(offset) {
  let header = { 
    magic: offset.readU32(),
    cputype: offset.add(0x4).readU32(),
    cpusubtype: offset.add(0x8).readU32(),
    filetype: offset.add(0x0c).readU32(),
    ncmds: offset.add(0x10).readU32(),
    sizeofcmds: offset.add(0x14).readU32(),
  };
  if (header.cputype !== 0x0100000c) {
    console.error('[X] sorry not a 64-bit app');
    return null;
  }
  return header;
}

function getEncryptionInfo(baseAddr, ncmds) {
  let cursor = baseAddr.add(0x20);
  const LC_ENCRYPTION_INFO_64 = 0x2C;
  let lc_encryption_info = "";
  while (ncmds-- > 0) {
    let command = cursor.readU32();
    let cmdSize = cursor.add(4).readU32();
    if (command !== LC_ENCRYPTION_INFO_64) {
      cursor = cursor.add(cmdSize);
      continue;
    }

    lc_encryption_info = {
      addr: cursor.sub(baseAddr),
      cryptoff: cursor.add(0x8).readU32(),
      cryptsize: cursor.add(0xc).readU32(),
      cryptid: cursor.add(0x10).readU32(),
    };
  }
  return lc_encryption_info;
}
