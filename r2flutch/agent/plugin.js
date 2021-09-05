'use strict';

const MH_MAGIC_64 = 0xfeedfacf;

const commands = {
  dump: dump,
  'dump*': R2dump,
  getMainBundleName: getMainBundleName
};

r2frida.pluginRegister('r2flutch', function (name) {
  return commands[name];
});

async function R2dump (args) {
  const mods = await dump(args);
  return mods.map(mod => {
    const addr = '0x' + (parseInt(mod.base, 16) + parseInt(mod.encryption_info.cryptoff, 10)).toString(16);
    return `s ${addr}; wtf ${mod.name} ${mod.encryption_info.cryptsize}`;
  }).join('\n');
}

async function dump (args) {
  Module.ensureInitialized('Foundation');
  const result = [];
  const modules = getAllAppModules(getMainBundlePath());
  for (let i = 0; i < modules.length; i++) {
    const res = await getDecryptedRegion(modules[i].name, modules[i].path, modules[i].base, modules[i].size, result);
    if (res) {
      result.push(res);
    }
  }
  return result;
}

function getDecryptedRegion (name, path, baseAddr, size) {
  if (!isMachoHeaderAtOffset(baseAddr)) {
    throw new Error('[X] Not a valid 64-bit Macho header at ' + baseAddr);
  }
  const header = parseMachOHeader(baseAddr);
  if (!header) {
    throw new Error('[X] Error parsing MachO header at ' + baseAddr);
  }
  const LCEncryptionInfo = getEncryptionInfo(baseAddr, header.ncmds);
  if (LCEncryptionInfo.cryptid === 1) {
    return {
      name: name,
      base: baseAddr,
      path: path,
      size: size,
      encryption_info: LCEncryptionInfo
    };
  }
}

function getMainBundlePath () {
  const MainBundle = ObjC.classes.NSBundle.mainBundle();
  const path = MainBundle.executablePath().toString();
  return path.substr(0, path.lastIndexOf('/'));
}

function getMainBundleName () {
  const MainBundle = ObjC.classes.NSBundle.mainBundle();
  const path = MainBundle.executablePath().toString();
  return path.substr(path.lastIndexOf('/') + 1);
}

function getAllAppModules (appPath) {
  const modules = [];
  const processModules = Process.enumerateModulesSync();
  for (let i = 0; i < processModules.length; i++) {
    if (processModules[i].path.indexOf(appPath) !== -1) {
      modules.push(processModules[i]);
    }
  }
  return modules;
}

function isMachoHeaderAtOffset (offset) {
  const cursor = trunc4k(offset);
  return (cursor.readU32() === MH_MAGIC_64);
}

function trunc4k (x) {
  return x.and(ptr('0xfff').not());
}

function parseMachOHeader (offset) {
  const header = {
    magic: offset.readU32(),
    cputype: offset.add(0x4).readU32(),
    cpusubtype: offset.add(0x8).readU32(),
    filetype: offset.add(0x0c).readU32(),
    ncmds: offset.add(0x10).readU32(),
    sizeofcmds: offset.add(0x14).readU32()
  };
  if (header.cputype !== 0x0100000c) {
    throw new Error('[X] sorry not a 64-bit app');
  }
  return header;
}

function getEncryptionInfo (baseAddr, ncmds) {
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
}
