/*
# Author : Murphy
# LICENSE: GPL v3
# Copyright (C) 2025 Murphy <me@0xmurphy.me>
*/

/// <reference types="@types/frida-gum" />

declare global {
  const r2frida: {
    pluginRegister: (pluginName: string, commandHandler: (name: string) => any) => void;
  };
}

export interface DecryptedModule {
  name: string;
  base: NativePointer;
  path: string;
  size: number;
  encryption_info: EncryptionInfo;
}

export interface EncryptionInfo {
  addr: NativePointer;
  cryptoff: number;
  cryptsize: number;
  cryptid: number;
}

export interface MachOHeader {
  magic: number;
  cputype: number;
  cpusubtype: number;
  filetype: number;
  ncmds: number;
  sizeofcmds: number;
}
