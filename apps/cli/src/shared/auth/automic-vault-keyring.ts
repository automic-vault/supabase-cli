import { spawnSync } from "node:child_process";
import process from "node:process";

import { resolveBinary } from "../legacy/go-proxy.layer.ts";

export interface AutomicVaultKeyring {
  get(account: string): string | null;
  set(account: string, value: string): boolean;
  delete(account: string): boolean;
  deleteAll(): boolean;
}

export function resolveAutomicVaultKeyring(): AutomicVaultKeyring | null {
  if (process.platform !== "darwin") return null;
  const resolved = resolveBinary();
  if (!("found" in resolved)) return null;
  const binary = resolved.found;

  return {
    get(account) {
      const result = spawnSync(binary, ["av-keyring", "get", account], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      });
      return result.status === 0 && result.stdout.length > 0 ? result.stdout : null;
    },
    set(account, value) {
      const result = spawnSync(binary, ["av-keyring", "set", account], {
        encoding: "utf8",
        input: value,
        stdio: ["pipe", "ignore", "ignore"],
      });
      return result.status === 0;
    },
    delete(account) {
      const result = spawnSync(binary, ["av-keyring", "delete", account], {
        encoding: "utf8",
        stdio: ["ignore", "ignore", "ignore"],
      });
      return result.status === 0;
    },
    deleteAll() {
      const result = spawnSync(binary, ["av-keyring", "delete-all"], {
        encoding: "utf8",
        stdio: ["ignore", "ignore", "ignore"],
      });
      return result.status === 0;
    },
  };
}
