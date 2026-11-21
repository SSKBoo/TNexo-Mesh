import { readKey, writeKey } from "./storage.ts";
import type { UserProfile } from "./types.ts";

const KEY = "user_profile";

export function saveUserProfile(profile: UserProfile): void {
  writeKey(KEY, JSON.stringify(profile));
}

export function loadUserProfile(): UserProfile | null {
  const raw = readKey(KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as UserProfile;
  } catch {
    return null;
  }
}

export function clearUserProfile(): void {
  // storage has no removeKey exposed; write empty not ideal; rely on migrate? 
}
