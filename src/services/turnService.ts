const CACHE_TTL_MS = 55 * 60 * 1000;

interface TurnCredentials {
  username: string;
  password: string;
  ttl: number;
}

let cache: { value: TurnCredentials; expiresAt: number } | null = null;

export async function getTurnCredentials(
  fetchFn: typeof fetch = fetch,
  baseUrl: string = "/turn/credentials"
): Promise<TurnCredentials> {
  const now = Date.now();
  if (cache && cache.expiresAt > now) {
    return cache.value;
  }
  const res = await fetchFn(baseUrl);
  const data = (await res.json()) as TurnCredentials;
  cache = { value: data, expiresAt: now + CACHE_TTL_MS };
  return data;
}

export function clearTurnCache(): void {
  cache = null;
}
