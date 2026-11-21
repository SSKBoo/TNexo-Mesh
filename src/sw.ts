/// <reference lib="webworker" />

declare const self: ServiceWorkerGlobalScope;

self.addEventListener("push", (event: PushEvent) => {
  let data: { title?: string; body?: string; targetTab?: string } = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = { body: event.data?.text() };
  }
  const title = data.title ?? "NexoMesh";
  event.waitUntil(
    self.registration.showNotification(title, {
      body: data.body,
      data: { targetTab: data.targetTab ?? "/" },
    })
  );
});

self.addEventListener("notificationclick", (event: NotificationEvent) => {
  event.notification.close();
  const targetTab = (event.notification.data as { targetTab?: string })?.targetTab ?? "/";
  event.waitUntil(
    (async () => {
      const allClients = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      for (const client of allClients) {
        if ("focus" in client) {
          await client.focus();
          if ("navigate" in client) await (client as WindowClient).navigate(targetTab);
          return;
        }
      }
      await self.clients.openWindow(targetTab);
    })()
  );
});

self.addEventListener("pushsubscriptionchange", (event: any) => {
  event.waitUntil(
    (async () => {
      try {
        const sub = await self.registration.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: (self as any).__VAPID_PUBLIC_KEY,
        });
        await fetch("/push/subscribe", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(sub),
        });
      } catch (e) {
        console.error("pushsubscriptionchange failed", e);
      }
    })()
  );
});

export {};
