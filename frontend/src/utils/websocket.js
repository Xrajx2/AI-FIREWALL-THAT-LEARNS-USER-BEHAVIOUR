import { buildWsUrl, getAuthToken } from './auth';

/**
 * Connect to the unified WebSocket endpoint with exponential backoff auto-reconnect (1s, 2s, 4s, ... up to 30s)
 * and token authentication on connect.
 */
export function createReconnectingWebSocket({
  path = '/api/ws/monitor',
  onMessage,
  onOpen,
  onClose,
  onError,
}) {
  let ws = null;
  let reconnectTimer = null;
  let reconnectAttempts = 0;
  let isClosedManually = false;

  const getBackoffDelay = (attempt) => {
    // 1s, 2s, 4s, 8s, 16s, max 30s
    const delay = 1000 * Math.pow(2, attempt);
    return Math.min(delay, 30000);
  };

  const connect = () => {
    if (isClosedManually) return;

    const token = getAuthToken();
    const wsUrl = `${buildWsUrl(path)}?token=${encodeURIComponent(token || '')}`;

    try {
      ws = new WebSocket(wsUrl);

      ws.onopen = (event) => {
        reconnectAttempts = 0;
        // Also send auth payload on connect for compatibility
        if (token) {
          try {
            ws.send(JSON.stringify({ type: 'auth', token }));
          } catch {
            // ignore
          }
        }
        if (onOpen) onOpen(event);
      };

      ws.onmessage = (event) => {
        if (onMessage) onMessage(event);
      };

      ws.onerror = (event) => {
        if (onError) onError(event);
      };

      ws.onclose = (event) => {
        if (onClose) onClose(event);
        if (!isClosedManually) {
          const delay = getBackoffDelay(reconnectAttempts);
          reconnectAttempts += 1;
          reconnectTimer = setTimeout(connect, delay);
        }
      };
    } catch (err) {
      if (!isClosedManually) {
        const delay = getBackoffDelay(reconnectAttempts);
        reconnectAttempts += 1;
        reconnectTimer = setTimeout(connect, delay);
      }
    }
  };

  connect();

  return {
    close: () => {
      isClosedManually = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) {
        try {
          ws.close();
        } catch {
          // ignore
        }
      }
    },
    send: (data) => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(typeof data === 'string' ? data : JSON.stringify(data));
      }
    },
    getWebSocket: () => ws,
  };
}
