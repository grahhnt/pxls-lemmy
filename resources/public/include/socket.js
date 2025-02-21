let user;

const WEBSOCKET_HEARTBEAT_MS = 5000;

// this object is takes care of the websocket connection
module.exports.socket = (function () {
  const self = {
    lastPacket: new Date().getTime(),
    heartbeatInterval: null,
    reconnectAttempts: 0,

    ws: null,
    hooks: [],
    sendQueue: [],
    wps: WebSocket.prototype.send, // make sure we have backups of those....
    wpc: WebSocket.prototype.close,
    ws_open_state: WebSocket.OPEN,
    reconnect: function () {
      $("#reconnecting").show();
      if (self.reconnectAttempts < 5) {
        console.info("Disconnected from websocket; reconnecting...");
        self.reconnectSocket();
      } else {
        console.error(
          "Max reconnect attempts exceeded; doing a full reload in 3 seconds"
        );
        setTimeout(() => {
          window.location.reload();
        }, 3000);
      }
    },
    reconnectSocket: function () {
      self.reconnectAttempts++;
      self.ws.onclose = function () {};
      self.connectSocket();
    },
    connectSocket: function () {
      const l = window.location;
      const url =
        (l.protocol === "https:" ? "wss://" : "ws://") +
        l.host +
        l.pathname +
        "ws";
      self.ws = new WebSocket(url);
      self.ws.onopen = (evt) => {
        $("#reconnecting").hide();
        setTimeout(() => {
          while (self.sendQueue.length > 0) {
            const toSend = self.sendQueue.shift();
            self.send(toSend);
          }
        }, 0);

        if (self.heartbeatInterval) clearInterval(self.heartbeatInterval);
        self.heartbeatInterval = setInterval(() => {
          if (
            new Date().getTime() - self.lastPacket >=
            WEBSOCKET_HEARTBEAT_MS
          ) {
            self.send({ type: "heartbeat" });
          } else {
            console.info(
              "No need for heartbeat",
              new Date().getTime(),
              self.lastPacket,
              new Date().getTime() - self.lastPacket
            );
          }
        }, WEBSOCKET_HEARTBEAT_MS);
      };
      self.ws.onmessage = function (msg) {
        const data = JSON.parse(msg.data);
        $.map(self.hooks, function (h) {
          if (h.type === data.type) {
            h.fn(data);
          }
        });
      };
      self.ws.onclose = function () {
        self.reconnect();
      };
    },
    init: function () {
      user = require("./user").user;

      if (self.ws !== null) {
        return; // already inited!
      }
      self.connectSocket();

      $(window).on("beforeunload", function () {
        self.ws.onclose = function () {};
        self.close();
      });

      $("#board-container").show();
      $("#ui").show();
      $("#loading").fadeOut(500);
      user.wsinit();
    },
    on: function (type, fn) {
      self.hooks.push({
        type: type,
        fn: fn,
      });
    },
    close: function () {
      self.ws.close = self.wpc;
      self.ws.close();
    },
    send: function (s) {
      const toSend = typeof s === "string" ? s : JSON.stringify(s);
      if (self.ws == null || self.ws.readyState !== self.ws_open_state) {
        self.sendQueue.push(toSend);
      } else {
        self.ws.send = self.wps;
        self.ws.send(toSend);
        self.lastPacket = new Date().getTime();
      }
    },
  };
  return {
    init: self.init,
    on: self.on,
    send: self.send,
    close: self.close,
    reconnect: self.reconnect,
    reconnectSocket: self.reconnectSocket,
  };
})();
