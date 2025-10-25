(function(){
  // Shared WebSocket initializer for /ws/pool/
  // Requires ReconnectingWebSocket to be loaded already.
  var ws_scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
  var ws_path = ws_scheme + '://' + window.location.host + '/ws/pool/';
  console.log('Connecting to ' + ws_path);
  try {
    var socket = new ReconnectingWebSocket(ws_path);
  } catch (e) {
    console.error('ReconnectingWebSocket not available', e);
    return;
  }

  socket.onmessage = function(message) {
    var data = null;
    try { data = JSON.parse(message.data); } catch (e) { console.error('Invalid JSON', e); return; }
    // Dispatch a DOM event so pages can handle messages without duplicating connection logic
    var ev = new CustomEvent('xerror:wsmessage', { detail: data });
    document.dispatchEvent(ev);
  };

  socket.onopen = function(){ console.log('xerror ws connected'); };
  socket.onclose = function(){ console.log('xerror ws closed'); };

  window.xerrorWS = window.xerrorWS || {};
  window.xerrorWS.socket = socket;
})();
