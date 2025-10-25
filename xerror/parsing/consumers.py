"""ASGI WebSocket consumer for Channels v3+.

This provides a minimal replacement for the old "function-based" consumers
that used the legacy channels API (Group, route). It implements a simple
pool broadcast group so the rest of the app can send/receive messages for
development/testing.

To keep changes minimal, the consumer name is `PoolConsumer` and exposes
the same high-level behaviour: clients join the "pool" group on connect,
are removed on disconnect, and any received message is broadcast to the
group as JSON containing 'message' and 'sender'.
"""

import json
from channels.generic.websocket import AsyncWebsocketConsumer


class PoolConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # join the shared pool group
        await self.channel_layer.group_add("pool", self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        # leave the pool group
        await self.channel_layer.group_discard("pool", self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        # Broadcast received text to everyone in the pool group
        payload = text_data or ''
        try:
            # if text is JSON and contains 'message' keep it, otherwise wrap
            message_text = json.loads(payload).get('message') if payload else ''
        except Exception:
            message_text = payload

        await self.channel_layer.group_send(
            "pool",
            {
                "type": "pool.message",
                "message": json.dumps({"message": message_text, "sender": self.channel_name}),
            },
        )

    async def pool_message(self, event):
        # handler for messages sent to the group
        await self.send(text_data=event.get('message', ''))

