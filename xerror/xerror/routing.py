from django.urls import re_path
from parsing.consumers import PoolConsumer

# WebSocket URL routing for Channels v3+ (ASGI). Maps websocket paths to
# the consumer class. Other legacy routing was removed in favor of URLRouter.

websocket_urlpatterns = [
    # connect clients to the pool consumer at ws/pool/
    re_path(r"ws/pool/?$", PoolConsumer.as_asgi()),
]
