"""
ASGI entrypoint file for default channel layer.
Points to the channel layer configured as "default" so you can point
ASGI applications at "liveblog.asgi:channel_layer" as their channel layer.
"""

import os
from django.core.asgi import get_asgi_application

# Channels and ASGI imports
from channels.routing import ProtocolTypeRouter, URLRouter
import xerror.routing as routing

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xerror.settings")


# Build an ASGI application that routes protocol types. HTTP goes to the
# standard Django ASGI application. WebSocket traffic is routed through
# Channels' URLRouter using the websocket_urlpatterns defined in
# `xerror.routing` (which imports parsing.consumers.PoolConsumer).
#
# This is a minimal, compatible Channels v3 setup suitable for development.
application = ProtocolTypeRouter({
	"http": get_asgi_application(),
	"websocket": URLRouter(routing.websocket_urlpatterns),
})
