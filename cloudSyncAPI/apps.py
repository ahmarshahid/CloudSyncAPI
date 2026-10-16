from django.apps import AppConfig


class CloudsyncapiConfig(AppConfig):
    name = 'cloudSyncAPI'

    def ready(self):
        from . import signals  # noqa: F401
