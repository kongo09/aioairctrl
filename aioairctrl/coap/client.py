"""Client to interact with the aiocoap library."""
import json
import logging
import os
from typing import Optional

from aiocoap import (
    NON,
    Context,
    Message,
)
from aiocoap.numbers.codes import (
    GET,
    POST,
)

from aioairctrl.coap.encryption import EncryptionContext

logger = logging.getLogger(__name__)


class Client:
    STATUS_PATH = "/sys/dev/status"
    CONTROL_PATH = "/sys/dev/control"
    SYNC_PATH = "/sys/dev/sync"

    def __init__(self, host, port=5683):
        self.host = host
        self.port = port
        self._client_context: Optional[Context] = None
        self._encryption_context: Optional[EncryptionContext] = None

    async def _init(self):
        self._client_context = await Context.create_client_context()
        self._encryption_context = EncryptionContext()
        try:
            await self._sync()
        except Exception as ex:
            logger.error("Error during sync: %s", ex)
            await self._client_context.shutdown()
            raise ex

    @classmethod
    async def create(cls, *args, **kwargs):
        obj = cls(*args, **kwargs)
        await obj._init()
        return obj

    async def shutdown(self) -> None:
        if self._client_context:
            await self._client_context.shutdown()

    async def _sync(self):
        logger.debug("syncing")
        sync_request = os.urandom(4).hex().upper()
        request = Message(
            code=POST,
            mtype=NON,
            uri=f"coap://{self.host}:{self.port}{self.SYNC_PATH}",
            payload=sync_request.encode(),
        )
        assert self._client_context is not None
        response = await self._client_context.request(request).response
        client_key = response.payload.decode()
        logger.debug("synced: %s", client_key)
        assert self._encryption_context is not None
        self._encryption_context.set_client_key(client_key)

    async def get_status(self):
        logger.debug("retrieving status")
        request = Message(
            code=GET,
            mtype=NON,
            uri=f"coap://{self.host}:{self.port}{self.STATUS_PATH}",
        )
        request.opt.observe = 0
        assert self._client_context is not None
        response = await self._client_context.request(request).response
        payload_encrypted = response.payload.decode()
        assert self._encryption_context is not None
        payload = self._encryption_context.decrypt(payload_encrypted)
        logger.debug("status: %s", payload)
        state_reported = json.loads(payload)
        max_age = 60
        try:
            max_age = response.opt.max_age
            logger.debug(f"max age = {max_age}")
        except Exception:
            logger.debug("no max age found in CoAP options")
        return state_reported["state"]["reported"], max_age

    async def observe_status(self):
        def decrypt_status(response):
            payload_encrypted = response.payload.decode()
            assert self._encryption_context is not None
            payload = self._encryption_context.decrypt(payload_encrypted)
            logger.debug("observation status: %s", payload)
            status = json.loads(payload)
            return status["state"]["reported"]

        logger.debug("observing status")
        request = Message(
            code=GET,
            mtype=NON,
            uri=f"coap://{self.host}:{self.port}{self.STATUS_PATH}",
        )
        request.opt.observe = 0
        assert self._client_context is not None
        requester = self._client_context.request(request)
        response = await requester.response
        yield decrypt_status(response)
        assert requester.observation is not None
        async for response in requester.observation:
            yield decrypt_status(response)

    async def set_control_value(self, key, value, retry_count=5, resync=True) -> bool:
        return await self.set_control_values(
            data={key: value}, retry_count=retry_count, resync=resync
        )

    async def set_control_values(self, data: dict, retry_count=5, resync=True) -> bool:
        state_desired = {
            "state": {
                "desired": {
                    "CommandType": "app",
                    "DeviceId": "",
                    "EnduserId": "",
                    **data,
                }
            }
        }
        payload = json.dumps(state_desired)
        logger.debug("REQUEST: %s", payload)
        assert self._encryption_context is not None
        payload_encrypted = self._encryption_context.encrypt(payload)
        request = Message(
            code=POST,
            mtype=NON,
            uri=f"coap://{self.host}:{self.port}{self.CONTROL_PATH}",
            payload=payload_encrypted.encode(),
        )
        assert self._client_context is not None
        response = await self._client_context.request(request).response
        logger.debug("RESPONSE: %s", response.payload)
        result = json.loads(response.payload)
        if result.get("status") == "success":
            return True
        else:
            if resync:
                logger.debug("set_control_value failed. resyncing...")
                await self._sync()
            if retry_count > 0:
                logger.debug("set_control_value failed. retrying...")
                return await self.set_control_values(data, retry_count - 1, resync)
            logger.error("set_control_value failed: %s", data)
            return False
