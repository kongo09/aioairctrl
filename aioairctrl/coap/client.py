"""Client to interact with the aiocoap library."""
import json
import logging
import os

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
        self._client_context: Context | None = None
        self._encryption_context: EncryptionContext | None = None

    @property
    def _ctx(self) -> Context:
        if self._client_context is None:
            raise RuntimeError("Client not initialized; use Client.create()")
        return self._client_context

    @property
    def _enc(self) -> EncryptionContext:
        if self._encryption_context is None:
            raise RuntimeError("Client not initialized; use Client.create()")
        return self._encryption_context

    async def _init(self):
        self._client_context = await Context.create_client_context()
        self._encryption_context = EncryptionContext()
        try:
            await self._sync()
        except BaseException:
            await self._client_context.shutdown()
            raise

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
        response = await self._ctx.request(request).response
        client_key = response.payload.decode()
        logger.debug("synced: %s", client_key)
        self._enc.set_client_key(client_key)

    async def get_status(self):
        logger.debug("retrieving status")
        request = Message(
            code=GET,
            mtype=NON,
            uri=f"coap://{self.host}:{self.port}{self.STATUS_PATH}",
        )
        request.opt.observe = 0
        response = await self._ctx.request(request).response
        payload_encrypted = response.payload.decode()
        payload = self._enc.decrypt(payload_encrypted)
        logger.debug("status: %s", payload)
        state_reported = json.loads(payload)
        max_age = 60
        if response.opt.max_age is not None:
            max_age = response.opt.max_age
            logger.debug("max age = %s", max_age)
        return state_reported["state"]["reported"], max_age

    async def observe_status(self):
        def decrypt_status(response):
            payload_encrypted = response.payload.decode()
            payload = self._enc.decrypt(payload_encrypted)
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
        requester = self._ctx.request(request)
        observation = requester.observation
        try:
            response = await requester.response
            yield decrypt_status(response)
            if observation is not None:
                async for response in observation:
                    yield decrypt_status(response)
        finally:
            if observation is not None:
                observation.cancel()

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
        for attempt in range(retry_count + 1):
            payload_encrypted = self._enc.encrypt(payload)
            request = Message(
                code=POST,
                mtype=NON,
                uri=f"coap://{self.host}:{self.port}{self.CONTROL_PATH}",
                payload=payload_encrypted.encode(),
            )
            response = await self._ctx.request(request).response
            logger.debug("RESPONSE: %s", response.payload)
            result = json.loads(response.payload)
            if result.get("status") == "success":
                return True
            if attempt == 0 and resync:
                logger.debug("set_control_value failed, resyncing...")
                await self._sync()
            else:
                logger.debug(
                    "set_control_value failed, retrying (attempt %d/%d)...",
                    attempt + 1,
                    retry_count,
                )
        logger.error("set_control_value failed: %s", data)
        return False
