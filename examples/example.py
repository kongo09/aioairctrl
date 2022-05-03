import asyncio
import logging

from aioairctrl import CoAPClient

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)


async def main():
    print("GETTING KEY (SYNC)")
    client = await CoAPClient.create(host="192.168.179.26")
    print(f"ID is {client._encryption_context._client_key}")

    print("GETTING STATUS")
    status = await client.get_status()
    print(status)

    print("TOGGLE POWER")
    power_state = int(status['pwr'])
    print(f"power is {power_state}")
    power_new = str(1 - power_state)
    await client.set_control_value(key='pwr', value=power_new)
    print(f"power set to {power_new}")

    print("GETTING STATUS")
    status = await client.get_status()
    print(status)

    # print("OBSERVING")
    # async for s in client.observe_status():
    #     print("GOT STATE")

    # await asyncio.sleep(10)
    await client.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
