import nmap
from getmac import get_mac_address
from telegram import Bot
import asyncio

IP = '192.168.1.1'
KNOWN_DEVICES = ["put your devices mac addres here seperated by quatation marks followd by comma" ]
TELEGRAM_BOT_TOKEN = "Put your geted tokens from telegram's botfather"
CHAT_ID = "Put your geted tokens from telegram's botfather"

class NetworkScanner:

    def __init__(self, ip: str):
        self.ip = ip
        self.connected_devices = set()

    def scan(self):
        network = f"{self.ip}/24"
        nm = nmap.PortScanner()

        while True:
            nm.scan(hosts=network, arguments='-sn')
            host_list = nm.all_hosts()

            for host in host_list:
                mac = get_mac_address(ip=host)
                print(mac)

                if mac and mac not in self.connected_devices and mac not in KNOWN_DEVICES:
                    print("new Device Found: ")
                    self.notify_new_devices(mac)
                    self.connected_devices.add(mac)

    async def send_telegram_message(self, bot, chat_id, message):
        await bot.send_message(chat_id=chat_id, text=message)

    def notify_new_devices(self, mac):
        bot = Bot(token=TELEGRAM_BOT_TOKEN)
        asyncio.run(self.send_telegram_message(bot, CHAT_ID, f"New Device Connected! MAC Address : {mac}"))


if __name__ == "__main__":
    scanner = NetworkScanner(IP)
    scanner.scan()