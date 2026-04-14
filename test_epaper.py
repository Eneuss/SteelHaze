#!/usr/bin/env python3
"""
Quick test: display project name + IP on the e-paper screen.
Run with: sudo python test_epaper.py
"""
import socket

print("Importing waveshare driver...")
from waveshare_epd import epd2in13_V4
from PIL import Image, ImageDraw, ImageFont
print("Import OK")

def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '?.?.?.?'

ip = get_ip()
print(f"IP: {ip}")

print("Initializing display...")
epd = epd2in13_V4.EPD()
epd.init()
epd.Clear(0xFF)
print("Display cleared")

img = Image.new('1', (250, 122), 255)
d = ImageDraw.Draw(img)

try:
    font_big = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', 28)
    font_small = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 16)
except Exception:
    font_big = ImageFont.load_default()
    font_small = ImageFont.load_default()

d.text((10, 20), 'SteelHaze', font=font_big, fill=0)
d.text((10, 65), f'IP: {ip}', font=font_small, fill=0)

print("Sending image to display...")
epd.display(epd.getbuffer(img))
print("Done! Screen should show SteelHaze + IP now.")
epd.sleep()
