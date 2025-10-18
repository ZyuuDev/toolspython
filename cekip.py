import socket
import requests
import json

try:
	hostname = input('Masukkan nama domain: ')
	ip_address = socket.gethostbyname(hostname)
	print(f'\nAlamat ip untuk {hostname} : {ip_address}\n')

	request_url = f'http://ip-api.com/json/{ip_address}'
	response = requests.get(request_url, timeout=5)
	response.raise_for_status()

	geolocation = response.json()

	print('=== Informasi Geolokasi ===')
	for k, v in geolocation.items():
	    print(f"{k} : {v}")

except socket.gaierror:
	print(" Domain tidak valid/tidak dapat ditemukan.")
except requests.RequestException as e:
	print(f"Gagal mengambil data geolokasi: {e}")
except json.JSONDecodeError:
	print("Gagal membaca data JSON dari API")


