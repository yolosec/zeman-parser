from bs4 import BeautifulSoup
import requests

headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}

resp = requests.get('https://www.fio.cz/ib2/transparent?a=2501277007', headers=headers)
soup = BeautifulSoup(resp.content, 'html.parser')