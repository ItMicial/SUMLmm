import pandas as pd
from scipy.io import arff
import numpy as np
import requests
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import streamlit as st
import re
import ssl
import socket
import whois

# Inicjalizacja stanu aplikacji w Streamlit
if "is_safe" not in st.session_state:
    st.session_state["is_safe"] = 1  # Domyślna wartość (np. URL podejrzany)

if "URL_list" not in st.session_state:
    st.session_state["URL_list"] = []  # Inicjalizacja pustej listy, jeśli nie istnieje

# Funkcja reagująca na zmianę wyboru w `selectbox`
def on_select_change():
    st.session_state["is_safe"] = 0

st.sidebar.title("Panel boczny")
selected_option = st.sidebar.selectbox("Wybierz opcję",
                                       ["Sprawdź URL", "Zobacz Historię"],
                                       on_change=on_select_change)

class PhishingFeatureExtractor:
    def extract_features(self, url):
        features = []
        features.append(self.contains_ip(url))
        features.append(self.url_length(url))
        features.append(self.uses_shortening_service(url))
        features.append(self.contains_at_symbol(url))
        features.append(self.contains_double_slash_redirect(url))
        features.append(self.contains_prefix_suffix(url))
        features.append(self.subdomain_count(url))
        features.append(self.ssl_final_state(url))
        features.append(self.domain_registration_length(url))
        features.append(self.favicon(url))
        features.append(self.uses_non_standard_port(url))
        features.append(self.contains_https_token(url))
        features.append(self.request_url(url))
        features.append(self.url_of_anchor(url))
        features.append(self.links_in_tags(url))
        features.append(self.sfh(url))
        features.append(self.submitting_to_email(url))
        features.append(self.abnormal_url(url))
        features.append(self.redirect(url))
        features.append(self.on_mouseover(url))
        features.append(self.right_click(url))
        features.append(self.pop_up_window(url))
        features.append(self.iframe(url))
        features.append(self.age_of_domain(url))
        features.append(self.dns_record(url))
        features.append(self.web_traffic(url))
        features.append(self.page_rank(url))
        features.append(self.google_index(url))
        features.append(self.links_pointing_to_page(url))
        features.append(self.statistical_report(url))
        return features

    def contains_ip(self, url):
        ip_pattern = re.compile(r"^(https?://)?(\d{1,3}\.){3}\d{1,3}")
        return 1 if ip_pattern.search(url) else -1

    def url_length(self, url):
        length = len(url)
        if length >= 54:
            return -1
        elif 40 <= length < 54:
            return 0
        return 1

    def uses_shortening_service(self, url):
        shortening_services = ["bit.ly", "tinyurl", "t.co", "goo.gl"]
        return 1 if any(service in url for service in shortening_services) else -1

    def contains_at_symbol(self, url):
        return 1 if "@" in url else -1

    def contains_double_slash_redirect(self, url):
        if "//" in url.split("//", 1)[-1]:
            return 1
        return -1

    def contains_prefix_suffix(self, url):
        domain = re.findall(r"https?://([^/]+)/?", url)
        if domain and "-" in domain[0]:
            return -1
        return 1

    def subdomain_count(self, url):
        domain = re.findall(r"https?://([^/]+)/?", url)
        if domain:
            subdomains = domain[0].split(".")
            if len(subdomains) > 3:
                return -1
            elif len(subdomains) == 3:
                return 0
        return 1

    def ssl_final_state(self, url):
        try:
            # Pobieranie hosta z URL
            if not url.startswith("https://"):
                url = f"https://{url.lstrip('http://')}"
            hostname = url.replace("https://", "").split('/')[0]

            # Ustawienie kontekstu SSL
            context = ssl.create_default_context()

            # Połączenie z serwerem
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        return 1  # Certyfikat jest ważny
        except ssl.SSLError:
            return 0  # Certyfikat jest nieważny
        except Exception:
            return -1  # Błąd, brak certyfikatu lub nie można zweryfikować

    def domain_registration_length(self, url):
        domain_expiry_date = self.get_domain_expiry_date(url)
        if not domain_expiry_date:
            return -1  # Assume phishing if the expiry date can't be determined

        time_to_expiry = (domain_expiry_date - datetime.now()).days
        return -1 if time_to_expiry <= 365 else 1

    def get_domain_expiry_date(self, url):
        try:
            domain_info = whois.whois(url)
            expiry_date = domain_info.expiration_date
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]
            return expiry_date if isinstance(expiry_date, datetime) else None
        except Exception as e:
            print(f"Error retrieving domain info for {url}: {e}")
            return None

    def favicon(self, url):
        base_domain = urlparse(url).netloc

        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')

            favicon_tag = soup.find('link', rel='icon')

            if favicon_tag:
                favicon_url = favicon_tag.get('href')

                if not favicon_url.startswith('http'):
                    favicon_url = urlparse(url)._replace(path=favicon_url).geturl()

                favicon_domain = urlparse(favicon_url).netloc

                if base_domain != favicon_domain:
                    return -1  # Favicon loaded from a different domain
                else:
                    return 1  # Favicon loaded from the same domain

            else:
                return -1

        except requests.exceptions.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return -1

    def uses_non_standard_port(self, url):
        parsed_url = urlparse(url)

        if parsed_url.port:
            port = parsed_url.port
        else:
            port = 443 if parsed_url.scheme == "https" else 80

        if port in [80, 443]:
            return 1
        else:
            return -1

    def contains_https_token(self, url):
        domain = re.findall(r"https?://([^/]+)/?", url)
        if domain and "https" in domain[0].lower():
            return -1
        return 1

    def request_url(self, url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')

            total_tags = 0
            external_resources = 0

            tags = soup.find_all(['img', 'script', 'link', 'iframe'])
            total_tags = len(tags)

            for tag in tags:
                src = tag.get('src') or tag.get('href')
                if src and src.startswith('http'):
                    resource_domain = urlparse(src).netloc
                    page_domain = urlparse(url).netloc
                    if resource_domain != page_domain:
                        external_resources += 1

            if total_tags == 0:
                return 1

            external_percentage = (external_resources / total_tags) * 100

            if external_percentage < 22:
                return 1
            elif 22 <= external_percentage < 61:
                return 0
            else:
                return -1

        except requests.exceptions.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return -1

    def url_of_anchor(self, url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')

            anchors = soup.find_all('a')
            external_anchors = 0
            total_anchors = len(anchors)

            for anchor in anchors:
                href = anchor.get('href', '')
                if href.startswith('http'):
                    anchor_domain = urlparse(href).netloc
                    page_domain = urlparse(url).netloc
                    if anchor_domain != page_domain:
                        external_anchors += 1

            if total_anchors == 0:
                return 1

            external_percentage = (external_anchors / total_anchors) * 100

            if external_percentage < 31:
                return 1
            elif 31 <= external_percentage <= 67:
                return 0
            else:
                return -1

        except requests.exceptions.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return -1

    def links_in_tags(self, url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')

            tags = soup.find_all(['meta', 'script', 'link'])
            external_links = 0
            total_tags = len(tags)

            for tag in tags:
                href_or_src = tag.get('href') or tag.get('src')
                if href_or_src and href_or_src.startswith('http'):
                    link_domain = urlparse(href_or_src).netloc
                    page_domain = urlparse(url).netloc
                    if link_domain != page_domain:
                        external_links += 1

            if total_tags == 0:
                return 1

            external_percentage = (external_links / total_tags) * 100

            if external_percentage < 17:
                return 1
            elif 17 <= external_percentage <= 81:
                return 0
            else:
                return -1

        except requests.exceptions.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return -1

    def sfh(self, url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')

            forms = soup.find_all('form')

            for form in forms:
                sfh = form.get('action', '').strip()

                if sfh in ['', 'about:blank']:
                    return -1

                if sfh.startswith('http'):
                    form_domain = urlparse(sfh).netloc
                    page_domain = urlparse(url).netloc
                    if form_domain != page_domain:
                        return 0

            return 1

        except requests.exceptions.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return -1

    def submitting_to_email(self, url):
        if "mailto:" in url or "@" in url:
            return -1
        return 1

    def abnormal_url(self, url):
        parsed_url = urlparse(url)
        if not parsed_url.netloc or parsed_url.netloc not in url:
            return -1
        return 1

    def redirect(self, url):
        redirect_count = url.count("//")
        if redirect_count >= 4:
            return -1
        elif 2 <= redirect_count < 4:
            return 0
        else:
            return 1

    def on_mouseover(self, url):
        if "onmouseover" in url:
            return -1
        return 1

    def right_click(self, url):
        if "event.button==2" in url:
            return -1
        return 1

    def pop_up_window(self, url):
        if "popup" in url:
            return -1
        return 1

    def iframe(self, url):
        if "iframe" in url and "frameborder=0" in url:
            return -1
        return 1

    def age_of_domain(self, url):
        domain_expiry_date = self.get_domain_expiry_date(url)
        if domain_expiry_date:
            age = (datetime.now() - domain_expiry_date).days
            return 1 if age > 180 else -1
        return -1

    def dns_record(self, url):
        try:
            domain = urlparse(url).netloc
            socket.gethostbyname(domain)
            return 1
        except Exception:
            return -1

    def web_traffic(self, url):
        return 1  # Placeholder

    def page_rank(self, url):
        return 1  # Placeholder

    def google_index(self, url):
        search_query = f"https://www.google.com/search?q=site:{url}"

        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            response = requests.get(search_query, headers=headers)

            if "did not match any documents" in response.text:
                return -1
            else:
                return 1
        except Exception as e:
            print(f"Error while checking Google index: {e}")
            return -1

    def links_pointing_to_page(self, url):
        return 1  # Placeholder

    def statistical_report(self, url):
        return 1  # Placeholder

# Funkcja dodająca URL do listy i wykonująca predykcję
def add_item():
    url = st.session_state.get("new_URL", "")

    if url:
        extractor = PhishingFeatureExtractor()
        features = extractor.extract_features(url)
        features_array = np.array(features).reshape(1, -1)
        prediction = forest.predict(features_array)[0]

        if prediction == 1:
            st.session_state["is_safe"] = 2
        else:
            st.session_state["is_safe"] = 1

        if url not in st.session_state["URL_list"]:
            st.session_state["URL_list"].append(url)

    st.session_state["new_URL"] = ""

# Wczytanie danych i trenowanie modelu
with open('Data/Training_Dataset.arff', 'r') as f:
    data, meta = arff.loadarff(f)

data_list = data.tolist()
df = pd.DataFrame(data_list)
df.columns = meta.names()

for col in df.columns:
    df[col] = df[col].apply(lambda x: x.decode() if type(x) == bytes else x)

df = df.astype(int)

X = df.drop('Result', axis=1)
y = df['Result']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

forest = RandomForestClassifier()
forest.fit(X_train, y_train)

y_pred = forest.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

if selected_option == "Sprawdź URL":
    st.title("Sprawdź URL")
    st.text_input("Wpisz URL:", key="new_URL", on_change=add_item)

    if st.session_state.is_safe == 2:
        st.success("URL wydaje się bezpieczny")
    elif st.session_state.is_safe == 1:
        st.error("Ostrzeżenie: URL jest podejrzane!")

elif selected_option == "Zobacz Historię":
    st.title("Lista Sprawdzonych URL")

    if st.session_state["URL_list"]:
        st.write("Sprawdzone URL:")
        for url in st.session_state["URL_list"]:
            st.write(f"- {url}")
    else:
        st.write("Lista pusta")
