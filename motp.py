import time
import json
import mitmproxy.http
from mitmproxy import ctx, options
from mitmproxy.addonmanager import AddonManager
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.proxy import Proxy, ProxyType
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os
from threading import Thread

# Define the websites to monitor for OTP requests
BLOCKED_SITES = ["paypal.com", "ebay.com", "amazon.com"]

# Class to handle OTP detection based on machine learning
class AIOTPBlocking:
    def __init__(self):
        self.model = None
        self.model_file = "otp_model.pkl"
        self.data_file = "request_data.json"
        self.load_model()

    def load_model(self):
        """Load pre-trained model if available, otherwise initialise an empty model."""
        if os.path.exists(self.model_file):
            self.model = joblib.load(self.model_file)
        else:
            self.model = RandomForestClassifier()

    def save_model(self):
        """Save the trained model."""
        joblib.dump(self.model, self.model_file)

    def train_model(self, data):
        """Train the model using the collected data."""
        if data:
            X = [d['features'] for d in data]
            y = [d['label'] for d in data]
            self.model.fit(X, y)
            self.save_model()

    def extract_features(self, flow):
        """Extract features from the HTTP request."""
        return [flow.request.url, flow.request.method]

    def predict(self, flow):
        """Predict if the request is OTP-related."""
        if self.model:
            features = self.extract_features(flow)
            return self.model.predict([features])[0] == 1
        return False  # Default to False if no model is available

    def update_data(self, flow, is_otp):
        """Update request data for training."""
        request_data = {
            "url": flow.request.url,
            "method": flow.request.method,
            "features": self.extract_features(flow),
            "label": 1 if is_otp else 0
        }
        with open(self.data_file, 'a') as file:
            json.dump(request_data, file)
            file.write('\n')

# Mitmproxy addon to monitor and intercept OTP requests
class BlockOTPRequestsAddon:
    def __init__(self, ai_blocking):
        self.ai_blocking = ai_blocking

    def request(self, flow: mitmproxy.http.HTTPFlow):
        """Intercept HTTP requests and detect OTP requests."""
        if any(site in flow.request.host for site in BLOCKED_SITES):
            if self.ai_blocking.predict(flow):
                ctx.log.info(f"OTP request intercepted: {flow.request.url}")
                self.ai_blocking.update_data(flow, True)
            else:
                self.ai_blocking.update_data(flow, False)

# Function to start mitmproxy
def start_mitmproxy():
    ai_blocking = AIOTPBlocking()
    addon = BlockOTPRequestsAddon(ai_blocking)
    opts = options.Options(listen_host='127.0.0.1', listen_port=8080)
    master = mitmproxy.master.Master(opts)
    master.addons.add(addon)
    master.run()

# Function to open Firefox with optional Tor proxy
def open_firefox_session(use_tor=False):
    options = Options()
    options.headless = False  # Change to True for headless mode

    # Set up Tor proxy if enabled
    if use_tor:
        proxy = Proxy()
        proxy.proxy_type = ProxyType.MANUAL
        proxy.http_proxy = "127.0.0.1:9050"
        proxy.ssl_proxy = "127.0.0.1:9050"

        capabilities = webdriver.DesiredCapabilities.FIREFOX
        proxy.add_to_capabilities(capabilities)

        driver = webdriver.Firefox(options=options, desired_capabilities=capabilities)
    else:
        driver = webdriver.Firefox(options=options)

    return driver

# Function to browse websites with Selenium
def selenium_browsing():
    driver = open_firefox_session(use_tor=True)

    # Example: Visit PayPal and simulate interaction
    try:
        driver.get("https://www.paypal.com/signin")
        time.sleep(10)

        otp_field = driver.find_element(By.CSS_SELECTOR, 'input[type="text"][name*="otp"]')
        print("OTP field detected.")
    except Exception as e:
        print("Error or OTP field not found:", str(e))

    driver.quit()

# Main function to run everything
def run_script():
    # Start mitmproxy in a separate thread
    mitmproxy_thread = Thread(target=start_mitmproxy)
    mitmproxy_thread.daemon = True
    mitmproxy_thread.start()

    # Run Selenium browsing
    selenium_browsing()

if __name__ == "__main__":
    run_script()
